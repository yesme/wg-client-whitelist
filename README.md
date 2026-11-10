# wg-client-whitelist

Split-tunnel toolchain for WireGuard clients in mainland China who also run
Tailscale: keep domestic traffic direct, send everything else through the
VPN — **without triggering the wireguard-windows killswitch** — plus a
Windows-native NRPT ruleset that keeps DNS answers ISP-aware for domestic
domains and clean for everything else.

## The hole model (v2 of the design)

WireGuard's AllowedIPs is **allow-only** (it is both routing and the
cryptokey source filter), so a split config is literally:

```
AllowedIPs = whole IPv4  minus  HOLES
```

A **hole** is a range kept DIRECT. Which holes to open, in priority order:

1. **mandatory** — LAN/CGNAT/Tailscale (192.168/16, 10/8, 100.64/10, ...),
   loopback/multicast, and pinned domestic resolvers. Always direct; this
   is what keeps Tailscale's underlay off the tunnel (the killswitch trap
   below would otherwise degrade RDP-over-Tailscale to ~450ms relays).
2. **CN carrier core** — APNIC-registered CN allocations up to /`--p`.
3. **blind-spot healing** — foreign-registered RIR blocks whose *announced*
   space (RouteViews origin-ASN truth, not registry country) is ≥`--ratio`
   CN. Catches e.g. cloud ranges bought through other registries that
   country-code lists never see.
4. **carrier families** — ALL prefixes announced by *your* carrier's ASNs
   (Tailscale P2P peer endpoints are raw IPs in consumer space; without
   this, hole-punching packets exit via the VPN and P2P dies). Other
   carriers: big aggregates only (default ≥/16 — the knee of the curve;
   the long tail costs 3x prefixes for +2pp).
5. **curated traffic** — RIR blocks hosting IPs from your must-be-direct
   list (big CDNs, AI APIs, ...).
6. **prune** — kill zero-traffic small holes with the sweep evidence.
   **Small holes are fragment amplifiers**: an isolated /24 hole splits
   its neighbors into awkward pieces; removing it lets allow prefixes
   re-collapse. Reference run: 65 tiny holes freed 719 prefixes at zero
   coverage loss.

Merging is **adjacent-only** — never merge across foreign space. The
tunnel's inner subnet (auto-derived from your conf) stays IN AllowedIPs
for cryptokey routing. **No literal /0 is ever emitted**, so the
wireguard-windows killswitch (single peer + literal /0 ⇒ WFP firewall that
shoves Tailscale's UDP through the tunnel) never arms.

Reference numbers (109k-domain china-list simulation, Nov 2026):
`1949 allow prefixes · 73.8% domains direct · curated list 100% direct ·
activation 2–5 s` (activation cost curve: ~1k prefixes ≈3 s, ~2k ≈2–5 s,
~12k ≈ minutes — stay under ~3–4k).

## The DNS layer — NRPT reverse split

Windows Name Resolution Policy Table, ~890 suffix rules, zero daemons
(port 53 is typically owned by ICS which WSL2 needs — do not fight it):

```
domestic suffix list + .cn wildcard  -> 223.5.5.5 / 119.29.29.29 (pinned DIRECT)
blocklisted subtrees                 ->  tunnel DNS via longest-match override
everything else                      ->  1.1.1.1 via WireGuard (clean answers)
```

Why reversed (default = tunnel DNS): certain names answered by domestic
resolvers come back **poisoned** — bogus IPs injected in the resolver's
upstream recursion, so DoH does not help; a bogus IP cannot be saved by
correct routing. Long-tail domestic names resolved via the tunnel DNS
still get *real* IPs (just non-optimal CDN nodes) — an accepted trade.

## Repository layout

| Path | Purpose |
|---|---|
| `scripts/gen_wg_split.py` | **Hole-model generator.** Auto-downloads 5×RIR delegated files + CAIDA RouteViews pfx2as (cached). Registry holes + ASN blind-spot healing + carrier families + curated blocks; complement + sanity asserts; tunnel subnet auto-derived. |
| `scripts/dns_sweep.py` | Threaded A-record sweep of a domain list via one UDP resolver (traffic-evidence TSV for pruning). |
| `scripts/audit_holes.py` | Hole audit & pruner: reconstruct holes from a conf, measure sweep evidence, kill zero-traffic small holes (fragment-amplifier cleanup). |
| `scripts/gen_nrpt_list.py` | NRPT suffix list: china-list ∩ Cisco Umbrella top-1M, traffic-ranked + curated core. |
| `scripts/gen_navscan.py` | Scrape nav-site homepages, intersect with china-list. |
| `scripts/blocklist_audit.py` | Reverse audit: community-blocklist names must never match an NRPT rule. |
| `scripts/verify_cdn.ps1` | Three-way verification for candidate domains (china-list + live resolve + IP geo). |
| `scripts/nrpt_install.ps1` | Installs the delta between the suffix list and live NRPT rules (elevated). |
| `lists/allowedips_cn_split.txt` | Pre-baked AllowedIPs snapshot (1949 prefixes, one per line) — comma-join into a tunnel, or diff against your own generation. |
| `lists/china_domains_full.txt` | china-list accelerated-domains snapshot (~109k) for sweep/pruning. |
| `lists/nrpt_domains.txt` | NRPT suffix master list. |
| `lists/nrpt_overrides.txt` | Suffixes overridden to the tunnel resolver. |

## Quick start

```bash
# 1. generate the split config from your full-tunnel .conf
python3 scripts/gen_wg_split.py --source original.conf --out split.conf \
    --cm-asns <your-carrier-asns>            # e.g. 9808,56040,...
#    -> import split.conf into WireGuard for Windows, activate

# 2. (recommended) build traffic evidence and prune
python3 scripts/dns_sweep.py --list lists/china_domains_full.txt --out sweep.tsv
python3 scripts/audit_holes.py --conf split.conf --sweep sweep.tsv \
    --out split_pruned.conf

# 3. NRPT side
python3 scripts/gen_nrpt_list.py --top 500 --out lists/nrpt_domains.txt
python3 scripts/blocklist_audit.py --master lists/nrpt_domains.txt
powershell -File scripts/nrpt_install.ps1 -MasterPath lists/nrpt_domains.txt
```

## The four safety rules

1. **Never a literal `/0`** in AllowedIPs (killswitch).
2. **Generic global CDNs never enter NRPT** (Cloudflare/Akamai/Fastly/
   CloudFront/Azure CDN...) — domestic resolvers would steer foreign
   sites' assets to CN edges. CN-owned CDNs and first-party CN delivery
   are fine.
3. **Reverse-audit against a community blocklist** after every bulk
   addition; blocked subtrees of kept rules get longest-match overrides
   to the tunnel resolver.
4. **Verify before adding** any domain or hole: china-list membership +
   live resolve + IP geo; for suspicious answers, query the authoritative
   NS directly to distinguish poisoning / blocking / owner-null-routing.

Also remember: registry-country lists have blind spots (CN services on
market-transferred ranges); the ASN branch above heals them.

## Verification cheatsheet

| Check | Read it as |
|---|---|
| `tracert -d -h 2 <ip>` | first hop = LAN gateway → direct; tunnel IP → VPN |
| `nslookup <domain>` | the "Server:" line is cosmetic — judge by the *answer IP's* network |
| authoritative-NS query | distinguishes poisoned vs blocked vs owner-null answers |
| `tailscale netcheck` | STUN endpoint should be your home IP, UDP true |

## Known dead ends

- Local :53 resolvers (AdGuard Home etc.): ICS owns UDP 53, WSL2 depends
  on ICS. NRPT replaces the whole idea.
- `DNS = https://...` in wireguard-windows: not supported (verified
  against source, v1.1.1).
- Pure per-ASN exclusion (every CN-origin prefix): ~12.5k allow prefixes
  — activation becomes unusable (~minutes). The hole model exists because
  of this ceiling. (A Linux router with nftables sets could digest it.)
- Team Cymru whois answers IP→ASN but not ASN→prefixes; use CAIDA
  RouteViews pfx2as for the inverse.

## License

MIT — see [LICENSE](LICENSE).
