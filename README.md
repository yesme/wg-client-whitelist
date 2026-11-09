# wg-client-whitelist

Split-tunnel toolchain for WireGuard clients in mainland China who also run
Tailscale: route domestic traffic direct, everything else through the VPN —
**without triggering the wireguard-windows killswitch**, and with a
Windows-native NRPT ruleset that keeps DNS answers ISP-aware for domestic
domains and clean for everything else.

## Why this exists

Two failure modes this project solves:

1. **The killswitch trap.** wireguard-windows enables a WFP "block untunneled
   traffic" firewall as soon as a tunnel has a single peer with a literal
   `0.0.0.0/0` / `::/0` in AllowedIPs. That firewall does not exempt other
   VPN overlays, so Tailscale's underlay UDP gets shoved through (or cut off
   from) the WireGuard tunnel — RDP over Tailscale dies during the
   re-convergence window (the classic `0x204`). A full CN prefix list
   (≈12k prefixes) avoids the literal /0 but takes minutes to activate.
   **Fix:** emit the complement of the direct set as an enumerated prefix
   list, trie-aggregated to stay under ~1000 routes — same routing semantics,
   no killswitch, seconds to activate.
2. **The DNS view problem.** If the tunnel DNS (e.g. 1.1.1.1) resolves a
   domestic domain, CDN geo-steering returns overseas nodes and your
   domestic traffic detours through the VPN. If a domestic resolver handles
   foreign domains, certain names come back with **poisoned answers**
   (bogus IPs injected upstream of the resolver — encrypted transports such
   as DoH do not help, the pollution happens in the resolver's recursion,
   not on your path).
   **Fix:** Windows NRPT (Name Resolution Policy Table) reverse split —
   default resolver goes through the tunnel (clean answers); a curated
   suffix list routes domestic domains to a pinned-direct domestic resolver
   (ISP-aware answers). Zero daemons, zero port-53 fights (ICS/WSL own :53),
   registry-persisted.

## Architecture

```
DNS layer — NRPT (Windows-native, ~890 rules)
  domestic suffix list + .cn wildcard  -> 223.5.5.5 / 119.29.29.29  (pinned DIRECT)
  overridden subtrees (.copilot.microsoft.com, ...) -> tunnel DNS (longest-match)
  everything else                      -> 1.1.1.1 via WireGuard (clean answers)

Routing layer — WireGuard AllowedIPs (aggregated, NO literal /0)
  mainland CN (APNIC) + Tailscale CGNAT 100.64.0.0/10 + RFC1918
    + pinned resolver /32s + manual CN exemptions   ->  physical NIC
  everything else (incl. CN Unicom/Telecom if you prefer VPN for them)
                                                     ->  WireGuard tunnel
```

## The four safety rules

1. **Never a literal `/0`.** Enumerate. (`0.0.0.0/1 + 128.0.0.0/1` also works
   but our aggregation already avoids it.)
2. **Generic global CDNs never enter NRPT** (Cloudflare, Akamai, Fastly,
   CloudFront, Azure CDN…). Domestic resolvers would steer foreign sites'
   assets to CN edges. First-party CN delivery (Apple, Windows Update) and
   CN-owned CDNs are fine.
3. **Reverse-audit against a community blocklist** after every bulk
   addition: a name that cannot be resolved truthfully from inside the CN
   network must never match an NRPT rule — a poisoned answer cannot be
   saved by correct routing. Such subtrees of otherwise-kept rules get
   longest-match overrides pointing at the tunnel resolver.
4. **Verify before adding**: china-list membership + live resolve via the
   domestic resolver + IP geo. A `0.0.0.1` apex from *your own authoritative
   NS* is an owner-side null route (defensive registration) — distinguish
   poisoning / blocking / owner-parking by querying the authoritative NS
   directly.

Also mind **prefix-list blind spots**: CN services on market-transferred
non-APNIC ranges (e.g. Alibaba's ARIN-registered 8.147.0.0/16) are invisible
to APNIC-derived lists. Symptom: a domestic API detours through the VPN.
Fix: add the range to the generator's exemption list, regenerate, re-import.

## Repository layout

| Path | Purpose |
|---|---|
| `scripts/gen_wg_split.py` | Generates the split-tunnel WireGuard config from your original .conf (keys are read, never printed; tunnel subnet auto-derived). APNIC source, trie aggregation, sanity asserts. |
| `scripts/gen_nrpt_list.py` | Builds the NRPT suffix list: china-list ∩ Cisco Umbrella top-1M, traffic-ranked, plus a curated core. Auto-downloads data. |
| `scripts/gen_navscan.py` | Scrapes nav-site homepages (hao123 / 360 / 2345), intersects with china-list — catches head sites the traffic rank misses. |
| `scripts/blocklist_audit.py` | Reverse audit: community-blocklist domains × NRPT rules, reports conflicts. Run after every bulk addition. |
| `scripts/verify_cdn.ps1` | Three-way verification for candidate domains (china-list + live resolve + IP geo). |
| `scripts/nrpt_install.ps1` | Installs the delta between `lists/nrpt_domains.txt` and live NRPT rules (elevated). |
| `lists/nrpt_domains.txt` | The suffix master list (one registrable domain per line). |
| `lists/nrpt_overrides.txt` | Suffixes intentionally overridden to the tunnel resolver. |

## Quick start

```bash
# 1. generate the split config from your existing full-tunnel .conf
python3 scripts/gen_wg_split.py --source /path/to/original.conf --out split.conf
#    -> import split.conf into WireGuard for Windows, activate

# 2. build / refresh the NRPT list (edit lists/nrpt_domains.txt to taste)
python3 scripts/gen_nrpt_list.py --top 500 --out lists/nrpt_domains.txt

# 3. audit before installing (defaults to a community blocklist mirror;
#    override with --blocklist-url if you prefer another)
python3 scripts/blocklist_audit.py --master lists/nrpt_domains.txt

# 4. install (elevated PowerShell)
powershell -File scripts/nrpt_install.ps1 -MasterPath lists/nrpt_domains.txt
```

## Maintenance

- Add one domain: `Add-DnsClientNrptRule -Namespace ".example.com" -NameServers "223.5.5.5"` (admin), and append to the master list.
- Refresh CN prefixes (monthly): re-run `gen_wg_split.py`, re-import the tunnel.
- Refresh traffic ranking (quarterly): re-run `gen_nrpt_list.py`.
- After any bulk change: run the blocklist audit.

## Verification cheatsheet

| Check | Read it as |
|---|---|
| `tracert -d -h 2 <ip>` | first hop = your LAN gateway → direct; tunnel IP → VPN |
| `nslookup <domain>` | the "Server:" line is cosmetic — judge by the *answer IP's* network |
| authoritative-NS query | distinguishes poisoned answers vs resolver blocking vs owner null-route |
| `tailscale netcheck` | STUN endpoint should be your home IP, UDP true |

## Known dead ends

- Local :53 resolvers (AdGuard Home etc.) on a typical Windows box: ICS owns
  UDP 53 and WSL2 depends on ICS. NRPT replaces the whole idea.
- `DNS = https://...` in wireguard-windows: not supported (verified against
  source, v1.1.1).
- Exact 12k-prefix CN list in AllowedIPs: activation is unusably slow;
  keep the aggregated set under ~1000.

## License

MIT — see [LICENSE](LICENSE).
