#!/usr/bin/env python3
"""Hole-model WireGuard split generator (hole model, successor of the
registry-only v4 generator).

WireGuard AllowedIPs is ALLOW-ONLY: the config is 'whole IPv4 minus holes'.
A HOLE is a range kept DIRECT (off the tunnel). Design goals, in priority
order:
  1. mandatory holes always direct: LAN/CGNAT/Tailscale/loopback/etc + any
     pinned domestic resolvers you list;
  2. mainland-CN carrier core: APNIC-registered CN allocations <= --p;
  3. blind-spot healing: foreign-registered RIR blocks whose announced
     address space originates >= --ratio from CN ASNs (RouteViews truth);
  4. carrier families: all prefixes announced by your own carrier's ASNs
     (keeps Tailscale P2P peer endpoints direct); other carriers' big
     aggregates only (--carrier-cuct, default /16 - the knee of the curve);
  5. curated traffic: RIR blocks hosting IPs from --curated-ips are holes;
  6. prune (separate script audit_holes.py + dns_sweep.py): kill zero-traffic
     small holes - small holes are FRAGMENT AMPLIFIERS (each splits adjacent
     allow prefixes; removing lets them re-collapse).
Merging is adjacent-only; never across foreign space. No literal /0 is
emitted (wireguard-windows killswitch stays off). The tunnel inner subnet
(auto-derived from the source conf's Address) stays IN AllowedIPs for
cryptokey routing.

Data (auto-downloaded, cached in --data-dir):
  5x RIR delegated files (ASN->country + v4 allocation blocks)
  CAIDA RouteViews pfx2as snapshot (prefix->origin ASNs)

Usage:
  python3 gen_wg_split.py --source original.conf --out split.conf \
      [--p 10] [--ratio 0.8] [--cuct 16] [--curated-ips ips.txt] \
      [--cm-asns 9808,56040,...] [--max-prefixes 3500]
"""
import argparse
import bisect
import gzip
import ipaddress
import os
import re
import urllib.request

RIRS = {
    "apnic": "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}
CAIDA_BASE = ("https://publicdata.caida.org/datasets/routing/"
              "routeviews-prefix2as")

MANDATORY = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
             "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
             "224.0.0.0/3")

ap = argparse.ArgumentParser()
ap.add_argument("--source", required=True, help="original full-tunnel .conf")
ap.add_argument("--out", default="wg_cn_split.conf")
ap.add_argument("--data-dir", default="data")
ap.add_argument("--p", type=int, default=10,
                help="max prefixlen of CN registry allocations to hole")
ap.add_argument("--ratio", type=float, default=0.8,
                help="CN-origin coverage for foreign blocks to hole")
ap.add_argument("--cuct", type=int, default=16,
                help="other carriers: hole only announced aggregates <= this")
ap.add_argument("--cm-asns", default="9808,56040,58453,9394,9231,24400",
                help="your carrier's ASNs (comma list) - ALL prefixes direct")
ap.add_argument("--cuct-asns", default="4837,9929,4808,4134,4811,4812,23724",
                help="other carriers' ASNs - big aggregates only")
ap.add_argument("--curated-ips", default=None,
                help="file of IPs (one per line) whose blocks must be direct")
ap.add_argument("--cn-cloud-asns",
                default="136907,45102,132203,135377,55967,55990",
                help="CN clouds' INTERNATIONAL arms (HK/SG/US-registered) "
                     "that still operate mainland POPs; their announced "
                     "prefixes count as islands (find yours via Cymru "
                     "whois name lookup, e.g. HUAWEI CLOUDS HK)")
ap.add_argument("--pin-dns", default="223.5.5.5/32,119.29.29.29/32",
                help="domestic reservers pinned direct (comma list)")
ap.add_argument("--carve-ips", default=None,
                help="file of IPs (blocklisted sites hosted on CN-registry "
                     "space); their /24s are carved back INTO AllowedIPs")
ap.add_argument("--max-prefixes", type=int, default=3500)
args = ap.parse_args()

os.makedirs(args.data_dir, exist_ok=True)

def fetch(url, name):
    path = os.path.join(args.data_dir, name)
    if not os.path.exists(path):
        print(f"downloading {name} ...", flush=True)
        urllib.request.urlretrieve(url, path)
    return path

# ---------- RIR delegated: ASN->CC + v4 blocks ----------
asn_cc = {}
blocks = []          # (start, end, plen, cc, registry)
for reg, url in RIRS.items():
    path = fetch(url, f"delegated-{reg}.txt")
    na = nb = 0
    for line in open(path, encoding="ascii", errors="replace"):
        p = line.split("|")
        if len(p) < 7 or p[0] != reg:
            continue
        if p[2] == "asn" and p[6] in ("allocated", "assigned"):
            for k in range(int(p[3]), int(p[3]) + int(p[4])):
                asn_cc[k] = p[1]
            na += 1
        elif p[2] == "ipv4" and re.match(r"^\d+\.\d+\.\d+\.\d+$", p[3]):
            a = int(ipaddress.IPv4Address(p[3]))
            cnt = int(p[4])
            blocks.append((a, a + cnt - 1,
                           32 - (cnt.bit_length() - 1), p[1], reg))
            nb += 1
    print(f"  {reg}: +{na} ASNs, +{nb} v4 blocks", flush=True)
blocks.sort()
bstart = [b[0] for b in blocks]
cn_asns = {a for a, cc in asn_cc.items() if cc == "CN"}
print(f"ASNs: {len(asn_cc)} total, {len(cn_asns)} CN; "
      f"v4 blocks: {len(blocks)}")

def block_idx(x):
    i = bisect.bisect_right(bstart, x) - 1
    return i if i >= 0 and blocks[i][1] >= x else None

# CN-registered ASNs whose POPs are largely OVERSEAS (intl arms): exclude
# from block-coverage math (their intl POP blocks must ride the tunnel —
# the okx/binance/futu/longbridge lesson: blocked exchanges sit on these).
# They still feed carrier families & curated islands where appropriate.
INTL_ARM_ASNS = {45102, 132203, 55967, 134565}

def latest_pfx2as():
    import datetime
    for back in range(1, 10):
        d = datetime.date.today() - datetime.timedelta(days=back)
        url = f"{CAIDA_BASE}/{d.year}/{d.month:02d}/"
        try:
            html = urllib.request.urlopen(url, timeout=60).read().decode(
                "ascii", "replace")
        except Exception:
            continue
        files = re.findall(r'routeviews-rv2-\d{8}-\d{4}\.pfx2as\.gz', html)
        if files:
            return url + sorted(files)[-1], sorted(files)[-1]
    raise SystemExit("no CAIDA pfx2as snapshot found in the last 10 days")

pfx_url, pfx_name = latest_pfx2as()
pfx_path = fetch(pfx_url, pfx_name)
cloud_asns = {int(x) for x in args.cn_cloud_asns.split(",")}
cn_pfx = {}          # prefix -> set of CN origin asns
cloud_pfx = {}       # prefix -> CN-cloud intl-arm origins (island class)
total_ann = 0
with gzip.open(pfx_path, "rt") as f:
    for line in f:
        parts = line.split("\t")
        if len(parts) < 3 or not parts[1].strip().isdigit():
            continue
        pfx = parts[0] + "/" + parts[1].strip()
        if not re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", pfx):
            continue
        total_ann += 1
        orig = {int(t) for t in re.split(r"[_{ },]+", parts[2].strip())
                if t.isdigit()}
        hit = orig & (cn_asns - INTL_ARM_ASNS)
        if hit:
            cn_pfx[pfx] = hit
        elif orig & (cloud_asns | INTL_ARM_ASNS):
            cloud_pfx[pfx] = orig & (cloud_asns | INTL_ARM_ASNS)
print(f"announced v4: {total_ann}, CN-origin: {len(cn_pfx)}, "
      f"CN-cloud intl islands: {len(cloud_pfx)}")

# ---------- CN coverage per RIR block ----------
cov = {}
for p in cn_pfx:
    n = ipaddress.ip_network(p)
    i = block_idx(int(n.network_address))
    if i is not None:
        lo = max(int(n.network_address), blocks[i][0])
        hi = min(int(n.broadcast_address), blocks[i][1])
        if hi >= lo:
            cov[i] = cov.get(i, 0) + (hi - lo + 1)

# ---------- holes ----------
holes = [ipaddress.ip_network(x) for x in MANDATORY]
holes += [ipaddress.ip_network(x) for x in args.pin_dns.split(",")]

def add_range(s, e):
    holes.extend(ipaddress.summarize_address_range(
        ipaddress.IPv4Address(s), ipaddress.IPv4Address(e)))

n_reg = n_cov = 0
for i, (s, e, pl, cc, reg) in enumerate(blocks):
    if reg == "apnic" and cc == "CN" and pl <= args.p:
        add_range(s, e); n_reg += 1
    elif reg != "apnic" or cc != "CN":
        if i in cov:
            ratio = cov[i] / (e - s + 1)
            if pl <= 10 or ratio >= args.ratio:
                add_range(s, e); n_cov += 1
print(f"registry CN <=/{args.p}: {n_reg} blocks; "
      f"foreign CN-covered: {n_cov} blocks")

CM = {int(x) for x in args.cm_asns.split(",")}
CUCT = {int(x) for x in args.cuct_asns.split(",")}
def reg_cn_ip(ip):
    """True if the covering RIR allocation is registry-CN — carrier holes
    are restricted to it (else CMI/CT-intl transit of foreign CDNs, e.g.
    CloudFront HK edges, sweeps global CDNs into direct)."""
    i = block_idx(int(ipaddress.IPv4Address(ip)))
    return i is not None and blocks[i][3] == "CN" and blocks[i][4] == "apnic"
n_cm = n_cuct = 0
for p, orig in cn_pfx.items():
    net = ipaddress.ip_network(p)
    if not reg_cn_ip(str(net.network_address)):
        continue
    if orig & CM:
        holes.append(net); n_cm += 1
    elif orig & CUCT and net.prefixlen <= args.cuct:
        holes.append(net); n_cuct += 1
print(f"carrier families (registry-CN space only): own {n_cm}, "
      f"others {n_cuct} (<=/{args.cuct})")

if args.curated_ips:
    # Triage per curated IP (the jdstatic/Cloudflare lesson: never hole a
    # foreign global-CDN allocation wholesale just because a curated name
    # resolves into it):
    #   registry-CN RIR block            -> hole the whole allocation
    #   foreign block, IP inside a CN-origin ANNOUNCED prefix -> hole that
    #     prefix only (island at routing granularity)
    #   foreign block, no CN announcement -> skip (site on a global CDN;
    #     rides the tunnel by doctrine)
    cn_ann = sorted((int(ipaddress.ip_network(p).network_address),
                     int(ipaddress.ip_network(p).broadcast_address))
                    for p in list(cn_pfx) + list(cloud_pfx))
    cn_ann_st = [a for a, _ in cn_ann]

    def ann_cn_idx(x):
        i = bisect.bisect_right(cn_ann_st, x) - 1
        return i if i >= 0 and cn_ann[i][1] >= x else None

    n_reg = n_isl = n_skip = 0
    for line in open(args.curated_ips):
        ip = line.strip()
        if not ip:
            continue
        x = int(ipaddress.IPv4Address(ip))
        i = block_idx(x)
        if i is None:
            continue
        s, e, pl, cc, reg = blocks[i]
        if reg == "apnic" and cc == "CN":
            add_range(s, e); n_reg += 1
        else:
            j = ann_cn_idx(x)
            if j is not None:
                add_range(cn_ann[j][0], cn_ann[j][1]); n_isl += 1
            else:
                n_skip += 1
    print(f"curated IPs: {n_reg} registry-CN blocks, {n_isl} CN islands, "
          f"{n_skip} skipped (foreign CDN -> tunnel)")

# ---------- tunnel subnet stays IN allow (cryptokey) ----------
src_txt = open(args.source, encoding="utf-8").read()
m = re.search(r"(?im)^Address\s*=\s*(\d+\.\d+\.\d+\.\d+)", src_txt)
if not m:
    raise SystemExit("cannot find 'Address =' in source conf")
tun = ipaddress.ip_network(m.group(1) + "/24", strict=False)
print(f"tunnel subnet (auto-derived): {tun}")

holes = [h for h in holes if not h.subnet_of(tun)]
holes = list(ipaddress.collapse_addresses(holes))   # adjacent-only merge
allow = []
cur = 0
LAST = int(ipaddress.IPv4Address("255.255.255.255"))
for h in holes:
    s, e = int(h.network_address), int(h.broadcast_address)
    if s > cur:
        allow += list(ipaddress.summarize_address_range(
            ipaddress.IPv4Address(cur), ipaddress.IPv4Address(s - 1)))
    cur = max(cur, e + 1)
if cur <= LAST:
    allow += list(ipaddress.summarize_address_range(
        ipaddress.IPv4Address(cur), ipaddress.IPv4Address(LAST)))
allow.append(tun)
allow = list(ipaddress.collapse_addresses(allow))

if args.carve_ips:
    # Blocklisted sites hosted on CN-registry space: carve their /24s back
    # INTO AllowedIPs (they need the tunnel: direct = SNI-filtered).
    n_carve = 0
    for line in open(args.carve_ips):
        ip = line.strip()
        if not ip:
            continue
        o = int(ipaddress.IPv4Address(ip)) & ~255
        allow.append(ipaddress.ip_network(
            f"{ipaddress.IPv4Address(o)}/24"))
        n_carve += 1
    allow = list(ipaddress.collapse_addresses(allow))
    print(f"carved {n_carve} blocklisted /24s into the tunnel side")
print(f"holes={len(holes)} allow={len(allow)} prefixes")
if len(allow) > args.max_prefixes:
    raise SystemExit(f"over --max-prefixes ({len(allow)} > "
                     f"{args.max_prefixes}); tune --p/--cuct or run "
                     f"audit_holes.py to prune")

# ---------- sanity ----------
def via(ip):
    return any(ipaddress.ip_address(ip) in a for a in allow)
assert via("8.8.8.8") and via("1.1.1.1"), "foreign must ride the tunnel"
assert not via("192.168.0.1") and not via("100.100.100.100"), \
    "LAN/Tailscale must be direct"
assert not via(args.pin_dns.split(",")[0].split("/")[0]), \
    "pinned resolver must be direct"
assert via(str(tun.network_address + 1)), "tunnel subnet must stay allowed"
assert not any(a.prefixlen == 0 for a in allow), "no literal /0"
print("sanity: OK")

# ---------- write ----------
allowed = ", ".join(str(n) for n in allow)
header = ("# HOLE MODEL: AllowedIPs = whole-v4 minus direct holes "
          f"(mandatory + CN registry <=/{args.p} + foreign blocks "
          f"CN-origin>={args.ratio} + carrier families + curated). "
          f"{len(allow)} prefixes. Generated by gen_wg_split.py.\n")
new = re.sub(r"(?im)^AllowedIPs\s*=.*$", f"AllowedIPs = {allowed}", src_txt)
new = re.sub(r"(?im)^DNS\s*=.*$", "DNS = 1.1.1.1, 8.8.8.8", new)
open(args.out, "w", encoding="utf-8").write(header + new)
assert "PrivateKey" in open(args.out, encoding="utf-8").read()
print(f"wrote {args.out} (contains your private key - keep local)")
print("next: dns_sweep.py + audit_holes.py to prune zero-traffic holes")
