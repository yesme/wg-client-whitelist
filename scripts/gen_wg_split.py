#!/usr/bin/env python3
"""Generate a full-CN-direct split-tunnel WireGuard config.

Reads your ORIGINAL full-tunnel .conf (keys are read, never printed),
rewrites AllowedIPs as the aggregated complement of the direct set:

  direct   = mainland-CN (APNIC) + Tailscale CGNAT + RFC1918/reserved
             + pinned direct DNS resolvers + manual CN exemptions
  via VPN  = everything else (enumerated prefixes, NO literal /0,
             so wireguard-windows will not enable its killswitch)

Usage:
  python3 gen_wg_split.py --source original.conf --out split.conf
Options: --t / --K control aggregation greed; --max-prefixes the cap.
"""
import argparse
import bisect
import ipaddress
import re
import sys
import time
import urllib.request

APNIC = ("http://ftp.apnic.net/apnic/stats/apnic/"
         "delegated-apnic-extended-latest")

# resolvers that must stay OFF the tunnel (domestic DNS pinned direct)
PINNED_DIRECT = ["223.5.5.5/32", "223.6.6.6/32",
                 "119.29.29.29/32", "120.53.53.53/32"]
# chnroute blind spots: CN-hosted ranges registered outside APNIC
# (market-transferred blocks). Add yours here after verifying geo+registry.
EXEMPT_CN = [
    "8.147.0.0/16",       # example: Alibaba Beijing via ARIN
    "103.143.17.0/24",    # example: CN IDC behind a DDoS-proxy CNAME
]
HARD_DIRECT = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
               "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
               "224.0.0.0/3"]

ap = argparse.ArgumentParser()
ap.add_argument("--source", required=True, help="original full-tunnel .conf")
ap.add_argument("--out", default="wg_cn_split.conf")
ap.add_argument("--t", type=float, default=0.01,
                help="swallow a mixed block into VPN if CN ratio <= t")
ap.add_argument("--K", type=int, default=16384,
                help="...or if it contains <= K CN addresses (long-tail cap)")
ap.add_argument("--max-prefixes", type=int, default=1000)
args = ap.parse_args()

t0 = time.time()
raw = urllib.request.urlopen(APNIC, timeout=90).read().decode("ascii", "replace")

cn = []
for line in raw.splitlines():
    p = line.split("|")
    if len(p) >= 5 and p[0] == "apnic" and p[1] == "CN" and p[2] == "ipv4":
        a = int(ipaddress.IPv4Address(p[3]))
        cn.append((a, a + int(p[4]) - 1))
cn.sort()
merged = []
for a, b in cn:
    if merged and a <= merged[-1][1] + 1:
        merged[-1][1] = max(merged[-1][1], b)
    else:
        merged.append([a, b])
starts = [a for a, _ in merged]
ends = [b for _, b in merged]
cum = [0]
for a, b in merged:
    cum.append(cum[-1] + b - a + 1)
TOTAL_CN = cum[-1]

def cn_le(x):
    """Count CN addresses <= x. cum[k] = total of merged[0:k] (exclusive of
    the k-th interval), so inside interval i: cum[i] + (x - starts[i] + 1);
    past interval i: cum[i + 1]. (A prior 'subtract the tail' form had an
    off-by-one producing negative counts on large merged intervals.)"""
    i = bisect.bisect_right(starts, x) - 1
    if i < 0:
        return 0
    if x <= ends[i]:
        return cum[i] + (x - starts[i] + 1)
    return cum[i + 1]

FDi = [(int(n.network_address), int(n.broadcast_address))
       for n in [ipaddress.ip_network(x) for x in HARD_DIRECT + PINNED_DIRECT]]
# tunnel inner subnet, forced via VPN so the provider's own /24 stays
# reachable through the tunnel; auto-derived from the source conf's Address
src_txt = open(args.source, encoding="utf-8").read()
m = re.search(r"(?im)^Address\s*=\s*(\d+\.\d+\.\d+\.\d+)", src_txt)
if not m:
    sys.exit("cannot find 'Address =' in source conf; cannot derive subnet")
_tun = ipaddress.ip_network(m.group(1) + "/24", strict=False)
FVs, FVe = (int(_tun.network_address), int(_tun.broadcast_address))
print(f"tunnel subnet (auto-derived): {_tun}")

def rec(s, depth, out, sw):
    size = 1 << (32 - depth)
    e = s + size - 1
    fv = FVs <= e and s <= FVe
    fd = any(zs <= e and s <= ze for zs, ze in FDi)
    if fv:
        if FVs <= s and e <= FVe:
            out.append((s, depth)); return
        if depth < 24:
            h = size >> 1
            rec(s, depth + 1, out, sw)
            rec(s + h, depth + 1, out, sw)
            return
    if fd and any(zs <= s and e <= ze for zs, ze in FDi):
        return
    if fv or fd:
        if depth < 24:
            h = size >> 1
            rec(s, depth + 1, out, sw)
            rec(s + h, depth + 1, out, sw)
        return
    c = cn_le(e) - cn_le(s - 1)
    if c <= 0:
        out.append((s, depth))
    elif c >= size:
        return
    elif c <= args.t * size or c <= args.K:
        out.append((s, depth)); sw[0] += c
    elif depth >= 24:
        out.append((s, depth)); sw[0] += c
    else:
        h = size >> 1
        rec(s, depth + 1, out, sw)
        rec(s + h, depth + 1, out, sw)

print(f"CN merged ranges: {len(merged)}, total {TOTAL_CN/1e6:.1f}M addrs")
out, sw = [], [0]
rec(0, 0, out, sw)
prefixes = list(ipaddress.collapse_addresses(
    ipaddress.ip_network(f"{ipaddress.IPv4Address(s)}/{d}") for s, d in out))
print(f"aggregated: {len(prefixes)} prefixes, CN swallowed "
      f"{sw[0]:,} ({sw[0]/TOTAL_CN*100:.2f}%)")
if len(prefixes) > args.max_prefixes:
    sys.exit(f"over --max-prefixes ({len(prefixes)} > {args.max_prefixes}); "
             "raise -t/-K or accept slower activation")

def covered(ip):
    return any(ipaddress.ip_address(ip) in n for n in prefixes)
assert not covered("223.5.5.5") and not covered("192.168.0.1")
assert not covered("100.100.100.100"), "Tailscale MagicDNS must be direct"
assert covered("8.8.8.8") and covered("1.1.1.1")
print("sanity checks: OK")

orig = src_txt
if not re.search(r"(?im)^AllowedIPs\s*=", orig):
    sys.exit("source conf has no AllowedIPs line")
allowed = ", ".join(str(n) for n in prefixes)
header = ("# AUTO-GENERATED split-tunnel: mainland-CN + Tailscale + private "
          "+ pinned DNS direct; rest via VPN. NO literal /0 (killswitch off).\n"
          f"# APNIC aggregated, {len(prefixes)} prefixes, "
          f"generated {time.strftime('%Y-%m-%d %H:%M')}\n")
new = re.sub(r"(?im)^AllowedIPs\s*=.*$", f"AllowedIPs = {allowed}", orig)
new = re.sub(r"(?im)^DNS\s*=.*$", "DNS = 1.1.1.1, 8.8.8.8", new)
open(args.out, "w", encoding="utf-8").write(header + new)
txt = open(args.out, encoding="utf-8").read()
assert "PrivateKey" in txt and "AllowedIPs = 0.0.0.0/0" not in txt
print(f"wrote {args.out} in {time.time()-t0:.1f}s "
      "(NOTE: file contains your private key - keep it local)")
