#!/usr/bin/env python3
"""Hole audit & pruner for a hole-model split conf.

Reconstructs every hole from the conf's AllowedIPs, measures TRAFFIC
EVIDENCE against a dns_sweep.py TSV (how many domains resolve into each
hole), and kills zero-traffic SMALL holes. Key insight: small holes are
FRAGMENT AMPLIFIERS - an isolated /24 hole splits its surrounding allow
prefixes into awkward pieces; removing it lets them re-collapse. In the
reference run, 65 zero-traffic /24 holes freed 719 allow prefixes at zero
coverage loss.

Usage:
  python3 audit_holes.py --conf split.conf --sweep sweep.tsv \
      [--keep-below 65536] --out split_pruned.conf [--report holes.tsv]
Verdicts: KILL (no traffic, smaller than --keep-below) / REVIEW (little
traffic) / KEEP (structural guess: holes larger than --keep-below are kept
- only you know if they are yours).
"""
import argparse
import bisect
import ipaddress
import re

ap = argparse.ArgumentParser()
ap.add_argument("--conf", required=True)
ap.add_argument("--sweep", required=True)
ap.add_argument("--out", required=True)
ap.add_argument("--report", default="holes_audit.tsv")
ap.add_argument("--keep-below", type=int, default=65536,
                help="kill zero-traffic holes SMALLER than this (addrs)")
args = ap.parse_args()

txt = open(args.conf, encoding="utf-8").read()
allow = sorted((ipaddress.ip_network(x.strip()) for x in
                re.search(r"(?im)^AllowedIPs = (.+)$", txt).group(1).split(",")),
               key=lambda n: int(n.network_address))
holes = []
cur = 0
LAST = int(ipaddress.IPv4Address("255.255.255.255"))
for a in allow:
    s = int(a.network_address)
    if s > cur:
        holes.append([cur, s - 1])
    cur = max(cur, int(a.broadcast_address) + 1)
if cur <= LAST:
    holes.append([cur, LAST])
hstart = [h[0] for h in holes]
print(f"holes reconstructed: {len(holes)}")

def hole_of(ip):
    x = int(ipaddress.IPv4Address(ip))
    i = bisect.bisect_right(hstart, x) - 1
    return i if i >= 0 and holes[i][1] >= x else None

dom_hits = {}
for line in open(args.sweep, encoding="utf-8", errors="replace"):
    parts = line.rstrip("\n").split("\t")
    if len(parts) != 2 or parts[1] in ("NXDOMAIN", "FAIL"):
        continue
    seen = set()
    for ip in parts[1].split(","):
        h = hole_of(ip)
        if h is not None:
            seen.add(h)
    for h in seen:
        dom_hits[h] = dom_hits.get(h, 0) + 1

rows = []
for idx, (h0, h1) in enumerate(holes):
    size = h1 - h0 + 1
    nd = dom_hits.get(idx, 0)
    if nd > 0:
        verdict = "KEEP"
    elif size >= args.keep_below:
        verdict = "KEEP(big-no-traffic)"
    else:
        verdict = "KILL"
    rows.append((idx, h0, h1, size, nd, verdict))

kills = [r for r in rows if r[5] == "KILL"]
print(f"KEEP {len(rows)-len(kills)} | KILL {len(kills)}")

with open(args.report, "w") as f:
    f.write("idx\tstart\tend\tsize\tdomains\tverdict\n")
    for r in rows:
        f.write("\t".join(str(x) for x in r) + "\n")

kept = [h for i, h in enumerate(holes) if rows[i][5] != "KILL"]
new_allow = []
cur = 0
for h in kept:
    if h[0] > cur:
        new_allow += list(ipaddress.summarize_address_range(
            ipaddress.IPv4Address(cur), ipaddress.IPv4Address(h[0] - 1)))
    cur = max(cur, h[1] + 1)
if cur <= LAST:
    new_allow += list(ipaddress.summarize_address_range(
        ipaddress.IPv4Address(cur), ipaddress.IPv4Address(LAST)))
new_allow = list(ipaddress.collapse_addresses(new_allow))
print(f"allow: {len(allow)} -> {len(new_allow)} prefixes")

lost = sum(r[4] for r in kills)
print(f"traffic lost: {lost} domain-hits (should be 0)")

new_txt = re.sub(r"(?im)^AllowedIPs = .*$",
                 "AllowedIPs = " + ", ".join(str(n) for n in new_allow), txt)
open(args.out, "w", encoding="utf-8").write(new_txt)
print(f"wrote {args.out}; report {args.report}")
