#!/usr/bin/env python3
"""Threaded A-record sweep of a domain list via one UDP resolver.

Produces the traffic-evidence TSV that audit_holes.py uses to prune:
    domain \t ip1,ip2,ip3   (up to 3 A records)
    domain \t NXDOMAIN | FAIL

Usage:
  python3 dns_sweep.py --list lists/china_domains_full.txt \
      --dns 223.5.5.5 --out sweep.tsv [--workers 200]
Notes: one socket per query, closed immediately (no fd leaks); answer
parsing starts at len(query) because the question section is echoed
verbatim by the resolver (structurally immune to name-offset bugs).
"""
import argparse
import concurrent.futures as cf
import socket
import struct
from collections import Counter

ap = argparse.ArgumentParser()
ap.add_argument("--list", required=True)
ap.add_argument("--dns", default="223.5.5.5")
ap.add_argument("--out", default="sweep.tsv")
ap.add_argument("--workers", type=int, default=200)
ap.add_argument("--timeout", type=float, default=2.5)
ap.add_argument("--retries", type=int, default=1)
args = ap.parse_args()
RESOLVER = (args.dns, 53)

def build_query(d, qid):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for part in d.split("."):
        q += bytes([len(part)]) + part.encode()
    return q + b"\x00" + struct.pack(">HH", 1, 1)

def parse_answers(data, qlen):
    ips = []
    i = qlen                      # skip header + echoed question
    an = struct.unpack(">H", data[6:8])[0]
    end = len(data)
    for _ in range(an):
        if i >= end:
            break
        while i < end:
            b = data[i]
            if b == 0:
                i += 1; break
            if b & 0xC0 == 0xC0:
                i += 2; break
            i += b + 1
        if i + 10 > end:
            break
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[i:i+10])
        i += 10
        if rtype == 1 and rdlen == 4 and i + 4 <= end:
            ips.append(".".join(str(b) for b in data[i:i+4]))
        i += rdlen
        if len(ips) >= 3:
            break
    return ips

def resolve(job):
    d, qid = job
    q = build_query(d, qid)
    for attempt in range(args.retries + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(args.timeout)
                s.sendto(q, RESOLVER)
                while True:
                    data, _ = s.recvfrom(2048)
                    if struct.unpack(">H", data[:2])[0] != qid:
                        continue          # stale answer
                    if data[3] & 0x0F == 3:
                        return d, "NXDOMAIN"
                    ips = parse_answers(data, len(q))
                    return d, (",".join(ips) if ips else "NXDOMAIN")
        except Exception:
            if attempt == args.retries:
                return d, "FAIL"

doms, seen = [], set()
for line in open(args.list, encoding="utf-8", errors="replace"):
    d = line.strip().lower().lstrip(".")
    m = None
    if d and "." in d and d not in seen:
        # accept both flat lists and dnsmasq 'server=/domain/' lines
        mm = __import__("re").match(r"^server=/([^/]+)/", d)
        if mm:
            d = mm.group(1)
        if d and "." in d and d not in seen:
            seen.add(d)
            doms.append(d)
print(f"domains: {len(doms)}", flush=True)

results = []
BATCH = 5000
with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
    for i in range(0, len(doms), BATCH):
        batch = doms[i:i+BATCH]
        futs = [ex.submit(resolve, (d, (0x1000 + j) & 0xFFFF))
                for j, d in enumerate(batch)]
        for f in cf.as_completed(futs):
            results.append(f.result())
        print(f"  {min(i+BATCH, len(doms))}/{len(doms)}", flush=True)

order = {d: k for k, d in enumerate(doms)}
results.sort(key=lambda r: order[r[0]])
with open(args.out, "w") as f:
    for d, r in results:
        f.write(f"{d}\t{r}\n")
kinds = Counter("NXDOMAIN" if v == "NXDOMAIN" else
                "FAIL" if v == "FAIL" else "OK" for _, v in results)
print("summary:", dict(kinds), "->", args.out)
