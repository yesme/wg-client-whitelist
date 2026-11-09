#!/usr/bin/env python3
"""Scrape nav-site homepages, extract registrable domains, keep those in
china-list, diff against the NRPT master list. Catches head sites the
traffic-rank intersection misses.

Usage:
  python3 gen_navscan.py --master lists/nrpt_domains.txt --out navscan_new.txt
"""
import argparse
import os
import re
import urllib.request

CHINA_URL = ("https://raw.githubusercontent.com/felixonmars/"
             "dnsmasq-china-list/master/accelerated-domains.china.conf")
NAV = ["https://www.hao123.com", "https://hao.360.com", "https://www.2345.com"]
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0"}

ap = argparse.ArgumentParser()
ap.add_argument("--master", default="lists/nrpt_domains.txt")
ap.add_argument("--out", default="navscan_new.txt")
ap.add_argument("--china", default="china_accel.conf")
args = ap.parse_args()

if not os.path.exists(args.china):
    urllib.request.urlretrieve(CHINA_URL, args.china)

cn = set()
for line in open(args.china, encoding="utf-8", errors="replace"):
    m = re.match(r"^server=/([^/]+)/", line)
    if m:
        cn.add(m.group(1).lower())
print(f"china-list: {len(cn)} domains")

def registrable(h):
    h = h.lower().strip(".:").split(":")[0]
    labels = h.split(".")
    if len(labels) >= 3 and labels[-1] == "cn" and labels[-2] in (
            "com", "net", "org", "gov", "edu", "ac"):
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else None

doms = set()
for url in NAV:
    try:
        html = urllib.request.urlopen(
            urllib.request.Request(url, headers=UA), timeout=30
        ).read().decode("utf-8", "replace")
        found = {registrable(h) for h in
                 re.findall(r'href="https?://([^/"\s?#]+)', html)}
        hits = {d for d in found if d and d in cn}
        print(f"{url}: {len(found)} domains, {len(hits)} CN-verified")
        doms |= hits
    except Exception as e:
        print(f"{url}: ERROR {e}")

master = {l.strip().lower() for l in open(args.master) if l.strip()}
new = sorted(d for d in doms if d not in master)
print(f"new vs master: {len(new)}")
open(args.out, "w").write("\n".join(new) + "\n")
for d in new:
    print("  ", d)
print("REVIEW then append to master; run blocklist_audit before installing")
