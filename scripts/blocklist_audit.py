#!/usr/bin/env python3
"""Reverse audit for NRPT rules.

A community-maintained blocklist (AutoProxy format, base64) lists names
whose truthful answers are not reliably obtainable from inside the CN
network. If such a name matches one of your NRPT suffixes, a domestic
resolver would answer it - and a poisoned/bogus answer cannot be saved by
correct routing. Run after EVERY bulk addition to the suffix list.

Usage:
  python3 blocklist_audit.py --master lists/nrpt_domains.txt
Exit code 1 if conflicts found.
"""
import argparse
import base64
import re
import urllib.request

# AutoProxy-format community blocklist (any public mirror; these two
# fallback to each other; override with --blocklist-url if preferred)
DEFAULT_BLOCKLIST = [
    "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt",
    "https://bitbucket.org/gfwlist/gfwlist/raw/master/gfwlist.txt",
]

ap = argparse.ArgumentParser()
ap.add_argument("--master", default="lists/nrpt_domains.txt")
ap.add_argument("--blocklist-url", action="append", dest="urls",
                help="override the default blocklist source(s); may be "
                     "passed multiple times for fallback")
args = ap.parse_args()
urls = args.urls or DEFAULT_BLOCKLIST

raw = None
for u in urls:
    try:
        raw = urllib.request.urlopen(u, timeout=60).read().decode(
            "ascii", "replace")
        print(f"fetched blocklist from {u.split('/')[2]}")
        break
    except Exception as e:
        print(f"{u.split('/')[2]}: {e}")
if raw is None:
    raise SystemExit("all blocklist sources failed")

try:
    text = base64.b64decode("".join(raw.split())).decode("utf-8", "replace")
except Exception:
    text = raw

doms = set()
for line in text.splitlines():
    s = line.strip()
    if not s or s.startswith(("!", "[", "@@", "|http", "https:/")):
        continue
    if s.startswith("||"):
        s = s[2:]
    m = re.match(r"^([a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+)", s)
    if m:
        doms.add(m.group(1).lower())
print(f"blocklist domains: {len(doms)}")

master = {l.strip().lower().lstrip(".") for l in open(args.master) if l.strip()}
# wildcard-style rules installed alongside the suffix list
wild = {"cn", "xn--fiqs8s"}

def hit(d):
    labels = d.split(".")
    for i in range(len(labels) - 1):
        suf = ".".join(labels[i:])
        if suf in master or suf in wild:
            return suf
    return None

conflicts = {}
for d in sorted(doms):
    h = hit(d)
    if h:
        conflicts.setdefault(h, []).append(d)

if not conflicts:
    print("CLEAN - no blocklisted domain matches any NRPT rule")
    raise SystemExit(0)

print("CONFLICTS FOUND:")
for suf, ds in sorted(conflicts.items()):
    print(f"  rule .{suf} matches {len(ds)} blocklisted domains: "
          f"{', '.join(ds[:10])}" + (" ..." if len(ds) > 10 else ""))
print("\nremediation:")
print("  whole-domain conflict  -> remove the rule (that name belongs on")
print("                            the tunnel-DNS path)")
print("  conflicted subtree of a kept rule -> add a longest-match OVERRIDE:")
print('    Add-DnsClientNrptRule -Namespace ".x.kept.com" '
      '-NameServers "1.1.1.1"')
raise SystemExit(1)
