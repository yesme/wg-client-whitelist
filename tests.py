#!/usr/bin/env python3
"""Unit tests for the interval arithmetic this project relies on.
Encodes bugs actually shipped:
  - cn_le off-by-one: cumulative counts went wrong inside merged intervals
    (whole CN cloud ranges misclassified as foreign)
  - un-hole direction inversion: address_exclude instead of re-adding a
    prefix to AllowedIPs (caught only by a runtime assert)
Run: python3 tests.py   (no dependencies)"""
import bisect
import ipaddress
import random


def merge_intervals(iv):
    m = []
    for s, e in sorted(iv):
        if m and s <= m[-1][1] + 1:
            m[-1][1] = max(m[-1][1], e)
        else:
            m.append([s, e])
    return m


def cn_le_fixed(starts, ends, cum, x):
    i = bisect.bisect_right(starts, x) - 1
    if i < 0:
        return 0
    if x <= ends[i]:
        return cum[i] + (x - starts[i] + 1)
    return cum[i + 1]


def brute_count(merged, x):
    n = 0
    for s, e in merged:
        if s <= x <= e:
            return n + (x - s + 1)
        if e < x:
            n += e - s + 1
    return n


def complement_allow(hole_list, last=(1 << 32) - 1):
    """allow = whole space minus holes (gap walk over merged intervals);
    returns ip_network list."""
    out = []
    cur = 0
    for h0, h1 in merge_intervals(hole_list):
        if h0 > cur:
            out += list(ipaddress.summarize_address_range(
                ipaddress.IPv4Address(cur), ipaddress.IPv4Address(h0 - 1)))
        cur = max(cur, h1 + 1)
    if cur <= last:
        out += list(ipaddress.summarize_address_range(
            ipaddress.IPv4Address(cur), ipaddress.IPv4Address(last)))
    return out


def via(nets, x):
    x = ipaddress.IPv4Address(x)
    return any(n.network_address <= x <= n.broadcast_address for n in nets)


def test_cn_le():
    random.seed(7)
    for _ in range(200):
        pts = sorted(random.sample(range(0, 5000), 12))
        iv = [(pts[i], pts[i] + random.randint(0, 300))
              for i in range(0, 12, 2)]
        m = merge_intervals(iv)
        starts = [s for s, _ in m]
        ends = [e for _, e in m]
        cum = [0]
        for s, e in m:
            cum.append(cum[-1] + e - s + 1)
        for x in range(-1, 5600):
            assert cn_le_fixed(starts, ends, cum, x) == brute_count(m, x)
    # production case shape: count at an interval END must be the full
    # cumulative total (the buggy subtract-the-tail form returned less)
    m = merge_intervals([(0, 9), (20, 20)])
    starts = [s for s, _ in m]
    ends = [e for _, e in m]
    cum = [0, 10, 11]
    assert cn_le_fixed(starts, ends, cum, 20) == 11
    print("test_cn_le: OK (fixed form == brute force, 200 fuzz rounds)")


def test_complement():
    random.seed(11)
    for _ in range(50):
        holes = merge_intervals(
            [(random.randint(0, 4000), random.randint(0, 4000) + 40)
             for _ in range(6)])
        nets = complement_allow(holes)
        for x in random.sample(range(0, 4200), 100):
            in_hole = any(s <= x <= e for s, e in holes)
            assert via(nets, x) != in_hole, (x, holes)
    print("test_complement: OK (gap-walk complement == brute membership)")


def test_unhole_direction():
    holes = [[100, 199]]  # hole at ints 100..199 (rest allow)
    allow = complement_allow(holes, last=1000)
    assert not via(allow, 150)
    # correct un-hole: ADD the prefix back into AllowedIPs
    fixed_net = ipaddress.ip_network("0.0.0.120/31")  # covers ints 120,121
    allow2 = list(ipaddress.collapse_addresses(allow + [fixed_net]))
    assert via(allow2, 120) and via(allow2, 121)
    # historical WRONG direction: address_exclude from an allow net
    wrong = []
    for a in allow:
        if fixed_net.subnet_of(a):
            wrong += a.address_exclude(fixed_net)
        else:
            wrong.append(a)
    assert not via(wrong, 120), "exclude direction keeps it OUT of allow"
    print("test_unhole_direction: OK (un-hole == add to allow; "
          "exclude direction demonstrably wrong)")


if __name__ == "__main__":
    test_cn_le()
    test_complement()
    test_unhole_direction()
    print("all tests passed")
