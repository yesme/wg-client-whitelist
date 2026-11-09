#!/usr/bin/env python3
"""Build the NRPT suffix master list:
china-list (accelerated-domains) INTERSECT Cisco Umbrella top-1M,
traffic-ranked, plus a curated core of CN consumer staples.

Auto-downloads both data files if missing. Re-run quarterly.

Usage: python3 gen_nrpt_list.py --top 500 --out lists/nrpt_domains.txt
"""
import argparse
import os
import re
import urllib.request
import zipfile

CHINA_URL = ("https://raw.githubusercontent.com/felixonmars/"
             "dnsmasq-china-list/master/accelerated-domains.china.conf")
UMBRELLA_URL = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"

# curated staples that must be present regardless of traffic rank
CORE = [
    # portals / search
    "baidu.com", "bdstatic.com", "bdimg.com", "bcebos.com", "sogou.com",
    "so.com", "sm.cn", "163.com", "126.com", "sina.com.cn", "sina.cn",
    "sohu.com", "ifeng.com", "qq.com", "weixin.qq.com", "qpic.cn",
    "gtimg.com", "myqcloud.com",
    # ecommerce / payment
    "taobao.com", "tmall.com", "alipay.com", "aliyun.com", "alicdn.com",
    "alibaba.com", "1688.com", "jd.com", "pinduoduo.com", "vip.com",
    "suning.com", "dangdang.com", "kaola.com", "meituan.com", "dianping.com",
    "ele.me", "ctrip.com", "qunar.com", "trip.com", "fliggy.com", "183.com",
    # video / audio / live
    "bilibili.com", "hdslb.com", "bilivideo.com", "iqiyi.com", "qy.net",
    "youku.com", "ykimg.com", "mgtv.com", "douyin.com", "kuaishou.com",
    "huya.com", "douyu.com", "acfun.cn", "xiaohongshu.com", "xhscdn.com",
    "kugou.com", "kuwo.cn", "migu.cn", "ximalaya.com", "xmcdn.com",
    # social / community
    "weibo.com", "zhihu.com", "zhimg.com", "douban.com", "tieba.baidu.com",
    # CN CDNs (first-party or CN-owned only - NEVER global CDNs)
    "qiniu.com", "qiniudn.com", "qbox.me", "upyun.com", "lxdns.com",
    "wscdns.com", "chinanetcenter.com", "ksyun.com", "baidubce.com",
    "bootcdn.net", "staticfile.org", "aliyuncdn.com",
    # updates / OEM
    "apple.com", "mzstatic.com", "cdn-apple.com", "windowsupdate.com",
    "microsoft.com", "visualstudio.com", "miui.com", "vmall.com",
    "oppo.com", "vivo.com", "oneplus.com", "lenovo.com",
    # office / collab
    "feishu.cn", "feishu.com", "dingtalk.com", "kdocs.cn", "wps.cn",
    "yuque.com", "shimo.im",
    # AI / LLM API providers headquartered in CN
    "moonshot.cn", "kimi.com", "deepseek.com", "bigmodel.cn", "z.ai",
    "aliyuncs.com", "volces.com", "minimax.cn", "siliconflow.cn",
    "stepfun.com", "xiaomimimo.com",
]

ap = argparse.ArgumentParser()
ap.add_argument("--top", type=int, default=500)
ap.add_argument("--out", default="nrpt_domains.txt")
ap.add_argument("--china", default="china_accel.conf")
ap.add_argument("--umbrella", default="top-1m.csv.zip")
args = ap.parse_args()

if not os.path.exists(args.china):
    urllib.request.urlretrieve(CHINA_URL, args.china)
os.makedirs(os.path.dirname(args.umbrella) or ".", exist_ok=True)
if not os.path.exists(args.umbrella):
    urllib.request.urlretrieve(UMBRELLA_URL, args.umbrella)

cn = set()
for line in open(args.china, encoding="utf-8", errors="replace"):
    m = re.match(r"^server=/([^/]+)/", line)
    if m:
        cn.add(m.group(1).lower())
print(f"china-list: {len(cn)} domains")

ranked = []
with zipfile.ZipFile(args.umbrella) as z:
    with z.open(z.namelist()[0]) as f:
        for raw in f.read().decode("utf-8", "replace").splitlines():
            p = raw.strip().split(",")
            if len(p) == 2 and p[1].lower() in cn:
                ranked.append(p[1].lower())
print(f"intersection in top-1M: {len(ranked)}")

final = []
for d in ranked[:args.top] + CORE:
    if d not in final:
        final.append(d)
print(f"final: {len(final)} suffixes (top{args.top} + core{len(CORE)})")

open(args.out, "w", encoding="utf-8").write("\n".join(sorted(final)) + "\n")
print(f"wrote {args.out}")
print("next: run blocklist_audit.py against this list before installing")
