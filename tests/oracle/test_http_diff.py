#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP 请求事件（activity80211 的 kind=http）对照 tshark：wpa-Induction 解密后的 5 条明文 HTTP 连接，
每个请求的 方法、Host、URI（截到 200 字符）、服务器 IP 和端口和 tshark 的 http.request.* 字段相同（逐连接按请求顺序）。
这个样例漏抓过包（见 test_tcpstream_diff.py）：漏在客户端方向的请求体或请求行处，我们只认头部完整的请求，tshark 同样不会给出头部不完整的请求，两边的差异固定在表里。"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decrypt_oracle as d  # noqa: E402
import fetch_samples  # noqa: E402
from wifi80211 import activity  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import pipeline as pl  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def tshark_requests(path, keys):
    """-> [(帧号, 客户端端口, 服务器 IP, 服务器端口, 方法, host, uri)]，一帧里有几个请求就有几行（字段是 | 连起来的列表）。"""
    usable, _ = d.tshark_usable(keys)
    with d.key_env(usable) as env:
        cmd = ["tshark", "-r", path] + d.TSHARK_DECRYPT + ["-Y", "http.request && tcp", "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|",
                                                           "-e", "frame.number", "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "http.request.method", "-e", "http.host", "-e", "http.request.uri"]
        out = subprocess.run(cmd, capture_output=True, text=True, env=env).stdout
    rows = []
    for line in out.split("\n"):
        if line:
            n, sport, dst, dport, m, h, u = line.split("\t")
            for mm, hh, uu in zip(m.split("|"), h.split("|"), u.split("|")):
                rows.append((int(n), int(sport), dst, int(dport), mm, hh, uu))
    return rows


fetch_samples.fetch()
keys = d.parse_keys()
path = os.path.join(fetch_samples.SAMPLE_DIR, "wpa-Induction.pcap.gz")
frames = list(fr.iter_frames(path))
ev = [e for e in activity.build(frames, pl.decrypt_capture(frames, keys)) if e["kind"] == "http"]
ts = tshark_requests(path, keys)
ours = sorted((e["server"], e["port"], e["method"], e["name"], e["path"]) for e in ev)
theirs = sorted((dst, dport, m, h.split(":")[0].lower(), u[:200]) for _n, _s, dst, dport, m, h, u in ts)
check(ours == theirs, "wpa-Induction：我们的 %d 个 HTTP 请求（服务器、端口、方法、Host、URI）和 tshark 的 %d 个相同" % (len(ours), len(theirs)))
per_server = {}
for e in ev:
    per_server[(e["server"], e["port"])] = per_server.get((e["server"], e["port"]), 0) + 1
check(per_server == {("66.230.200.100", 80): 1, ("66.230.200.228", 80): 1, ("209.188.21.206", 80): 8, ("72.14.255.99", 80): 1} and len(ev) == 11,
      "5 条连接 4 台服务器共 11 个请求（其中 51692 号连接漏抓了 467 字节，缺口前后各一个请求）：%s" % per_server)
check(all(e["via"] == "host" for e in ev), "名字都来自 Host 头")
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
