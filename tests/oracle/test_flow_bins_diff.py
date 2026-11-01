#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""流量的时间格子对照 tshark：24 个样例解密后，每个设备的每条 TCP / UDP 流在每一格（时间 // activity.BIN_SECONDS）里的上行 / 下行 L3 字节，
和 tshark 逐帧读到的 frame.time_epoch 与 ip.len / ipv6.plen 按同样方式累加的结果完全相同；各格加起来也等于 traffic 的整条流字节。
口径和 test_traffic_diff.py 一样（只比 tshark 解开了的帧；AP 发出的组播 / 广播帧不算；ICMP 差错报文去掉）。"""
import collections
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


FIELDS = ["ip.src", "ip.dst", "ip.len", "ipv6.src", "ipv6.dst", "ipv6.plen", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "wlan.fc.tods", "wlan.ra", "frame.number", "frame.time_epoch"]


def canon_v6(ip):
    import ipaddress
    return str(ipaddress.ip_address(ip)) if ":" in ip else ip


def tshark_bins(path, keys):
    """-> ({(协议, 设备 IP, 设备端口, 对端 IP, 对端端口): {格: [上行字节, 下行字节]}}, 解开了的帧号集合)"""
    usable, _ = d.tshark_usable(keys)
    with d.key_env(usable) as env:
        cmd = ["tshark", "-r", path] + d.TSHARK_DECRYPT + ["-Y", "wlan.fc.protected==1 && wlan.fc.type==2 && (tcp || udp) && !icmp", "-T", "fields", "-E", "occurrence=f"]
        for f in FIELDS:
            cmd += ["-e", f]
        out = subprocess.run(cmd, capture_output=True, text=True, env=env).stdout
    flows, seen = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0])), set()
    for line in out.split("\n"):
        if not line:
            continue
        r = dict(zip(FIELDS, (line.split("\t") + [""] * len(FIELDS))[:len(FIELDS)]))
        proto, sp, dp = ("tcp", r["tcp.srcport"], r["tcp.dstport"]) if r["tcp.srcport"] else ("udp", r["udp.srcport"], r["udp.dstport"])
        if r["ip.src"]:
            src, dst, length = r["ip.src"], r["ip.dst"], int(r["ip.len"])
        else:
            src, dst, length = r["ipv6.src"], r["ipv6.dst"], 40 + int(r["ipv6.plen"])
        up = r["wlan.fc.tods"] in ("1", "True")
        if not up and int(r["wlan.ra"].split(":")[0], 16) & 1:
            continue
        seen.add(int(r["frame.number"]))
        key = (proto, canon_v6(src), int(sp), canon_v6(dst), int(dp)) if up else (proto, canon_v6(dst), int(dp), canon_v6(src), int(sp))
        flows[key][int(float(r["frame.time_epoch"]) // activity.BIN_SECONDS)][0 if up else 1] += length
    return flows, seen


fetch_samples.fetch()
keys = d.parse_keys()
cells = flows_n = 0
for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    frames = list(fr.iter_frames(path))
    dec = pl.decrypt_capture(frames, keys)
    theirs_raw, seen = tshark_bins(path, keys)
    theirs = {k: {b: v for b, v in bins.items()} for k, bins in theirs_raw.items()}
    res = activity.analyze(frames, {n: v for n, v in dec.items() if n in seen})
    mine = {(proto, canon_v6(lip), lport, canon_v6(rip), rport): bins for (st, proto, lip, lport, rip, rport), bins in res.flow_bins.items()}
    if theirs or mine:
        check(mine == theirs, "%s：%d 条流、%d 个格子的上下行字节与 tshark 完全相同（我们 %d 条）" % (name, len(theirs), sum(len(b) for b in theirs.values()), len(mine)))
        cells += sum(len(b) for b in theirs.values())
        flows_n += len(theirs)
    full = activity.analyze(frames, dec)
    ok = all(sum(c[0] for c in full.flow_bins[k].values()) == a["bytes_up"] and sum(c[1] for c in full.flow_bins[k].values()) == a["bytes_down"] for k, a in full.flow_stats.items())
    check(ok and set(full.flow_bins) == set(full.flow_stats), "%s：每条流的各格加起来等于整条流的上 / 下行字节" % name)
check(cells > 0, "一共比较了 %d 条流、%d 个格子" % (flows_n, cells))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
