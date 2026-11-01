#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tcpstream80211：乱序、重传、重叠、序号回绕、缺口、无 SYN、坏校验和。段用 scapy 构造再交给 net80211.parse_tcp（校验和由 scapy 算）。
真实抓包和 tshark 的「Follow TCP Stream」对照见 tests/oracle/test_tcpstream_diff.py。"""
import logging
import os
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, Raw, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wifi80211 import net, tcpstream as ts  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def seg(seq, data=b"", flags="A", sport=40000, dport=443, src="10.0.0.2", dst="10.0.0.9", ack=0):
    ip = net.parse_ipv4(bytes(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags) / Raw(data)))
    return ip, net.parse_tcp(ip["payload"], ip)


def feed(segs):
    f = ts.Flows()
    for i, (ip, t) in enumerate(segs):
        f.add(ip["src"], ip["dst"], t, i)
    return f


def one(segs):
    return next(iter(feed(segs).dirs.values()))


print("== 按序、乱序、重传 ==")
d = one([seg(1000, flags="S"), seg(1001, b"hello "), seg(1007, b"world")])
check(d.data() == b"hello world" and not d.gap, "SYN + 两段按序：从 SYN+1 起拼成 hello world")
check(one([seg(1000, flags="S"), seg(1007, b"world"), seg(1001, b"hello ")]).data() == b"hello world", "后一段先到：按序号排好")
d = one([seg(1000, flags="S"), seg(1001, b"hello "), seg(1001, b"hello "), seg(1007, b"world"), seg(1007, b"world")])
check(d.data() == b"hello world", "整段重传：不重复")
d = one([seg(1000, flags="S"), seg(1001, b"hello wo"), seg(1007, b"world!")])
check(d.data() == b"hello world!", "部分重叠（第二段从第 7 字节起，和第一段重叠 2 字节）：重叠部分只取一次")
d = one([seg(1000, flags="S"), seg(1001, b"abc"), seg(1001, b"abcdef")])
check(d.data() == b"abcdef", "同一起点后来的段更长（先发了一半）：取长的")
d = one([seg(1000, flags="S"), seg(1001, b"abcdef"), seg(1003, b"XYZ")])
check(d.data() == b"abcdef", "完全落在已有字节之内的段：不改动已有内容")
check(one([seg(1000, flags="S"), seg(1001, b"abcdef")]).data(limit=4) == b"abcd", "limit 截取前 N 个字节")

print("== 缺口 ==")
d = one([seg(1000, flags="S"), seg(1001, b"aaa"), seg(1010, b"ccc")])
check(d.data() == b"aaa" and d.gap, "中间缺 6 字节：只返回缺口之前的，gap 为 True")
check(d.pieces() == [("data", b"aaa"), ("gap", 6), ("data", b"ccc")], "pieces()：缺口两边的数据分开，缺口记下缺了 6 字节")
check(not one([seg(1000, flags="S"), seg(1001, b"aaa")]).gap and one([seg(1000, flags="S")]).data() == b"", "没缺口 gap 为 False；只有 SYN 没有数据")
d = one([seg(1000, flags="S"), seg(1004, b"bbb")])
check(d.data() == b"" and d.gap, "第一段数据没到（SYN 之后缺 3 字节）：data 为空，gap 为 True")

print("== 没抓到 SYN、回绕 ==")
d = one([seg(5000, b"def"), seg(4997, b"abc")])
check(d.data() == b"abcdef" and d.start == -3, "中途开始：起点取见到的最小序号（后到的更小序号也算，不丢）")
d = one([seg(0xFFFFFFFD, b"abc"), seg(0, b"def"), seg(3, b"ghi")])
check(d.data() == b"abcdefghi", "序号从 2^32 回绕到 0：照常连续")
d = one([seg(0xFFFFFFFF, flags="S"), seg(0, b"xy")])
check(d.data() == b"xy", "SYN 在 2^32-1，数据从 0 起")
d = one([seg(1000, flags="SA", ack=7), seg(1001, b"srv")])
check(d.data() == b"srv", "SYN+ACK 同样占一个序号")

d = one([seg(1000, flags="S", data=b"fast"), seg(1005, b"-open")])
check(d.data() == b"fast-open", "SYN 里带数据（TCP Fast Open）：数据从 SYN 的下一个序号起，和后面的段接上")
d = one([seg(1000, flags="S"), seg(990, b"0123456789ABC"), seg(1003, b"DEF")])
check(d.data() == b"BCDEF", "有个段盖住了 SYN 之前的序号：起点之前的字节丢掉，其余接上")

print("== 校验和 ==")
ip, t = seg(1001, b"junk")
t = dict(t, checksum_ok=False)
f = ts.Flows()
f.add(ip["src"], ip["dst"], seg(1000, flags="S")[1], 0)
f.add(ip["src"], ip["dst"], t, 1)
f.add(ip["src"], ip["dst"], seg(1001, b"good")[1], 2)
check(next(iter(f.dirs.values())).data() == b"good", "校验和不对的段丢掉，正确的重传补上")

print("== 方向与连接 ==")
f = feed([seg(1000, flags="S"), seg(1001, b"GET"), seg(7000, flags="SA", sport=443, dport=40000, src="10.0.0.9", dst="10.0.0.2"), seg(7001, b"200", sport=443, dport=40000, src="10.0.0.9", dst="10.0.0.2"),
          seg(50, b"zzz", sport=40001)])
pairs = f.pairs()
check(len(pairs) == 2 and len(f.dirs) == 3, "两条连接、三个方向（第二条连接只抓到一个方向）")
p = next(x for x in pairs if x["key"][1] == 40000)
check(p["client"] == ("10.0.0.2", 40000, "10.0.0.9", 443) and p["fwd"].data() == b"GET" and p["rev"].data() == b"200", "client 是发 SYN 的一方；两个方向各自拼接")
f = feed([seg(7000, flags="SA", sport=443, dport=40000, src="10.0.0.9", dst="10.0.0.2"), seg(1000, flags="S")])
check(f.pairs()[0]["client"] == ("10.0.0.2", 40000, "10.0.0.9", 443), "SYN+ACK 先出现：client 仍是只发 SYN 的那一方")
f = feed([seg(1000, flags="S", sport=40000, dport=40001), seg(5000, flags="S", sport=40001, dport=40000, src="10.0.0.9", dst="10.0.0.2")])
check(f.pairs()[0]["client"] == ("10.0.0.2", 40000, "10.0.0.9", 40001), "双方同时发 SYN：按先出现的方向，不颠倒")
check(next(x for x in pairs if x["key"][1] == 40001)["rev"] is None, "只有一个方向：rev 为 None")

print("== 容量 ==")
saved = ts.MAX_BYTES
ts.MAX_BYTES = 10
d = one([seg(1000, flags="S"), seg(1001, b"a" * 8), seg(1009, b"b" * 8)])
ts.MAX_BYTES = saved
check(d.data() == b"a" * 8, "超过每方向的存储上限：后面的段不再收")
ts.MAX_BYTES = 10
d = one([seg(1000, flags="S"), seg(1001, b"a" * 8), seg(1009, b"b" * 8), seg(1017, b"c" * 2), seg(1019, b"d")])
ts.MAX_BYTES = saved
check(d.data() == b"a" * 8 and not d.gap and d.missing_bytes() == 0 and d.full, "存满之后更小的段也不再收：不会在中间留下假缺口（原先 c 会挤进来，被当成缺 8 字节）")
ts.MAX_BYTES = 10
f = feed([seg(1000, flags="S"), seg(1001, b"a" * 8), seg(1009, b"b" * 8), seg(1017, b"c" * 2)])
ts.MAX_BYTES = saved
s = f.summary()
check(s["with_gap"] == 0 and s["missing_bytes"] == 0, "诊断计数：存满的方向不算「中途缺包」")
ts.MAX_BYTES = 10
d = one([seg(1000, flags="S"), seg(1001, b"a" * 8), seg(1009, b"b" * 8), seg(1001, b"a" * 8)])
ts.MAX_BYTES = saved
check(d.data() == b"a" * 8 and d.packets == 4, "存满之后重传前面的段：内容不变，包数照数（4 个：SYN、a、b、重传的 a）")
ts.MAX_BYTES = 10
d = one([seg(1000, flags="S"), seg(1001, b"a" * 4), seg(1009, b"b" * 4)])
ts.MAX_BYTES = saved
check(d.data() == b"a" * 4 and d.gap and d.missing_bytes() == 4 and not d.full, "没存满时真正的缺口照旧报告（缺 4 字节）")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
