#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""streaming：从「按 5 秒一格的下行字节」里找持续下行的时段（连续、允许空格、至少多久），以及这些格子是怎么从包里来的
（activity.Collector.flow_bins，经 plain.analyze 和 traffic.flows(with_bins=True)）。
真实 tshark 对照见 tests/oracle/test_flow_bins_diff.py。默认参数没有用真实数据标定，这里的测试只证明机制按说明工作，不证明门槛合适。"""
import logging
import os
import struct
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, Raw, TCP, UDP, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wifi80211 import activity, capture, plain, streaming, traffic  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


B = activity.BIN_SECONDS
check(B == 5, "一格是 5 秒（streaming 的说明和默认参数按这个写）")
RATE = 100000                                        # 字节 / 秒：高于默认的 50000
fast = int(RATE * B)                                 # 一格里收这么多字节就算活跃


def run(cells, **kw):
    """cells：{格: 字节} -> 时段列表"""
    return streaming.episodes(cells, **kw)


print("== 找时段 ==")
e = run({i: fast for i in range(100, 112)})                      # 连续 12 格 = 60 秒
check(len(e) == 1 and e[0]["seconds"] == 60 and e[0]["start"] == 500 and e[0]["end"] == 560 and e[0]["bytes_down"] == 12 * fast and e[0]["avg_rate"] == RATE and e[0]["active_seconds"] == 60,
      "连续 12 格：一个时段，60 秒，起止对得上，字节和平均速率是整段的")
check(run({i: fast // 4 for i in range(100, 130)}) == [], "速率低于门槛：没有时段")
check(len(run({i: fast // 2 for i in range(100, 112)}, min_rate=RATE // 2)) == 1, "速率恰好等于门槛算活跃")
check(run({i: fast // 2 - 1 for i in range(100, 112)}, min_rate=RATE // 2) == [], "差一个字节就不算")
check(run({i: fast for i in range(100, 105)}) == [], "只有 25 秒（不到 30 秒）：不成时段")
check(len(run({i: fast for i in range(100, 106)})) == 1, "正好 30 秒：成时段")
check(len(run({i: fast for i in range(100, 105)}, min_seconds=25)) == 1, "min_seconds 可以调")

print("== 空格 ==")
chunks = {100 + 2 * k: fast * 2 for k in range(8)}                # 每隔一格来一块（间隔 5 秒的安静格）：像一块一块拉视频
e = run(chunks)
check(len(e) == 1 and e[0]["seconds"] == 75 and e[0]["active_seconds"] == 40 and e[0]["bytes_down"] == 8 * fast * 2, "一块一块拉（中间一格安静）：连成一个时段，整段 75 秒，活跃 40 秒")
two = {**{i: fast for i in range(100, 108)}, **{i: fast for i in range(112, 120)}}     # 中间空 4 格 = 20 秒
e = run(two)
check(len(e) == 2 and e[0]["end"] == 540 and e[1]["start"] == 560, "中间空 20 秒（大于 max_gap 15）：分成两个时段")
e = run(two, max_gap=20)
check(len(e) == 1 and e[0]["seconds"] == 100, "max_gap 放到 20：连成一个")
three = {**{i: fast for i in range(100, 108)}, **{i: fast for i in range(111, 119)}}   # 空 3 格 = 15 秒，正好等于 max_gap
check(len(run(three)) == 1, "空格正好等于 max_gap：连起来")
mid = dict({i: fast for i in range(100, 108)})
mid[103] = 10                                                      # 中间一格几乎没有流量
e = run(mid)
check(len(e) == 1 and e[0]["bytes_down"] == 7 * fast + 10 and e[0]["active_seconds"] == 35, "中间有一格太慢：它不算活跃，但它的字节仍计入整段")
check(run({}) == [], "没有数据：没有时段")

print("== 参数检查 ==")
for kw in ({"min_rate": 0}, {"min_seconds": 0}, {"max_gap": -1}, {"bin_seconds": 0}):
    try:
        run({1: 1}, **kw)
        check(False, "%s 应该报错" % kw)
    except ValueError:
        check(True, "%s：报错" % kw)

print("== 按应用 ==")


class Rules:
    def label(self, name):
        if name.endswith("video.example"):
            return {"app": "视频应用", "category": "视频", "company": None}
        if name.endswith("m1.example"):
            return {"app": "成员一", "category": "视频", "company": "某公司"}
        if name.endswith("m2.example"):
            return {"app": "成员二", "category": "社交", "company": "某公司"}
        return None


cells1 = {i: fast // 2 for i in range(100, 112)}
cells2 = {i: fast // 2 for i in range(100, 112)}                     # 同一应用的两条流，各一半：合起来才达到门槛
fl = [
    {"station": "d1", "name": "a.video.example", "bins": {k: [10, v] for k, v in cells1.items()}},
    {"station": "d1", "name": "b.video.example", "bins": {k: [10, v] for k, v in cells2.items()}},
    {"station": "d1", "name": "other.example", "bins": {k: [10, fast] for k in range(100, 112)}},   # 没规则：不统计
    {"station": "d1", "name": None, "bins": {k: [10, fast] for k in range(100, 112)}},                 # 没名字：不统计
    {"station": "d2", "name": "a.video.example", "bins": {k: [10, 0] for k in range(100, 112)}},      # 只有上行：没有下行
]
s = streaming.summary(Rules(), fl)
check(list(s) == [("d1", "视频应用")] and s[("d1", "视频应用")]["seconds"] == 60 and s[("d1", "视频应用")]["bytes_down"] == 12 * fast, "同一应用的两条流合起来算；没规则 / 没名字 / 只有上行的不算；设备分开")
series = streaming.app_series(Rules(), fl)
check(set(series) == {("d1", "视频应用")} and series[("d1", "视频应用")][100] == fast, "app_series：只含认得出应用的流，下行字节逐格相加")
check(s[("d1", "视频应用")]["apps"] == ["视频应用"], "summary：没写 company 的应用，组就是它自己")

print("== 同一家公司合起来算 ==")
half = {k: [0, fast // 4] for k in range(100, 112)}           # 每个成员单独只有门槛的一半（fast 是 100 KB/秒，这里 25 KB/秒，门槛 50）：单独看都不成时段，两个合起来刚好过线
fl2 = [{"station": "d1", "name": "a.m1.example", "bins": half}, {"station": "d1", "name": "b.m2.example", "bins": half},
       {"station": "d1", "name": "c.video.example", "bins": half}, {"station": "d2", "name": "a.m1.example", "bins": half}]
s3 = streaming.summary(Rules(), fl2)
check(set(s3) == {("d1", "某公司")}, "两个应用的 company 相同：合成一组「某公司」，各自单独看都不够的流量合起来过了门槛")
check(("d1", "某公司") in s3 and s3[("d1", "某公司")]["apps"] == ["成员一", "成员二"] and s3[("d1", "某公司")]["seconds"] == 60 and s3[("d1", "某公司")]["bytes_down"] == 12 * (fast // 2), "成员列表是排好序的两个应用，字节是两个应用相加")
check(("d1", "视频应用") not in s3, "没写 company 的应用不会被并进别人的组，它自己单独看不够门槛")
check(("d2", "某公司") not in s3, "设备之间不合并：d2 只有一个成员的一半流量，不成时段")
check(streaming.app_series(Rules(), fl2)[("d1", "某公司")][100] == fast // 2, "app_series：组的格子是成员的下行相加")
mem = {}
streaming.app_series(Rules(), fl2, mem)
check(mem == {("d1", "某公司"): {"成员一", "成员二"}, ("d1", "视频应用"): {"视频应用"}, ("d2", "某公司"): {"成员一"}}, "app_series 填 members：每组出现过的应用")

print("== 没有名字的下行占多少 ==")
fl3 = [{"station": "d1", "name": "a.m1.example", "bytes_down": 600}, {"station": "d1", "name": None, "bytes_down": 400}, {"station": "d2", "name": None, "bytes_down": 0},
       {"station": "d2", "name": "x", "bytes_down": 0}]
check(streaming.unnamed_share(fl3) == {"d1": (400, 1000), "d2": (0, 0)}, "unnamed_share：每台设备没有名字的下行字节和全部下行字节")
s2 = streaming.summary(Rules(), fl, min_rate=2 * RATE)
check(s2 == {}, "提高门槛：没有时段就不出现在结果里")

print("== 格子是怎么从包里来的 ==")
DEV, RTR = "02:00:00:00:00:01", "02:00:00:00:00:fe"
LAN, SRV = "192.168.1.20", "203.0.113.80"


def pkt(ts, up, n):
    ip = IP(src=LAN, dst=SRV) / TCP(sport=40000, dport=443) if up else IP(src=SRV, dst=LAN) / TCP(sport=443, dport=40000)
    return ts, bytes((Ether(src=DEV, dst=RTR) if up else Ether(src=RTR, dst=DEV)) / ip / Raw(b"x" * n))


def pcap(packets):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, b in packets:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(b), len(b)) + b
    return out


plan = [(100.0, True, 10), (100.0, False, 1000), (102.5, False, 1400), (104.999, False, 500), (105.0, False, 700), (111.0, True, 20), (111.0, False, 50), (500.2, False, 100)]
res = plain.analyze(plain.iter_packets(capture.parse_capture(pcap([pkt(*p) for p in plan]))))
fl = traffic.flows(res, with_bins=True)
want = {20: [50, 40 + 1000 + 40 + 1400 + 40 + 500], 21: [0, 40 + 700], 22: [60, 90], 100: [0, 140]}
check(len(fl) == 1 and fl[0]["bins"] == want, "每个包按时间 // 5 落进格子，上下行分开，字节是 IP 总长度（实际 %s）" % (fl[0]["bins"] if fl else None))
check(sum(c[0] for c in fl[0]["bins"].values()) == fl[0]["bytes_up"] and sum(c[1] for c in fl[0]["bins"].values()) == fl[0]["bytes_down"], "各格子加起来等于流的总字节")
check("bins" not in traffic.flows(res)[0], "不要 bins 时流的字段不变")
check(streaming.app_series(Rules(), fl) == {}, "这条流没有名字：app_series 为空")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
