#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""抓包质量（wifi80211/health.py）：用真正的 802.11 头字节（经 parser.parse_mac_header）造帧序列，检查序号缺口的记账和每台设备的汇总——
回绕 4095 -> 0、重传（同序号）、分片、缺口上限（64 算丢帧，65 起算断档）、往回走的旧帧、发送方计数器重置后重新对齐、
非 QoS 数据与管理帧共用一个计数器、QoS 按 TID 分开、两种 AP（每个接收方一个计数器 / 所有接收方共用）下自动选对分法、
已知丢帧率下估计与真实相符、长时间没发帧（断档）不冲掉丢帧率、校验和不对的帧不参与、设备归属、握手状态的提示。
真实样例上的对照（tshark 重算、删帧实验）见 tests/oracle/test_health_diff.py。"""
import os
import random
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import health, parser  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


AP, S1, S2 = "02:00:00:00:00:01", "02:00:00:00:00:a1", "02:00:00:00:00:a2"


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


class Gen:
    """按顺序造帧，帧号自增。"""

    def __init__(self):
        self.n = 0
        self.out = []

    def add(self, typ, sub, a1, a2, a3, sn, frag=0, retry=0, tods=0, fromds=0, tid=None, prot=0, fcs_ok=None):
        self.n += 1
        fc0 = (typ << 2) | (sub << 4)
        fc1 = tods | (fromds << 1) | (retry << 3) | (prot << 6)
        hdr = struct.pack("<BBH", fc0, fc1, 0) + mac(a1) + mac(a2) + mac(a3) + struct.pack("<H", (sn << 4) | frag)
        if typ == 2 and sub & 8:
            hdr += struct.pack("<H", tid or 0)
        body = b"\x00" * 8
        h = parser.parse_mac_header(hdr + body)
        self.out.append(fr.Frame(self.n, self.n * 0.01, hdr + body, h, body, fcs_ok))
        return self

    def up(self, sta, sn, tid=0, **kw):                  # 设备发给 AP 的 QoS 数据（ToDS）
        return self.add(2, 8, AP, sta, AP, sn, tods=1, tid=tid, **kw)

    def down(self, sta, sn, tid=0, **kw):                # AP 发给设备的 QoS 数据（FromDS）
        return self.add(2, 8, sta, AP, AP, sn, fromds=1, tid=tid, **kw)

    def mgmt(self, ta, ra, sn, **kw):                    # 管理帧（探测响应）
        return self.add(0, 5, ra, ta, AP, sn, **kw)


def one(frames, by="ra"):
    """只有一个计数器时它的统计。"""
    cs = health.sequence(frames, by)["counters"]
    assert len(cs) == 1, cs
    return list(cs.values())[0]


print("== 单个计数器的记账 ==")
c = one(Gen().up(S1, 0).up(S1, 1).up(S1, 2).up(S1, 3).out)
check((c["seen"], c["missing"], c["outages"], c["dup"]) == (4, 0, 0, 0), "连续的序号：听到 4 个，没有缺口")
c = one(Gen().up(S1, 0).up(S1, 1).up(S1, 3).up(S1, 7).out)
check((c["seen"], c["missing"]) == (4, 1 + 3), "0,1,3,7：缺口 1 + 3 = 4")
c = one(Gen().up(S1, 4094).up(S1, 4095).up(S1, 0).up(S1, 1).out)
check((c["seen"], c["missing"], c["reordered"]) == (4, 0, 0), "回绕 4094,4095,0,1：没有缺口，也不当作往回走")
c = one(Gen().up(S1, 4094).up(S1, 0).out)
check((c["seen"], c["missing"]) == (2, 1), "回绕时缺 4095：缺口 1")
c = one(Gen().up(S1, 10).up(S1, 11, retry=1).up(S1, 11, retry=1).up(S1, 12).out)
check((c["seen"], c["missing"], c["dup"], c["retries"]) == (3, 0, 1, 2), "同序号的重传不算新帧，也不算缺口；重传位单独计数")
c = one(Gen().up(S1, 5).up(S1, 7, retry=1).out)
check((c["seen"], c["missing"], c["retries"]) == (2, 1, 1), "第一次发送没听到、只听到重传（序号跳了）：6 算缺口")
c = one(Gen().up(S1, 10, frag=0).up(S1, 10, frag=1).up(S1, 10, frag=2).up(S1, 11).out)
check((c["seen"], c["missing"], c["dup"]) == (2, 0, 2), "分片（同序号、分片号递增）：当作一个帧，不算缺口")
c = one(Gen().up(S1, 0).up(S1, 65).out)
check((c["missing"], c["outages"], c["outage_frames"]) == (64, 0, 0), "一次缺 64 个：算丢帧（MAX_LOSS_GAP = 64）")
c = one(Gen().up(S1, 0).up(S1, 66).out)
check((c["missing"], c["outages"], c["outage_frames"], c["seen"]) == (0, 1, 65, 2), "一次缺 65 个：算断档，不进缺口；断档帧数 65，两个帧都算听到")
c = one(Gen().up(S1, 100).up(S1, 101).up(S1, 99).up(S1, 102).out)
check((c["seen"], c["missing"], c["reordered"]) == (3, 0, 1), "迟到的旧帧（99）：算乱序，不更新基准，后面的 102 不受影响")
g = Gen().up(S1, 100)
for sn in range(4000, 4008):
    g.up(S1, sn)
g.up(S1, 4008).up(S1, 4009)
c = one(g.out)
check((c["reordered"], c["missing"], c["outages"], c["seen"]) == (8, 0, 0, 4), "发送方计数器重置（连续 8 个都往回走）：重新对齐，之后的 4008、4009 正常记")
g = Gen().up(S1, 100)
for sn in range(4000, 4007):
    g.up(S1, sn)
g.up(S1, 101)
c = one(g.out)
check((c["reordered"], c["missing"], c["seen"]) == (7, 0, 2), "只有 7 个往回走就回来了：还没到重新对齐，回来的 101 正常")

print("== 哪些帧共用一个计数器 ==")
g = Gen().mgmt(S1, AP, 1).add(2, 4, AP, S1, AP, 2, tods=1).mgmt(S1, AP, 3)             # 管理帧、Null 数据帧（非 QoS）
cs = health.sequence(g.out)["counters"]
check(len(cs) == 1 and list(cs.values())[0]["missing"] == 0 and list(cs.values())[0]["seen"] == 3, "管理帧和非 QoS 的数据帧（Null）共用发送方的一个计数器：1,2,3 没有缺口")
g = Gen().up(S1, 1, tid=0).up(S1, 100, tid=5).up(S1, 2, tid=0).up(S1, 101, tid=5).up(S1, 3, tid=0)
cs = health.sequence(g.out)["counters"]
check(len(cs) == 2 and sum(x["missing"] for x in cs.values()) == 0 and sum(x["reordered"] for x in cs.values()) == 0, "QoS 的不同 TID 各一个计数器：交错的 TID 0 和 TID 5 都没有缺口")
g = Gen().add(2, 8, "01:00:5e:00:00:fb", AP, AP, 1, fromds=1, tid=0).add(2, 8, "01:00:5e:00:00:fb", AP, AP, 2, fromds=1, tid=0).down(S1, 500).down(S1, 501)
cs = health.sequence(g.out)["counters"]
check(len(cs) == 2 and all(x["missing"] == 0 for x in cs.values()), "组播的 QoS 帧单独一个计数器，不和发给设备的单播混在一起")

g = Gen()
for i in range(50):                                                                  # 组播与单播各有各的序号；即使只按（发送方, TID）分，组播也不能和单播混在一起
    g.add(2, 8, "01:00:5e:00:00:fb", AP, AP, i, fromds=1, tid=0).down(S1, 500 + i)
res = health.sequence(g.out, "tid")
check(len(res["counters"]) == 2 and sum(x["missing"] for x in res["counters"].values()) == 0 and sum(x["reordered"] for x in res["counters"].values()) == 0,
      "只按（发送方, TID）分时，组播的 QoS 帧仍是单独一个计数器")

print("== 两种 AP：序号计数器按接收方分，还是所有接收方共用 ==")
g = Gen()
for i in range(100):                                                                # AP 给每个设备一个计数器
    g.down(S1, i).down(S2, 1000 + i)
res = health.sequence(g.out)
check(res["choice"] == {(AP, 0): "ra"} and sum(x["missing"] for x in res["counters"].values()) == 0 and len(res["counters"]) == 2, "每个接收方一个计数器的 AP：选「按接收方分」，没有假缺口")
g = Gen()
for i in range(100):                                                                # AP 所有设备共用一个 TID 计数器
    g.down(S1, 2 * i).down(S2, 2 * i + 1)
res = health.sequence(g.out)
check(res["choice"] == {(AP, 0): "tid"} and sum(x["missing"] for x in res["counters"].values()) == 0, "共用一个计数器的 AP：选「只按发送方和 TID」，没有假缺口（按接收方分会有 99 个假缺口）")
check(sum(x["missing"] for x in health.sequence(g.out, "ra")["counters"].values()) > 90, "（对照）共用计数器的 AP 如果硬按接收方分：全是假缺口")
st = health.sequence(g.out)["station"]
check(set(st.values()) == {None}, "选了粗分法时，缺口只进总计，不归任何设备")
rng = random.Random(7)
g = Gen()
dropped = 0
for i in range(2000):
    for sta, base in ((S1, 0), (S2, 3000)):
        if rng.random() < 0.10:
            dropped += 1
            continue
        g.down(sta, (base + i) % 4096)
res = health.sequence(g.out)
tot = health._sum(res["counters"].values())
check(res["choice"] == {(AP, 0): "ra"} and abs(tot["loss"] - dropped / 4000) < 0.003, "每个接收方一个计数器、丢 10%%：仍选「按接收方分」，估计 %.1f%% 对真实 %.1f%%" % (100 * tot["loss"], 100 * dropped / 4000))

print("== 已知丢帧率：估计要对上 ==")
for p in (0.05, 0.10, 0.20):
    rng = random.Random(int(p * 100))
    g = Gen()
    kept = dropped = 0
    sn = 0
    for _ in range(10000):
        if rng.random() < p:
            dropped += 1
        else:
            g.up(S1, sn % 4096)
            kept += 1
        sn += 1
    c = one(g.out)
    est = c["missing"] / (c["seen"] + c["missing"])
    real = dropped / (kept + dropped)
    check(abs(est - real) < 0.002 and c["outages"] == 0, "丢 %d%%（10000 个帧，带回绕）：估计 %.2f%%，真实 %.2f%%，差在 0.2 个百分点内，没有断档" % (round(p * 100), 100 * est, 100 * real))
rng = random.Random(3)
g = Gen()
sn = 0
for _ in range(3000):
    if rng.random() >= 0.10:
        g.up(S1, sn % 4096, retry=int(rng.random() < 0.2))
        if rng.random() < 0.2:
            g.up(S1, sn % 4096, retry=1)                          # 重传一次（同序号）
    sn += 1
c = one(g.out)
check(abs(c["missing"] / (c["seen"] + c["missing"]) - 0.10) < 0.01, "加上大量同序号的重传：丢帧率不受影响（仍约 10%%，测得 %.1f%%）" % (100 * c["missing"] / (c["seen"] + c["missing"])))

print("== 长时间没发帧（断档）不冲掉丢帧率 ==")
g = Gen()
for i in range(200):
    if i % 10 != 5:
        g.up(S1, i)                                                                  # 10% 丢帧
base = one(g.out)
g2 = Gen()
for i in range(200):
    if i % 10 != 5:
        g2.up(S1, i)
for i in range(700, 900):
    if i % 10 != 5:
        g2.up(S1, i)                                                                 # 中间断了 500 个
gap = one(g2.out)
check(gap["outages"] == 1 and 490 <= gap["outage_frames"] <= 510, "中间断了约 500 个：记 1 处断档，断档帧数 %d" % gap["outage_frames"])
r1, r2 = base["missing"] / (base["seen"] + base["missing"]), gap["missing"] / (gap["seen"] + gap["missing"])
check(abs(r1 - r2) < 0.01, "丢帧率不被断档冲掉：没断档 %.1f%%，断档后 %.1f%%" % (100 * r1, 100 * r2))

print("== AP 的共用计数器不归任何一个设备 ==")
g = Gen()
for i in range(200):
    g.up(S1, i, prot=1)                                                              # S1 的上行一个都没丢
    if i % 2 == 0:
        g.mgmt(AP, S1 if i % 4 == 0 else S2, i)                                      # AP 的管理帧计数器（给 S1、S2 的探测响应共用，丢了一半）
hb = health.build(g.out, {f.n: {} for f in g.out}, [{"ap": AP, "sta": S1, "state": "verified"}])
check(hb["overall"]["missing"] > 90 and hb["stations"][0]["seq"]["missing"] == 0 and hb["stations"][0]["notes"] == [],
      "AP 的管理帧计数器缺了很多（总计缺口 %d），但 S1 自己的序号一个缺口都没有：不把 AP 的缺口算到 S1 头上" % hb["overall"]["missing"])

print("== 校验和不对的帧不参与 ==")
g = Gen().up(S1, 0).up(S1, 1).up(S1, 3000, fcs_ok=False).up(S1, 2).up(S1, 3, fcs_ok=False)
res = health.sequence(g.out)
c = list(res["counters"].values())[0]
check(res["bad_fcs"] == 2 and (c["seen"], c["missing"], c["outages"], c["frames"]) == (3, 0, 0, 3), "FCS 不通过的 2 个帧只计个数，不进序号统计（否则乱序号会造出断档）")

print("== 设备汇总 ==")
g = Gen()
prot = {}
for i in range(20):
    g.up(S1, i, prot=1)
    g.down(S1, i, prot=1)
for i in range(10):
    g.up(S2, i, prot=1)
g.mgmt(AP, S1, 1).add(0, 8, "ff:ff:ff:ff:ff:ff", AP, AP, 1)                              # 信标：AP 发的，不归设备
dec = {f.n: {} for f in g.out if f.h["type"] == 2 and f.h["qos"] and f.h["addr2"] == S1 and f.n % 2 == 1}      # 解开了 S1 的一部分
hd = health.build(g.out, dec, [{"ap": AP, "sta": S1, "state": "verified"}])
sx = {s["mac"]: s for s in hd["stations"]}
check([s["mac"] for s in hd["stations"]] == [S1, S2] and sx[S1]["protected"] == 40 and sx[S2]["protected"] == 10, "设备按受保护帧数降序：S1 40 个，S2 10 个；AP 不是设备")
check(sx[S1]["decrypted"] == len(dec) and sx[S2]["decrypted"] == 0, "解开的个数按设备统计")
check(sx[S1]["handshake"] == "verified" and sx[S2]["handshake"] == "no_handshake", "握手状态：S1 verified（pairs 里有）；pairs 里没有的设备 no_handshake")
check(any("重连" in n for n in sx[S2]["notes"]) and not any("重连" in n for n in sx[S1]["notes"]), "没有握手的设备给出「让它断开重连」；握手好的不给")
check(any("握手验证通过" in n and "没解开" in n for n in sx[S1]["notes"]), "握手好但仍有帧没解开：说明握手之前的帧解不开属正常")
hd0 = health.build(g.out, {f.n: {} for f in g.out}, [])
check(all(not s["notes"] for s in hd0["stations"]), "全部解开、没有丢帧：没有任何提示")
hm = health.build(g.out, dec, [{"ap": AP, "sta": S1, "state": "mic_mismatch"}])
check(any("口令" in n for n in {s["mac"]: s for s in hm["stations"]}[S1]["notes"]), "握手 MIC 对不上：提示核对口令和 SSID")
check(health.handshake_state(S1, [{"sta": S1, "state": "mic_mismatch"}, {"sta": S1, "state": "verified"}]) == "verified"
      and health.handshake_state(S1, [{"sta": S1, "state": "only_m1"}, {"sta": S1, "state": "mic_mismatch"}]) == "only_m1", "同一设备有多对握手：有一对 verified 就是 verified，否则取第一对")
check(health.build(g.out, dec)["stations"][0]["handshake"] is None, "没给握手信息时，握手状态是 None，不乱说")

print("== 丢帧率高、重传多、有断档时的提示 ==")
g = Gen()
sn = 0
rng = random.Random(11)
for i in range(1000):
    sn += 1
    if rng.random() < 0.3:
        continue
    g.up(S1, sn % 4096, prot=1, retry=int(rng.random() < 0.5))
hb = health.build(g.out, {f.n: {} for f in g.out}, [{"ap": AP, "sta": S1, "state": "verified"}])
notes = hb["stations"][0]["notes"]
check(any("丢帧估计" in n and "实测" in n for n in notes) and any("重传" in n for n in notes), "丢帧约 30%、重传约一半：提醒丢帧（措辞是「可能的原因，要实测」）和重传")
g = Gen().up(S1, 0, prot=1).up(S1, 500, prot=1)
hb = health.build(g.out, {f.n: {} for f in g.out}, [{"ap": AP, "sta": S1, "state": "verified"}])
check(any("断档" in n for n in hb["stations"][0]["notes"]), "有断档：提示")
check(health.build([], {}, [])["overall"]["loss"] is None, "没有帧：丢帧率是 None，不除以零")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
