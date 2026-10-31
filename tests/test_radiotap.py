#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""radiotap.parse：手算字节的单元测试（对齐、多位图、多天线、厂商命名空间、出错）。真实头由 tests/oracle 对照 tshark。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import radiotap  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def hdr(length, *words):
    return struct.pack("<BBH", 0, 0, length) + b"".join(struct.pack("<I", w) for w in words)


print("== 单个位图 ==")
# 与 wep 样例同款：TSFT flags rate channel antsignal antenna rxflags，总长 26
raw = (hdr(26, 0x482f) + struct.pack("<Q", 1234567890123) + b"\x10\x0c" + struct.pack("<HH", 2437, 0x00a0)
       + b"\xce\x00" + struct.pack("<H", 0x0000))
r = radiotap.parse(raw + b"DOT11")
check(r["length"] == 26 and raw[26 - 1:26] == b"\x00", "总长 26")
check((r["tsft"], r["flags"], r["rate"], r["antsignal"], r["antenna"], r["rx_flags"]) == (1234567890123, 0x10, 12, -50, 0, 0),
      "TSFT / flags / rate(12=6Mbps) / 信号 -50 / 天线 0 / rx_flags")
check(r["channel"] == {"freq": 2437, "flags": 0x00a0}, "信道 2437 MHz、标志 0x00a0")
check(r["fcs_included"] is True, "flags 的 0x10 位 = 帧末尾带 FCS")

print("== 对齐（从 radiotap 头起点算）==")
r = radiotap.parse(hdr(14, 0x0000000a) + b"\x10" + b"\x00" + struct.pack("<HH", 5180, 0x0140))
check(r["flags"] == 0x10 and r["channel"] == {"freq": 5180, "flags": 0x0140}, "flags 后补 1 字节，channel 对齐到 2")
r = radiotap.parse(hdr(20, 0x00100002) + b"\x00" + b"\x00" * 3 + struct.pack("<IHBB", 0xdeadbeef, 0x0003, 0x2a, 0))
check(r["ampdu"]["reference"] == 0xdeadbeef and r["ampdu"]["delimiter_crc"] == 0x2a, "A-MPDU 对齐到 4")
r = radiotap.parse(hdr(28, 0x00400002) + b"\x00" + b"\x00" * 7 + struct.pack("<QHBB", 77, 1, 2, 3))
check(r["timestamp"]["ts"] == 77 and r["timestamp"]["unit_position"] == 2, "timestamp 对齐到 8")
r = radiotap.parse(hdr(8, 0))
check(r["length"] == 8 and r["fcs_included"] is False, "没有任何字段")

print("== 多个位图 ==")
# 两个天线：位图 1 带 bit29（下一个位图仍是 radiotap 命名空间）和 bit31（后面还有位图）
raw = hdr(16, 0xA0000020 | 0x800, 0x20 | 0x800) + b"\xd0\x00" + b"\xcc\x01"
r = radiotap.parse(raw)
check(r["antsignal"] == -48 and r["antsignal_all"] == [-48, -52], "两个天线的信号：第一个 + 全部列表")
check(r["antenna"] == 0 and r["antenna_all"] == [0, 1], "两个天线编号")
# 厂商命名空间：位图 1 = flags + 下一个是厂商命名空间 + 后面还有；位图 2 = 厂商的；位图 3 = radiotap（信号）
# 数据：flags(16) 补 1 字节，厂商头 6 字节（OUI 3 + 子命名空间 1 + 数据长度 2）+ 3 字节厂商数据，再是信号(27)，总长 28
raw = (hdr(28, 0xC0000002, 0xA0000001, 0x00000020) + b"\x10\x00" + b"\x01\x02\x03\x00" + struct.pack("<H", 3)
       + b"xyz" + b"\xce")
r = radiotap.parse(raw)
check(r["flags"] == 0x10 and r["antsignal"] == -50, "跳过厂商命名空间（6 字节头 + 声明的 3 字节数据）后，下一个 radiotap 位图的字段位置正确")
r = radiotap.parse(hdr(13, 0x80000002, 0x00000001) + b"\x10")
check(r["flags"] == 0x10 and r["stopped_at"] == "bit32", "命名空间内第 2 个 32 位（位 32 起）没有定义：停下并说明")
# TLV（位 28）
raw = hdr(20, 0x10000000 | 0x2) + b"\x10" + b"\x00" * 3 + struct.pack("<HH", 5, 1) + b"\xd8" + b"\x00" * 3
r = radiotap.parse(raw)
check(r["flags"] == 0x10 and r["antsignal"] == -40, "TLV：类型 5（信号）长 1，补齐到 4")

print("== 由 MCS 算速率（802.11n 标准表里的值）==")
K = radiotap.MCS_KNOWN_BW | radiotap.MCS_KNOWN_INDEX | radiotap.MCS_KNOWN_GI
for idx, flags, want in ((0, 0, 6.5), (7, 0, 65.0), (15, 0, 130.0), (31, 0, 260.0),
                         (7, 0x04, 72.2222), (7, 0x01, 135.0), (7, 0x05, 150.0), (15, 0x05, 300.0),
                         (0, 0x01, 13.5), (3, 0, 26.0), (5, 0, 52.0), (4, 0x01, 81.0)):
    got = radiotap.ht_rate_mbps(K, flags, idx)
    check(abs(got - want) < 1e-3, "MCS %d flags 0x%02x -> %.4g Mbps（标准 %.4g）" % (idx, flags, got, want))
check(radiotap.ht_rate_mbps(radiotap.MCS_KNOWN_INDEX, 0x05, 7) == 65.0, "带宽 / 保护间隔「未知」时按 20 MHz、长间隔，不看 flags")
check(radiotap.ht_rate_mbps(radiotap.MCS_KNOWN_BW | radiotap.MCS_KNOWN_GI, 0, 7) is None, "MCS index 未知：None")
check(radiotap.ht_rate_mbps(K, 0, 32) is None, "MCS 32 以上（不是这张表）：None")
check(radiotap.data_rate_mbps({"rate": 11}) == 5.5, "rate 字段 11（500 kbps 为单位）= 5.5 Mbps")
check(radiotap.data_rate_mbps({"rate": 2, "mcs": {"known": K, "flags": 0, "index": 7}}) == 1.0, "有 rate 字段时优先用它")
check(radiotap.data_rate_mbps({"mcs": {"known": K, "flags": 0, "index": 7}}) == 65.0, "没有 rate 字段：由 MCS 算")
check(radiotap.data_rate_mbps({}) is None, "什么都没有：None")

print("== 出错 ==")
for name, raw in (("太短", b"\x00\x00\x08"), ("版本不是 0", struct.pack("<BBHI", 1, 0, 8, 0)),
                  ("长度小于 8", struct.pack("<BBHI", 0, 0, 7, 0) + b"\x00" * 8),
                  ("长度大于整个包", struct.pack("<BBHI", 0, 0, 40, 0)),
                  ("字段超出长度", hdr(10, 0x2 | 0x8) + b"\x00\x00"),
                  ("位图没结束", struct.pack("<BBHI", 0, 0, 8, 0x80000000))):
    try:
        radiotap.parse(raw)
        check(False, name + "：应当报错")
    except ValueError:
        check(True, name + "：ValueError")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
