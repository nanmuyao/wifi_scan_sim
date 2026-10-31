#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""parse_mac_header / parse_frame_control：用合成的帧头逐位检查，补公开样例覆盖不到的取值（例如分片号 8-15）。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import wifi_frame_parser as w  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def hdr(fc, duration=0, seqctl=0):
    return struct.pack("<HH", fc, duration) + bytes.fromhex("0102030405 06".replace(" ", "")) \
        + bytes.fromhex("a1a2a3a4a5a6") + bytes.fromhex("b1b2b3b4b5b6") + struct.pack("<H", seqctl)


print("== 序列控制：序号 12 位，分片号 4 位 ==")
h = w.parse_mac_header(hdr(0x0008, seqctl=(4095 << 4) | 15))
check((h["seq_num"], h["frag_num"]) == (4095, 15), "序号 4095、分片号 15")
h = w.parse_mac_header(hdr(0x0008, seqctl=(1 << 4) | 8))
check((h["seq_num"], h["frag_num"]) == (1, 8), "序号 1、分片号 8（只有第 4 位）")

print("== Frame Control 的每一位 ==")
BITS = [("to_ds", 8), ("from_ds", 9), ("more_frag", 10), ("retry", 11),
        ("pwr_mgmt", 12), ("more_data", 13), ("protected", 14), ("order", 15)]
for name, bit in BITS:
    f = w.parse_frame_control(0x0008 | (1 << bit))
    others = [k for k, _ in BITS if k != name and f[k]]
    check(f[name] == 1 and not others, "第 %d 位只置 %s" % (bit, name))
f = w.parse_frame_control((13 << 4) | (2 << 2) | 1)
check((f["version"], f["type"], f["subtype"]) == (1, 2, 13), "version/type/subtype 的位置")

print("== 其余字段 ==")
h = w.parse_mac_header(hdr(0x0008, duration=0xFFFF))
check(h["duration"] == 0xFFFF, "duration 取满 16 位")
check((h["addr1"], h["addr2"], h["addr3"]) == ("01:02:03:04:05:06", "a1:a2:a3:a4:a5:a6", "b1:b2:b3:b4:b5:b6"),
      "三个地址的位置和格式")
try:
    w.parse_mac_header(b"\x00" * 23)
    check(False, "不足 24 字节应当报错")
except ValueError:
    check(True, "不足 24 字节：ValueError")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
