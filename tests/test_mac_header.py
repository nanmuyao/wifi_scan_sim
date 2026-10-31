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
print("== 变长帧头（用 synth 里的构造器）==")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "oracle"))
import synth  # noqa: E402

h = w.parse_mac_header(synth.frame(2, 8, 1, 0, qos=synth.qos_word(tid=12)))
check(h["qos"]["tid"] == 12, "QoS TID 取 4 位（12），不是 3 位")
for name, fr, hlen in (("Data 3 地址", synth.frame(2, 0, 1, 0), 24),
                       ("Data 4 地址", synth.frame(2, 0, 1, 1), 30),
                       ("QoS Data", synth.frame(2, 8, 1, 0, qos=0), 26),
                       ("QoS Data 4 地址", synth.frame(2, 8, 1, 1, qos=0), 32),
                       ("QoS Data + HT Control", synth.frame(2, 8, 1, 0, order=1, qos=0, htc=1), 30),
                       ("QoS Data 4 地址 + HT Control", synth.frame(2, 8, 1, 1, order=1, qos=0, htc=1), 36),
                       ("Data，Order 位但不是 HT Control", synth.frame(2, 0, 1, 0, order=1), 24),
                       ("管理帧 + HT Control", synth.frame(0, 14, order=1, htc=1), 28),
                       ("管理帧没有 addr4（即使 ToDS=FromDS=1）", synth.frame(0, 8, 1, 1), 24)):
    check(w.parse_mac_header(fr)["header_len"] == hlen, "%s：头长 %d" % (name, hlen))
for name, fr in (("4 地址帧少 1 字节", synth.frame(2, 0, 1, 1, body=b"")[:-1]),
                 ("QoS 帧只有基本头", synth.frame(2, 8, 1, 0, qos=0, body=b"")[:24]),
                 ("HT Control 不完整", synth.frame(0, 14, order=1, htc=1, body=b"")[:-2])):
    try:
        w.parse_mac_header(fr)
        check(False, name + "：应当报错")
    except ValueError:
        check(True, name + "：ValueError")

try:
    w.parse_mac_header(b"\x00" * 23)
    check(False, "不足 24 字节应当报错")
except ValueError:
    check(True, "不足 24 字节：ValueError")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
