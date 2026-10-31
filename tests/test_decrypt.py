#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""decrypt80211 的 CCMP / GCMP：用 pycryptodome 当独立加密方（AAD 在这里手写一遍，不借用被测代码），
覆盖真实样例里没有的帧形态（非 QoS、四地址、带 HT 控制、各种会被屏蔽的位）。真实帧的对照在 tests/oracle/test_decrypt_diff.py。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import decrypt80211 as dec  # noqa: E402
import wifi_frame_parser as w  # noqa: E402
from aead_build import A1, A2, A3, A4, build, frame  # noqa: E402,F401

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


PLAIN = b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + bytes(range(40))
TK16, TK32 = bytes(range(16)), bytes(range(32))
CASES = [
    ("CCMP-128", TK16, "非 QoS 三地址", dict()),
    ("CCMP-128", TK16, "QoS（TID 5）", dict(qos=0x0005)),
    ("CCMP-128", TK16, "QoS 控制里 TID 以外的位被屏蔽（EOSP / 确认策略 / A-MSDU）", dict(qos=0x00F5 | 0x0100)),
    ("CCMP-128", TK16, "重试 / 省电 / 更多数据位被屏蔽", dict(qos=0x0003, flags=0x38)),
    ("CCMP-128", TK16, "序号被屏蔽、分片号保留", dict(qos=0x0000, seq=0x0FFF, frag=3)),
    ("CCMP-128", TK16, "四地址 QoS", dict(qos=0x0002, four=True)),
    ("CCMP-128", TK16, "带 HT 控制（顺序位）", dict(qos=0x0001, htc=True)),
    ("CCMP-128", TK16, "子类型 10（QoS 数据 + CF-Poll 类，子类型低位被屏蔽）", dict(qos=0x0000, subtype=10)),
    ("CCMP-128", TK16, "密钥序号 1", dict(qos=0x0000, key_id=1)),
    ("CCMP-256", TK32, "CCMP-256（MIC 16 字节）", dict(qos=0x0006)),
    ("GCMP-128", TK16, "GCMP-128", dict(qos=0x0000)),
    ("GCMP-256", TK32, "GCMP-256 四地址", dict(qos=0x0007, four=True)),
]
PN = 0x0000A1B2C3D4E5F6 & 0xFFFFFFFFFFFF
for cipher, tk, what, kw in CASES:
    print("== %s：%s ==" % (cipher, what))
    f = frame(build(cipher, tk, PN, PLAIN, **kw))
    pt, ok, pn = dec.decrypt_aead(tk, cipher, f)
    check(ok and pt == PLAIN and pn == PN, "MIC 通过、明文还原、PN = %#x" % PN)
    check(not dec.decrypt_aead(bytes(len(tk)), cipher, f)[1], "错的密钥 MIC 不通过")

print("== 会改变 AAD / nonce 的位必须让 MIC 失败 ==")
base = build("CCMP-128", TK16, PN, PLAIN, qos=0x0005)
hl = w.parse_mac_header(base)["header_len"]


def mutated(off, xor):
    b = bytearray(base)
    b[off] ^= xor
    return frame(bytes(b))


check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(4, 0x01))[1], "地址 1 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(10, 0x01))[1], "地址 2 变了（nonce 和 AAD）")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(16, 0x01))[1], "地址 3 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(22, 0x01))[1], "分片号变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(24, 0x01))[1], "QoS 的 TID 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(1, 0x04))[1], "更多分片位变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(1, 0x02))[1], "FromDS 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(hl, 0x01))[1], "PN0 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(hl + 7, 0x01))[1], "PN5 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(len(base) - 1, 0x01))[1], "MIC 末字节变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(hl + 9, 0x01))[1], "密文变了")

print("== pn_of ==")
check(dec.pn_of(bytes([1, 2, 0, 0x20, 3, 4, 5, 6])) == (0x060504030201, 0, True), "PN0 PN1 在前、PN2-PN5 在后，ExtIV 位")
check(dec.pn_of(bytes([0, 0, 0, 0xE0, 0, 0, 0, 0]))[1] == 3, "密钥序号取最高 2 位")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
