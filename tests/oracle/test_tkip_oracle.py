#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TKIP 密钥混合对照 tshark：用我们的 tkip_encrypt 加密一批合成帧（TSC 的高 / 低位、TA、TK 各种取值，固定随机种子），
让 tshark 用同一把 TEK（密钥类型 "tk"）解密。tshark 的实现是独立的：它解出和我们加密前相同的明文，才说明两阶段混合都对。
真实样例里的 TSC 都很小（高 32 位的低 16 位以上全 0），高位的混合只有这里覆盖得到。
"""
import os
import random
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wifi80211 import crypto as c  # noqa: E402
import decrypt_oracle as d  # noqa: E402
import synth  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


rnd = random.Random(20261101)
MSDU = b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + bytes(range(40))
CASES = [(0, 0), (1, 0), (0xFF, 0x7F), (0x1234, 0x0000), (0xFFFF, 0x0000), (0, 0x0001), (0, 0xFFFF), (0x40, 0x0000), (0x7F, 0x8000)]
cases = [(lo | (hi << 16)) for lo, hi in [(a, b) for a, b in CASES]]
cases += [(rnd.getrandbits(32) << 16 | rnd.getrandbits(16)) for _ in range(15)]    # 48 位 TSC：高 16 位也有值
cases = [(t & 0xFFFFFFFFFFFF) for t in cases]
cases += [0x0001_0000_0000, 0xFFFF_FFFF_FFFF, 0x8000_0000_0000]

frames, meta = [], []
for i, tsc in enumerate(cases):
    tk = bytes(rnd.getrandbits(8) for _ in range(16))
    ta = bytes([2]) + bytes(rnd.getrandbits(8) for _ in range(5))
    fc = bytes([0x08, 0x41, 0, 0]) + bytes([2, 0, 0, 0, 0, 1]) + ta + bytes([2, 0, 0, 0, 0, 3]) + struct.pack("<H", 0x1000)
    frames.append(fc + c.tkip_encrypt(tk, ta, tsc, 0, MSDU + bytes(12)))     # 后面 12 字节：占位的 Michael MIC（8）+ 凑数，tshark 不校验 Michael 时只看 ICV
    meta.append((tk, tsc))

print("== TKIP 混合：%d 帧，每帧自己的 TEK / TA / TSC ==" % len(frames))
good = 0
with tempfile.TemporaryDirectory() as tmp:
    for i, (tk, tsc) in enumerate(meta):
        path = os.path.join(tmp, "t%d.pcap" % i)
        synth.write_pcap(path, [frames[i]])
        got = d.tshark_plain(path, [("tk", tk.hex())])
        ok = 1 in got and got[1]["method"] == "TKIP" and got[1]["plain"].startswith(MSDU)
        good += ok
        if not ok:
            check(False, "TSC %#014x：tshark 没有解出我们加密的明文" % tsc)
check(good == len(frames), "tshark 解出了全部 %d 帧（TSC 高低位、TSC1 = 0x40 / 0x7F / 0x80 以上、TA、TK 各不相同）" % len(frames))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
