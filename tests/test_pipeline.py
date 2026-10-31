#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pipeline80211.decrypt_capture：用 WEP 的合成帧（pycryptodome 的 ARC4 + zlib.crc32 独立加密）测接线：
解出的帧进结果、没有解开的 / 没受保护的不进、A-MSDU 拆成多个 MSDU、how 标签。单播 / 组播 / FT 等路径由真实抓包的 tests/oracle/test_net_diff.py 覆盖。"""
import os
import struct
import sys
import tempfile
import zlib

from Crypto.Cipher import ARC4

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "oracle"))
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import pipeline as pl  # noqa: E402
import synth  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


KEY = bytes.fromhex("1234567890")
A1, A2, A3 = bytes([2, 0, 0, 0, 0, 1]), bytes([2, 0, 0, 0, 0, 2]), bytes([2, 0, 0, 0, 0, 3])
LLC = b"\xaa\xaa\x03\x00\x00\x00\x08\x06"


def wep_body(data, key=KEY, iv=b"\x01\x02\x03"):
    return iv + b"\x00" + ARC4.new(iv + key).encrypt(data + struct.pack("<I", zlib.crc32(data)))


def frame(subtype, body, prot=1, qos=None):
    old = (synth.A1, synth.A2, synth.A3)
    synth.A1, synth.A2, synth.A3 = A1, A2, A3
    try:
        return synth.frame(2, subtype, 1, 0, qos=qos, body=body, prot=prot)
    finally:
        synth.A1, synth.A2, synth.A3 = old


def subframe(da, sa, payload, pad=True):
    sf = da + sa + struct.pack(">H", len(payload)) + payload
    return sf + (bytes((-len(sf)) % 4) if pad else b"")


P1, P2 = LLC + bytes(range(28)), LLC + bytes(range(100, 128))
amsdu_plain = subframe(A3, A2, P1) + subframe(A3, A2, P2, pad=False)
frames_ = [frame(0, wep_body(P1)),                                           # 1 非 QoS WEP
           frame(8, wep_body(P1), qos=0x0000),                              # 2 QoS WEP
           frame(8, wep_body(amsdu_plain), qos=0x0080),                     # 3 QoS WEP，A-MSDU 位置位：两个子帧
           frame(0, wep_body(P1, key=bytes(5))),                            # 4 密钥不对：解不开
           frame(0, P1, prot=0),                                            # 5 没受保护：不在结果里
           frame(0, wep_body(P2, iv=b"\x09\x08\x07"))]                      # 6 另一个 IV
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "t.pcap")
    synth.write_pcap(path, frames_)
    fl = list(fr.iter_frames(path))
res = pl.decrypt_capture(fl, [("wep", KEY.hex())])
check(sorted(res) == [1, 2, 3, 6], "解开的是 1、2、3、6；密钥不对的 4 和没受保护的 5 不在结果里：%s" % sorted(res))
check(res[1] == {"how": "wep", "msdus": [P1]} and res[6]["msdus"] == [P2], "WEP：how 标签，MSDU 就是明文")
check(res[2]["msdus"] == [P1], "QoS 但 A-MSDU 位没置：整个帧体是一个 MSDU")
check(res[3]["msdus"] == [P1, P2] and res[3]["how"] == "wep", "A-MSDU 位置位：拆成两个子帧，每个 MSDU 是子帧负载（不含 14 字节子帧头和填充）")
check(pl.decrypt_capture(fl, []) == {}, "没有密钥：什么都解不开")
check(sorted(pl.decrypt_capture(fl, [("wep", bytes(5).hex()), ("wep", KEY.hex())])) == [1, 2, 3, 4, 6], "密钥表有多把 WEP 密钥：逐把试（全 0 的那把正好解开了第 4 帧）")
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
