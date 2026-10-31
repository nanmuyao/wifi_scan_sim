#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""strip_radiotap：头长度取自 offset 2 的小端 16 位，不是固定值。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wifi80211 import parser as w  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def rt(hlen, claimed=None):
    return struct.pack("<BBHI", 0, 0, hlen if claimed is None else claimed, 0) + b"\x00" * (hlen - 8)


DOT11 = b"\x80\x00" + b"\xaa" * 22
check(w.strip_radiotap(rt(8) + DOT11) == DOT11, "头长 8")
check(w.strip_radiotap(rt(36) + DOT11) == DOT11, "头长 36（真实网卡常见）")
check(w.strip_radiotap(rt(300) + DOT11) == DOT11, "头长 300：长度字段超过一个字节也对")
check(w.strip_radiotap(rt(36, claimed=4) + DOT11) == b"", "长度字段小于 8：头不合法，没有可解析的帧")
check(w.strip_radiotap(rt(8, claimed=500)) == b"", "长度字段超过整个包：头不合法")
check(w.strip_radiotap(b"\x00\x00\x08") == b"\x00\x00\x08", "不足 8 字节：原样返回（调用方会判“帧过短”）")
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
