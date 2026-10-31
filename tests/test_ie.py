#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ie.walk：元素遍历（顺序、重复、扩展元素、被截断）。各子类型的固定部分长度由 tests/oracle 对照 tshark。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ie  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


els, trunc = ie.walk(b"")
check(els == [] and trunc is False, "空")
els, trunc = ie.walk(b"\x00\x04test\x03\x01\x06")
check([(e.id, e.data, e.offset) for e in els] == [(0, b"test", 0), (3, b"\x06", 6)] and trunc is False, "两个元素：ID、数据、偏移")
els, _ = ie.walk(b"\xdd\x02ab\x00\x00\xdd\x01c")
check([(e.id, e.data) for e in els] == [(221, b"ab"), (0, b""), (221, b"c")], "同一 ID 出现多次都保留；长度 0 的元素也保留")
els, _ = ie.walk(b"\xff\x03\x23xy\x30\x00")
check([(e.id, e.ext, e.data) for e in els] == [(255, 0x23, b"xy"), (48, None, b"")], "扩展元素：扩展 ID 取数据第 1 字节，其余是数据")
els, _ = ie.walk(b"\xff\x00")
check([(e.id, e.ext, e.data) for e in els] == [(255, None, b"")], "扩展元素长度 0：没有扩展 ID")

els, trunc = ie.walk(b"\x00\x01a\x30\x14\x01\x00")
check([e.id for e in els] == [0] and trunc is True, "最后一个元素声明的长度超过剩余字节：前面的保留，truncated")
els, trunc = ie.walk(b"\x00\x01a\x30")
check([e.id for e in els] == [0] and trunc is True, "只剩 1 个字节（没有长度）：truncated")
els, trunc = ie.walk(b"\x00\x01a\x30\x00")
check([e.id for e in els] == [0, 48] and trunc is False, "恰好用完：不算 truncated")
els, trunc = ie.walk(b"\x00\x02a")
check(els == [] and trunc is True, "第一个元素就超长")

print("== ids() ==")
els, _ = ie.walk(b"\x00\x00\xff\x01\x6b\x30\x00\xff\x01\x24\x00\x00")
check(ie.ids(els) == ([0, 48, 0], [107, 36]), "普通元素 ID 与扩展 ID 分开，各自保持出现顺序")
els, _ = ie.walk(b"\xff\x00")
check(ie.ids(els) == ([], []), "没有扩展 ID 的扩展元素不计入")

print("== 固定部分长度表 ==")
check(ie.FIXED_LEN == {0: 4, 1: 6, 2: 10, 3: 6, 4: 0, 5: 12, 8: 12, 10: 2, 11: 6, 12: 2}, "各管理帧子类型（已由合成帧对照 tshark）")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
