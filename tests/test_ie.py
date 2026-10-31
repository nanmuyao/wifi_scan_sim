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

print("== 元素内容 ==")
check(ie.decode_ssid(b"") == {"ssid": b""} and ie.decode_ssid(b"x" * 33) is None, "SSID：空（隐藏）可以，超过 32 字节不合规")
check(ie.decode_ssid(bytes(range(0x80, 0xa0)))["ssid"] == bytes(range(0x80, 0xa0)), "SSID 是字节串，不要求 UTF-8")
r = ie.decode_rates(bytes([0x82, 0x84, 0x0b, 0x16, 0xff]))
check(r["rates"] == [0x82, 0x84, 0x0b, 0x16, 0xff] and r["mbps"] == [1.0, 2.0, 5.5, 11.0, 63.5] and r["basic"] == [True, True, False, False, True],
      "速率：原字节、Mbps（低 7 位 / 2）、基本速率位（最高位）")
check(ie.decode_ds(b"\x0b") == {"channel": 11} and ie.decode_ds(b"") is None, "DS：信道；空数据不合规")
t = ie.decode_tim(bytes([1, 3, 0x05, 0xAA, 0xBB]))
check(t == {"dtim_count": 1, "dtim_period": 3, "multicast": True, "offset": 2, "bitmap": b"\xaa\xbb"}, "TIM：位图控制 bit0 = 组播，bit1-7 = 偏移（0x05 -> 偏移 2）")
check(ie.decode_tim(bytes([0, 1, 0])) is None, "TIM：不足 4 字节不合规")
check(ie.decode_tim(bytes([0, 1, 0xFE, 0]))["offset"] == 127 and not ie.decode_tim(bytes([0, 1, 0xFE, 0]))["multicast"], "TIM：偏移是高 7 位的数值（最大 127），bit0 为 0 时无组播")
c = ie.decode_country(b"US \x01\x0b\x1e\x24\x04\x17")
check(c["code"] == "US" and c["environment"] == 0x20 and c["triplets"] == [
    {"first_channel": 1, "num_channels": 11, "max_power": 30}, {"first_channel": 36, "num_channels": 4, "max_power": 23}], "国家：两个信道三元组")
c = ie.decode_country(b"DEO" + bytes([201, 13, 4]) + bytes([36, 4, 23]) + b"\x00")
check(c["environment"] == ord("O") and c["triplets"] == [
    {"operating_ext": 201, "operating_class": 13, "coverage_class": 4}, {"first_channel": 36, "num_channels": 4, "max_power": 23}],
    "国家：运行类别三元组（首字节 >= 201），末尾 1 字节填充被忽略")
check(ie.decode_country(b"JP " + bytes([1, 13, 0xf6]))["triplets"][0]["max_power"] == -10, "国家：最大功率是有符号数")
check(ie.decode_country(b"US \x01\x0b") is None, "国家：不足 6 字节不合规")
check(ie.decode_erp(b"\x05") == {"value": 5, "non_erp_present": True, "use_protection": False, "barker_preamble": True}, "ERP：三个位")
check(ie.decode_erp(b"") is None, "ERP：空数据不合规")

print("== decode_all ==")
els, _ = ie.walk(b"\x00\x01a\x00\x01b\x03\x01\x06\x05\x01\x00\xff\x02\x23\x00")
d = ie.decode_all(els)
check(d["ssid"] == {"ssid": b"a"} and d["ds"] == {"channel": 6}, "同一种元素只取第一次出现的")
check("tim" not in d, "数据不合规的元素不出现在结果里")
check(set(d) == {"ssid", "ds"}, "扩展元素（ID 255）不按普通元素 ID 解码")

print("== 固定部分长度表 ==")
check(ie.FIXED_LEN == {0: 4, 1: 6, 2: 10, 3: 6, 4: 0, 5: 12, 8: 12, 10: 2, 11: 6, 12: 2}, "各管理帧子类型（已由合成帧对照 tshark）")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
