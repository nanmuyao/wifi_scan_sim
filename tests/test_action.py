#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""action.decode_action：手算字节（含样例里的真实字节）。类别名称表由 tests/oracle 对照 tshark，字段由合成帧对照 tshark。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import action  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


print("== 类别与错误响应 ==")
a = action.decode_action(bytes([3, 0, 0xAA]))
check((a["category"], a["category_name"], a["error_response"], a["code"], a["payload"]) == (3, "Block Ack", False, 0, b"\xaa"), "类别 3 = Block Ack，动作码 0，内容是动作码之后的字节")
a = action.decode_action(bytes([0x83, 1]))
check((a["category"], a["category_raw"], a["error_response"], a["category_name"]) == (3, 0x83, True, "Block Ack"), "0x83：最高位是错误响应标志，类别仍是 3")
check(action.decode_action(bytes([0x7f, 0]))["error_response"] is False and action.decode_action(bytes([0x7f, 0]))["category"] == 127, "0x7f = 127 厂商专用，不是错误响应")
check(action.decode_action(bytes([0xff, 0]))["category"] == 127 and action.decode_action(bytes([0xff, 0]))["error_response"], "0xff = 厂商专用的错误响应")
a = action.decode_action(bytes([99, 5]))
check(a["category_name"] is None and a["category"] == 99 and a["details"] is None, "不认识的类别：名字 None，不解内容")
check(action.decode_action(b"\x03") is None and action.decode_action(b"") is None, "不足 2 字节：None")
check(action.decode_action(bytes([4, 4]))["payload"] == b"" and action.decode_action(bytes([4, 4]))["details"] is None, "只有类别和动作码：内容为空")

print("== Block Ack：ADDBA 请求 ==")
raw = bytes.fromhex("03 00 01 03 10 00 00 10 00".replace(" ", ""))        # 样例里的真实 ADDBA 请求
a = action.decode_action(raw)
d = a["details"]
check(d["dialog_token"] == 1 and d["params"]["value"] == 0x1003 and d["timeout"] == 0 and d["ssc"] == 0x0010, "对话令牌 1、参数 0x1003、超时 0、起始序列控制 0x0010（样例真实字节）")
check(d["params"] == {"value": 0x1003, "amsdu": True, "immediate": True, "tid": 0, "buffers": 64}, "参数 0x1003：允许 A-MSDU、立即块确认、TID 0、64 个缓冲区")
check((d["fragment"], d["start_seq"]) == (0, 1), "起始序列控制 0x0010：分片 0、起始序号 1")
d = action.decode_action(bytes([3, 0, 9]) + struct.pack("<H", 0 | 0 << 1 | 5 << 2 | 1023 << 6) + struct.pack("<HH", 0xffff, 4095 << 4 | 3))["details"]
check(d["params"]["amsdu"] is False and d["params"]["immediate"] is False and d["params"]["tid"] == 5 and d["params"]["buffers"] == 1023, "延迟块确认、TID 5、1023 个缓冲区（10 位）")
check(d["timeout"] == 0xffff and d["fragment"] == 3 and d["start_seq"] == 4095, "超时 16 位；序号 12 位 4095；分片 3")
check(action.decode_action(bytes([3, 0, 9]) + struct.pack("<HHH", 1 << 2 | 1 << 1, 0, 0))["details"]["params"]["tid"] == 1, "TID 是参数的 bit2-5（0x0006 -> TID 1，bit1 是策略）")
check(action.decode_action(raw[:8])["details"] is None and action.decode_action(raw)["details"] is not None, "ADDBA 请求最少 9 字节（含类别和动作码）；少 1 字节：None")

print("== Block Ack：ADDBA 响应 ==")
raw = bytes([3, 1, 1]) + struct.pack("<HHH", 0, 0x1002, 0)
d = action.decode_action(raw)["details"]
check((d["dialog_token"], d["status"], d["params"]["value"], d["params"]["amsdu"], d["params"]["immediate"], d["params"]["buffers"], d["timeout"]) == (1, 0, 0x1002, False, True, 64, 0),
      "响应：令牌 1、状态 0、参数 0x1002（不允许 A-MSDU、立即、64 个缓冲区）（样例真实字节）")
d = action.decode_action(bytes([3, 1, 2]) + struct.pack("<HHH", 37, 9 << 2 | 1, 7))["details"]
check(d["status"] == 37 and d["params"]["tid"] == 9 and d["params"]["amsdu"] and d["timeout"] == 7, "状态码在参数之前（先 2 字节状态，再 2 字节参数）")
check(action.decode_action(raw[:8])["details"] is None, "ADDBA 响应最少 9 字节；少 1 字节：None")

print("== Block Ack：DELBA ==")
d = action.decode_action(bytes.fromhex("0302000825 00".replace(" ", "")))["details"]
check(d == {"params": 0x0800, "initiator": True, "tid": 0, "reason": 0x25}, "DELBA 样例真实字节：发起方、TID 0、原因 37")
d = action.decode_action(bytes([3, 2]) + struct.pack("<HH", 0xF000, 0xffff))["details"]
check(d["initiator"] is False and d["tid"] == 15 and d["reason"] == 0xffff, "TID 是参数的高 4 位（bit12-15）；bit11 才是发起方")
d = action.decode_action(bytes([3, 2]) + struct.pack("<HH", 0x0800 | 7 << 12, 1))["details"]
check(d["initiator"] and d["tid"] == 7, "发起方 + TID 7")
check(action.decode_action(bytes([3, 2, 0, 8, 1]))["details"] is None and action.decode_action(bytes([3, 2, 0, 8, 1, 0]))["details"] is not None, "DELBA 最少 6 字节；少 1 字节：None")
check(action.decode_action(bytes([3, 9, 1, 2, 3, 4, 5, 6, 7]))["details"] is None, "块确认的其它动作码：不解")

print("== High Throughput ==")
d = action.decode_action(bytes([7, 1, 0]))["details"]
check(d == {"control": 0, "sm_enabled": False, "sm_dynamic": False}, "SM 省电 控制 0x00（样例真实字节）：关闭、静态")
for ctl, en, dyn in ((1, True, False), (2, False, True), (3, True, True)):
    d = action.decode_action(bytes([7, 1, ctl]))["details"]
    check(d["sm_enabled"] is en and d["sm_dynamic"] is dyn, "SM 省电 控制 0x%02x：bit0 开启=%s，bit1 动态=%s" % (ctl, en, dyn))
check(action.decode_action(bytes([7, 0, 1]))["details"] == {"channel_width": 1}, "通知信道宽度：1 = 任意宽度")
check(action.decode_action(bytes([7, 0]))["details"] is None and action.decode_action(bytes([7, 1]))["details"] is None, "HT 动作缺 1 字节内容：None")
check(action.decode_action(bytes([7, 2, 1, 2]))["details"] is None, "HT 的其它动作码（PSMP 等）：不解")
check(action.decode_action(bytes([0x87, 1, 3]))["details"] == {"control": 3, "sm_enabled": True, "sm_dynamic": True} and action.decode_action(bytes([0x87, 1, 3]))["error_response"], "错误响应位不影响按类别解码")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
