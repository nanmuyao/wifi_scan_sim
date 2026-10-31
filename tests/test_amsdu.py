#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""amsdu.parse：子帧头、4 字节填充、截断。子帧个数、地址、长度另由合成帧对照 tshark（tests/oracle）。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import amsdu  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


A, B, C = bytes.fromhex("020000000001"), bytes.fromhex("020000000002"), bytes.fromhex("020000000003")


def sub(da, sa, payload, pad=True):
    s = da + sa + struct.pack(">H", len(payload)) + payload
    return s + (b"\x00" * (-len(s) % 4) if pad else b"")


print("== 子帧 ==")
r = amsdu.parse(b"")
check(r == {"subframes": [], "truncated": False}, "空")
r = amsdu.parse(sub(A, B, b"hello", pad=False))
check(r["subframes"] == [{"da": "02:00:00:00:00:01", "sa": "02:00:00:00:00:02", "length": 5, "payload": b"hello", "truncated": False}] and not r["truncated"],
      "一个子帧：目的地址、源地址、长度（大端）、数据")
check(amsdu.parse(A + B + b"\x01\x00" + b"x" * 256)["subframes"][0]["length"] == 256, "长度字段是大端（01 00 = 256），不是小端")
check(amsdu.parse(A + B + b"\x00\x05" + b"hello")["subframes"][0]["length"] == 5, "00 05 = 5")

print("== 填充 ==")
for n in range(1, 9):
    body = sub(A, B, b"p" * n) + sub(B, C, b"q" * 3, pad=False)
    r = amsdu.parse(body)
    check([s["length"] for s in r["subframes"]] == [n, 3] and r["subframes"][1]["payload"] == b"qqq",
          "第一个子帧数据 %d 字节（14 + %d = %d，填充 %d）：第二个子帧起点正确" % (n, n, 14 + n, (-(14 + n)) % 4))
r = amsdu.parse(sub(A, B, b"abc") + sub(B, A, b"de"))
check([s["length"] for s in r["subframes"]] == [3, 2] and not r["truncated"], "最后一个子帧后面也有填充：不算错")
r = amsdu.parse(sub(A, B, b"abcd", pad=True) + sub(B, A, b"x", pad=False))
check([s["length"] for s in r["subframes"]] == [4, 1], "14 + 4 = 18：填充 2 字节")
r = amsdu.parse(sub(A, B, b"a" * 2, pad=True) + sub(B, C, b"b" * 4, pad=True) + sub(C, A, b"c" * 6, pad=False))
check([s["length"] for s in r["subframes"]] == [2, 4, 6], "14 + 2 = 16 已对齐：不补填充")

print("== 截断 ==")
body = sub(A, B, b"abc") + sub(B, A, b"defghij", pad=False)
r = amsdu.parse(body[:-3])
check(len(r["subframes"]) == 2 and r["truncated"] and r["subframes"][1]["truncated"] and not r["subframes"][0]["truncated"], "头部完整、数据被截断的子帧仍然列出，标 truncated（和 tshark 一样）")
check(r["subframes"][1]["length"] == 7 and r["subframes"][1]["payload"] == b"defg", "length 是声明的值（7），payload 是剩下的 4 字节")
r = amsdu.parse(body[:len(sub(A, B, b"abc")) + 13])
check(len(r["subframes"]) == 1 and r["truncated"], "第二个子帧头只有 13 字节：不列出，整体 truncated")
r = amsdu.parse(sub(A, B, b"abc") + b"\x00\x00")
check(len(r["subframes"]) == 1 and not r["truncated"], "尾巴不足 14 字节但全是 0（填充）：不算问题")
r = amsdu.parse(sub(A, B, b"abc") + b"\x00\x01")
check(len(r["subframes"]) == 1 and r["truncated"], "尾巴不足 14 字节且不全是 0：truncated")
r = amsdu.parse(b"\x01" * 5)
check(r["subframes"] == [] and r["truncated"], "不足一个子帧头：没有子帧，truncated")

print("== 长度 0 的子帧（与 tshark 不同：我们继续往下读）==")
r = amsdu.parse(sub(A, B, b"") + sub(B, A, b"z", pad=False))
check([s["length"] for s in r["subframes"]] == [0, 1] and [s["payload"] for s in r["subframes"]] == [b"", b"z"], "长度 0 的子帧算一个子帧，后面的照常读")
check(amsdu.parse(sub(A, B, b"") + sub(B, A, b"z", pad=False))["subframes"][0]["truncated"] is False, "长度 0 不是截断")

print("== 子帧头正好占满剩余字节 ==")
r = amsdu.parse(A + B + b"\x00\x00")
check(len(r["subframes"]) == 1 and r["subframes"][0]["length"] == 0 and not r["truncated"], "只有 14 字节的头、长度 0：一个空子帧，不是截断")
r = amsdu.parse(A + B + b"\x00\x05")
check(len(r["subframes"]) == 1 and r["subframes"][0]["truncated"] and r["subframes"][0]["payload"] == b"" and r["truncated"], "只有 14 字节的头、声明长度 5：子帧列出，数据为空，截断")
r = amsdu.parse(sub(A, B, b"abcd") + A + B + b"\x00\x00")
check([s["length"] for s in r["subframes"]] == [4, 0], "最后恰好是一个只有头的子帧")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
