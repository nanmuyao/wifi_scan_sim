#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Action 帧类别名称表与 tshark 的值表（wlan.fixed.category_code）逐项对照。需要 tshark。

tshark 的表里 128 以上是「类别号 + 0x80」的错误响应写法，名字后面带 (error)；这里的 action.py 把最高位当成独立的「错误响应」标志，
所以只对照 0-127，并检查每个 128 以上的条目都对应一个 0-127 里的类别。
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
import action  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


out = subprocess.run(["tshark", "-G", "values"], capture_output=True, text=True).stdout
oracle = {}
for line in out.split("\n"):
    p = line.split("\t")
    if len(p) >= 4 and p[0] == "V" and p[1] == "wlan.fixed.category_code":
        oracle[int(p[2], 0)] = p[3]

low = {k: v for k, v in oracle.items() if k < 128}
high = {k: v for k, v in oracle.items() if k >= 128}
print("== 类别 0-127 ==")
check(set(action.CATEGORY_NAMES) == set(low), "类别号集合一致（只有我们有: %s；只有 tshark 有: %s）"
      % (sorted(set(action.CATEGORY_NAMES) - set(low)), sorted(set(low) - set(action.CATEGORY_NAMES))))
for k in sorted(set(action.CATEGORY_NAMES) & set(low)):
    check(action.CATEGORY_NAMES[k] == low[k], "%d %s（tshark: %s）" % (k, action.CATEGORY_NAMES[k], low[k]))
print("== 错误响应（类别号 + 0x80）==")
check(len(high) > 0 and all(re.sub(r"[^a-z0-9]", "", v.lower().replace("(error)", "")) and (k - 128) in low for k, v in high.items()),
      "tshark 的 128 以上条目（%d 个）都是某个 0-127 类别加上最高位" % len(high))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
