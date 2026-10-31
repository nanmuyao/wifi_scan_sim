#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""快速切换元素（FTE，55）对照 tshark：24 个样例里所有带 FTE 的管理帧，逐字段对：MIC Control、元素个数、MIC、ANonce、SNonce、R1KH-ID、R0KH-ID。
我们还要求 decode_ft 能把整个元素解完（子元素恰好用尽数据）——这本身就是对 MIC 长度编码的检验。
tshark 4.4 对 24 字节 MIC 的重（关联）请求只显示 16 字节，所以 MIC 按「tshark 的是我们的前缀」比。
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_samples  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import ie  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def hx(s):
    return bytes.fromhex(s.replace(":", "")) if s else None


FIELDS = ["frame.number", "wlan.ft.mic_control", "wlan.ft.mic_control.element_count", "wlan.ft.mic", "wlan.ft.anonce", "wlan.ft.snonce",
          "wlan.ft.subelem.r1kh_id", "wlan.ft.subelem.r0kh_id"]
fetch_samples.fetch()
# tshark 4.4 不认 24 字节 MIC 的 FTE（MIC Length 编码 1）：只显示 16 字节，后面的字段错位，R1KH-ID / R0KH-ID 读不出来。
# 我们的解码用尽了全部子元素（子元素长度恰好吻合），所以以我们的为准；差异固定成下面的列表。
KNOWN_GAPS = {"wpa3-ft-sae-ext-key-group20.pcapng.gz": [(21, "snonce"), (21, "r0kh_id"), (22, "anonce"), (22, "snonce"), (22, "r1kh_id"), (22, "r0kh_id"),
                                                        (23, "anonce"), (23, "snonce"), (23, "r1kh_id"), (23, "r0kh_id"), (24, "anonce"), (24, "snonce"), (24, "r1kh_id"), (24, "r0kh_id")]}
total = 0
for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    cmd = ["tshark", "-r", path, "-Y", "wlan.tag.number == 55 && wlan.fc.type == 0", "-T", "fields"]
    for f in FIELDS:
        cmd += ["-e", f]
    rows = {int(l.split("\t")[0]): (l.split("\t") + [""] * 8)[:8] for l in subprocess.run(cmd, capture_output=True, text=True).stdout.split("\n") if l}
    mine, bad = {}, 0
    for f in fr.iter_frames(path):
        h = f.h
        if h["type"] != 0 or h["subtype"] not in ie.FIXED_LEN or h["protected"]:
            continue
        els, _ = ie.walk(f.body[ie.FIXED_LEN[h["subtype"]]:])
        raw = next((e for e in els if e.id == 55 and e.ext is None), None)
        if raw is None:
            continue
        d = ie.decode_ft(bytes(raw.data))
        if d is None:
            bad += 1
        else:
            mine[f.n] = d
    ok = sorted(mine) == sorted(rows) and bad == 0
    diffs = []
    for n, d in mine.items():
        r = rows.get(n)
        if r is None:
            continue
        _, mc, cnt, mic, an, sn, r1, r0 = r
        for field, same in (("mic_control", int(mc, 16) == d["mic_control"]), ("element_count", int(cnt) == d["element_count"]),
                            ("mic", d["mic"].startswith(hx(mic))), ("anonce", hx(an) == d["anonce"]), ("snonce", hx(sn) == d["snonce"]),
                            ("r1kh_id", hx(r1.split(",")[0]) == d["r1kh_id"]), ("r0kh_id", hx(r0.split(",")[0]) == d["r0kh_id"])):
            if not same:
                diffs.append((n, field))
    total += len(mine)
    if mine or rows:
        want = KNOWN_GAPS.get(name, [])
        check(ok and diffs == want, "%s：FTE %d 帧（tshark %d 帧），全部解完；与 tshark 不同的字段 %s（表里 %s）" % (name, len(mine), len(rows), diffs, want))
check(total == 16, "共 %d 个带 FTE 的管理帧" % total)
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
