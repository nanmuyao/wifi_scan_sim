#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""24 个公开样例：本项目的解析结果与 tshark 逐帧一致（diff.py 的字段范围）。需要 tshark 和样例（缺的先下载）。

要求：每个样例都能打开、帧数相同、所有字段 0 不一致 0 漏解析；对比的字段值总数不能少于下限，
防止“什么都没对比也算通过”。tshark 没给出类型的帧（没有 802.11 层）不参与对比。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import diff  # noqa: E402
import fetch_samples  # noqa: E402

MIN_COMPARED_TYPE_SUBTYPE = 6400      # 实测 6461
failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


try:
    fetch_samples.fetch()
except Exception as exc:
    print("样例准备失败: %s" % exc)
    sys.exit(1)

d = fetch_samples.SAMPLE_DIR
compared = 0
for name in sorted(os.listdir(d)):
    r = diff.diff_file(os.path.join(d, name))
    if r["error"]:
        check(False, "%s：无法读取 %s" % (name, r["error"]))
        continue
    bad = sum(v["diff"] + v["missing"] for v in r["stats"].values())
    compared += r["stats"]["type_subtype"]["ok"]
    check(r["frames"] == r["ours_frames"] and bad == 0,
          "%s：%d 帧，不一致/没解析共 %d%s" % (name, r["frames"], bad, ("，例如 %s" % (r["details"][:2],)) if bad else ""))
check(compared >= MIN_COMPARED_TYPE_SUBTYPE, "类型字段共对比 %d 帧（下限 %d）" % (compared, MIN_COMPARED_TYPE_SUBTYPE))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
