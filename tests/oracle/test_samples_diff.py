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
# 已知缺口：字段 -> (不一致帧数, 没解析帧数)，24 个样例合计，必须精确相等（变好、变坏都要改这张表）。
# 其余字段一律要求 0 / 0。
KNOWN_GAPS = {
    # 数据帧里的 EAPOL-Key：tshark 会读 Key Data 里的 RSN 元素（阶段 D）
    # 4 帧 Multi-Link 元素里嵌套的子元素：tshark 展开了，我们不展开（阶段 C，解码 Multi-Link）
    "tags": (2, 43),
    # 8 帧 SAE 认证：帧体不是元素序列，要按曲线组的长度跳过 scalar / element（阶段 E）；另有 2 帧同上的 Multi-Link
    "ext_tags": (2, 8),
    # 同样是那几帧 Multi-Link：嵌套的子元素里还有速率元素，tshark 把它们的速率并进同一个列表
    "rates": (2, 0),
    "ext_rates": (2, 0),
    # 6 帧 SAE 认证里的扩展元素 114（AKM Suite Selector），tshark 也按 RSN 的 AKM 列出来（阶段 E）
    "rsn_akm": (0, 6),
    # 一帧 Multi-Link 里嵌套的子元素带了厂商元素（WMM），tshark 一并列出
    "vendor_oui": (1, 0),
    "wfa_type": (1, 0),
}
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
gaps = {}
for name in sorted(os.listdir(d)):
    r = diff.diff_file(os.path.join(d, name))
    if r["error"]:
        check(False, "%s：无法读取 %s" % (name, r["error"]))
        continue
    compared += r["stats"]["type_subtype"]["ok"]
    for field, v in r["stats"].items():
        g = gaps.setdefault(field, [0, 0])
        g[0] += v["diff"]
        g[1] += v["missing"]
    bad = sum(v["diff"] + v["missing"] for f_, v in r["stats"].items() if f_ not in KNOWN_GAPS)
    check(r["frames"] == r["ours_frames"] and bad == 0,
          "%s：%d 帧，已知缺口之外不一致/没解析共 %d%s" % (name, r["frames"], bad,
                                         ("，例如 %s" % ([x for x in r["details"] if x[1] not in KNOWN_GAPS][:2],)) if bad else ""))
for field, want in KNOWN_GAPS.items():
    check(tuple(gaps.get(field, (0, 0))) == want, "已知缺口 %s：不一致/没解析 = %s（表里写的 %s；不等就更新这张表或修缺口）" % (field, tuple(gaps.get(field, (0, 0))), want))
check(compared >= MIN_COMPARED_TYPE_SUBTYPE, "类型字段共对比 %d 帧（下限 %d）" % (compared, MIN_COMPARED_TYPE_SUBTYPE))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
