#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""差分工具自身的测试：比较逻辑（合成数据）和端到端（tshark 对仓库自带的抓包）。需要 tshark，在容器里跑。"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import diff  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def frame(**kw):
    f = {n: None for n, _ in diff.FIELDS}
    f.update(kw)
    return f


print("== compare：一致 / 不一致 / 没解析 / 标准答案没有值 ==")
oracle = [frame(type_subtype=8, ra="a", seq=5), frame(type_subtype=29, ra="b")]
ours = [frame(type_subtype=8, ra="a", seq=6), frame(type_subtype=29, ra=None, seq=9)]
stats, details = diff.compare(oracle, ours)
check(stats["type_subtype"] == {"ok": 2, "diff": 0, "missing": 0}, "类型全部一致")
check(stats["ra"] == {"ok": 1, "diff": 0, "missing": 1}, "我们没解析出 ra 算 missing")
check(stats["seq"] == {"ok": 0, "diff": 1, "missing": 0}, "序号不同算 diff；标准答案没有序号的帧不参与对比")
check(details == [(1, "seq", 5, 6)], "不一致明细带帧号、标准答案、我们的值")
stats, _ = diff.compare([frame(type_subtype=8)] * 2, [frame(type_subtype=8)])
check(stats["type_subtype"] == {"ok": 1, "diff": 0, "missing": 1}, "我们少解析了帧：多出来的算 missing")

print("== 端到端：仓库自带的抓包，tshark 与我们逐帧一致 ==")
check(diff.tshark_version().startswith(diff.TSHARK_MAJOR_MINOR), "tshark 是 %s.x（实际 %s）" % (diff.TSHARK_MAJOR_MINOR, diff.tshark_version()))
for rel in ("tests/fixtures/wpa2_handshake.pcap", "wifi_demo_parse.pcap", "demo.pcap"):
    r = diff.diff_file(os.path.join(ROOT, rel))
    bad = sum(v["diff"] + v["missing"] for v in r["stats"].values()) if r["stats"] else -1
    check(r["error"] is None and r["frames"] == r["ours_frames"] > 0 and bad == 0,
          "%s：%d 帧，不一致/没解析共 %d" % (rel, r["frames"], bad))

print("== 合成的头部变体（4 地址、QoS、HT Control、分片等），tshark 当标准答案 ==")
import tempfile  # noqa: E402
import synth  # noqa: E402
with tempfile.TemporaryDirectory() as tmp:
    cases = synth.cases()
    path = os.path.join(tmp, "synth.pcap")
    synth.write_pcap(path, [c[1] for c in cases])
    r = diff.diff_file(path)
    check(r["error"] is None and r["frames"] == r["ours_frames"] == len(cases), "%d 帧都能读出" % len(cases))
    for field, v in r["stats"].items():
        check(v["diff"] == 0 and v["missing"] == 0, "%s：一致 %d / 不一致 %d / 没解析 %d" % (field, v["ok"], v["diff"], v["missing"]))
    bad = [d for d in r["details"]]
    names = [c[0] for c in cases]
    for n, field, want, got in bad[:5]:
        print("      %s 帧 %d(%s) tshark=%r 我们=%r" % (field, n, names[n - 1], want, got))

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
