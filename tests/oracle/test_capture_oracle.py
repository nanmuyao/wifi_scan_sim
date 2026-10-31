#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""capture.py 在 24 个公开样例上与 tshark / editcap 对照。需要 tshark 和样例（缺的会先下载）。

每个样例：包数、每个包的 caplen / origlen / 时间戳 / 链路类型与 tshark 一致；
再用 editcap 转成经典 pcap，字节内容逐包一致。
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
from wifi80211 import capture  # noqa: E402
import fetch_samples  # noqa: E402

# tshark 的 frame.encap_type -> pcap 链路类型
ENCAP_TO_LINKTYPE = {1: 1, 23: 127, 20: 105}

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
total_pkts = 0
with tempfile.TemporaryDirectory() as tmp:
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        cap = capture.read_capture(path)
        out = subprocess.run(["tshark", "-r", path, "-T", "fields", "-E", "separator=/t",
                              "-e", "frame.cap_len", "-e", "frame.len", "-e", "frame.time_epoch", "-e", "frame.encap_type"],
                             capture_output=True, text=True).stdout.strip().split("\n")
        rows = [r.split("\t") for r in out if r]
        ok = len(rows) == len(cap.packets) and not cap.truncated
        bad = ""
        if ok:
            for i, (r, p) in enumerate(zip(rows, cap.packets)):
                if (int(r[0]) != p.caplen or int(r[1]) != p.origlen or abs(float(r[2]) - p.ts) > 1e-6
                        or ENCAP_TO_LINKTYPE.get(int(r[3])) != p.linktype):
                    ok, bad = False, "第 %d 个包: tshark=%s 我们=(%d,%d,%.6f,%d)" % (i + 1, r, p.caplen, p.origlen, p.ts, p.linktype)
                    break
        else:
            bad = "包数 tshark %d / 我们 %d%s" % (len(rows), len(cap.packets), "（文件被判截断）" if cap.truncated else "")
        check(ok, "%s：%d 个包，长度/时间戳/链路类型与 tshark 一致%s" % (name, len(rows), (" ← " + bad) if bad else ""))
        total_pkts += len(rows)

        pcap_path = os.path.join(tmp, name + ".pcap")
        subprocess.run(["editcap", "-F", "pcap", path, pcap_path], capture_output=True)
        if os.path.exists(pcap_path):
            ref = capture.read_capture(pcap_path)
            same = len(ref.packets) == len(cap.packets) and all(a.data == b.data for a, b in zip(ref.packets, cap.packets))
            check(same, "%s：字节内容与 editcap 转出的 pcap 逐包一致" % name)
        else:
            check(False, "%s：editcap 转换失败" % name)

print("\n共 %d 个包。结果: %s（%d 项失败）" % (total_pkts, "全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
