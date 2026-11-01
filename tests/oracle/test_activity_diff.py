#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""设备访问事件（activity80211）里的 DNS 查询对照 tshark：每个样例里，设备发往 AP 的 DNS / mDNS 查询帧，
帧号、设备 MAC、第一个提问的名字和 tshark 逐帧相同；每个样例的事件数固定成表。
（样例里没有 TLS 流，TLS 的 SNI 由 tests/test_activity.py 的合成流和 tests/oracle/test_tls_diff.py 对 tshark 覆盖。）"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decrypt_oracle as d  # noqa: E402
import fetch_samples  # noqa: E402
from wifi80211 import activity  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import pipeline as pl  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def tshark_queries(path, keys):
    usable, _ = d.tshark_usable(keys)
    with d.key_env(usable) as env:
        cmd = ["tshark", "-r", path] + d.TSHARK_DECRYPT + ["-Y", "(dns || mdns) && dns.flags.response == 0 && wlan.fc.tods == 1 && wlan.fc.fromds == 0 && wlan.fc.protected == 1",
                                                            "-T", "fields", "-E", "occurrence=f", "-e", "frame.number", "-e", "wlan.sa", "-e", "dns.qry.name"]
        out = subprocess.run(cmd, capture_output=True, text=True, env=env).stdout
    rows = {}
    for line in out.split("\n"):
        if line:
            n, sa, name = (line.split("\t") + ["", ""])[:3]
            rows[int(n)] = (sa, name)
    return rows


EXPECTED = {"wpa-Induction.pcap.gz": (17, 1, 13, 13)}               # 事件数、设备数、不同名字数、其中 DNS（其余是 mDNS）；其它样例里设备自己发的 DNS 查询为 0
fetch_samples.fetch()
keys = d.parse_keys()
seen = set()
for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    frames = list(fr.iter_frames(path))
    ev = [e for e in activity.build(frames, pl.decrypt_capture(frames, keys)) if e["kind"] in ("dns", "mdns")]
    ts = tshark_queries(path, keys)
    mine = {e["frame"]: (e["station"], e["name"]) for e in ev}
    if ev or ts:
        seen.add(name)
        check(mine == ts, "%s：设备发出的 %d 个 DNS / mDNS 查询，帧号、设备 MAC、名字和 tshark 逐帧相同（我们 %d 个，tshark %d 个）" % (name, len(ts), len(mine), len(ts)))
        row = (len(ev), len({e["station"] for e in ev}), len({e["name"] for e in ev}), sum(e["kind"] == "dns" for e in ev))
        check(row == EXPECTED.get(name), "%s：事件 / 设备 / 不同名字 / DNS = %s（表里 %s）" % (name, row, EXPECTED.get(name)))
check(seen == set(EXPECTED), "只有表里的样例有设备发出的 DNS 查询（%s）" % sorted(seen))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
