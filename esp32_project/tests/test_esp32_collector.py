#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_esp32_collector.py —— M2 AP 聚合逻辑单测（阶段9）

覆盖：BSSID 去重（跨轮 seen_count 累计 / RSSI 与信道更新）、
隐藏→可见 SSID 合并优先、可见→隐藏保留可见、RSSI 降序排序、
信道统计、top_aps、rssi_policy=best、ProbeCollector 广播/定向聚合。

运行：cd esp32_project && python3 tests/test_esp32_collector.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from esp32_ap_parser import parse_ap_record  # noqa: E402
from esp32_collector import ApCollector, ProbeCollector  # noqa: E402


def _ap(ssid, bssid, rssi, channel, authmode=3, hidden=None):
    rec = {"ssid": ssid, "bssid": bssid, "rssi": rssi,
           "channel": channel, "authmode": authmode}
    ap = parse_ap_record(rec)
    assert ap is not None
    if hidden is not None:
        ap.hidden = hidden
    return ap


def test_dedup_same_bssid_multiple_rounds():
    col = ApCollector()
    col.add(_ap("Home", "aa:bb:cc:dd:ee:01", -50, 1))
    col.add(_ap("Home", "aa:bb:cc:dd:ee:01", -45, 6))
    col.add(_ap("Home", "aa:bb:cc:dd:ee:01", -48, 11))
    assert len(col) == 1
    aps = col.aps()
    assert len(aps) == 1
    assert aps[0].bssid == "aa:bb:cc:dd:ee:01"
    assert aps[0].rssi == -48      # latest
    assert aps[0].channel == 11
    # seen_count 累计
    items = col.items()
    assert items[0][1] == 3


def test_hidden_then_visible_merged():
    col = ApCollector()
    col.add(_ap("", "aa:bb:cc:dd:ee:02", -70, 6, hidden=True))
    col.add(_ap("Known-SSID", "aa:bb:cc:dd:ee:02", -68, 6))
    aps = col.aps()
    assert len(aps) == 1
    assert aps[0].hidden is False
    assert aps[0].ssid == "Known-SSID"


def test_visible_then_hidden_keeps_visible():
    col = ApCollector()
    col.add(_ap("Known-SSID", "aa:bb:cc:dd:ee:03", -68, 6))
    col.add(_ap("", "aa:bb:cc:dd:ee:03", -72, 6, hidden=True))
    aps = col.aps()
    assert len(aps) == 1
    assert aps[0].hidden is False
    assert aps[0].ssid == "Known-SSID"


def test_sort_by_rssi_desc():
    col = ApCollector()
    col.add(_ap("A", "aa:bb:cc:dd:ee:01", -70, 1))
    col.add(_ap("B", "aa:bb:cc:dd:ee:02", -40, 6))
    col.add(_ap("C", "aa:bb:cc:dd:ee:03", -55, 11))
    aps = col.aps()
    assert [a.ssid for a in aps] == ["B", "C", "A"]
    assert [a.rssi for a in aps] == [-40, -55, -70]


def test_channel_stats():
    col = ApCollector()
    col.add(_ap("A", "aa:bb:cc:dd:ee:01", -70, 1))
    col.add(_ap("B", "aa:bb:cc:dd:ee:02", -40, 6))
    col.add(_ap("C", "aa:bb:cc:dd:ee:03", -55, 6))
    col.add(_ap("D", "aa:bb:cc:dd:ee:04", -60, 11))
    stats = col.channel_stats()
    assert stats == {1: 1, 6: 2, 11: 1}


def test_top_aps():
    col = ApCollector()
    col.add(_ap("A", "aa:bb:cc:dd:ee:01", -70, 1))
    col.add(_ap("B", "aa:bb:cc:dd:ee:02", -40, 6))
    col.add(_ap("C", "aa:bb:cc:dd:ee:03", -55, 11))
    top = col.top_aps(2)
    assert [a.ssid for a in top] == ["B", "C"]


def test_rssi_policy_best():
    col = ApCollector(rssi_policy="best")
    col.add(_ap("Home", "aa:bb:cc:dd:ee:01", -60, 1))
    col.add(_ap("Home", "aa:bb:cc:dd:ee:01", -42, 6))
    col.add(_ap("Home", "aa:bb:cc:dd:ee:01", -50, 11))
    assert col.aps()[0].rssi == -42   # 保留最强信号


def test_add_records_returns_parsed_count():
    col = ApCollector()
    n = col.add_records([
        {"ssid": "A", "bssid": "aa:bb:cc:dd:ee:01", "rssi": -50, "channel": 1, "authmode": 0},
        {"ssid": "B", "bssid": "bad-bssid", "rssi": -55, "channel": 6, "authmode": 0},
    ])
    assert n == 1


def test_probe_collector_broadcast_and_directed():
    pc = ProbeCollector()
    pc.add_probe("11:22:33:44:55:66", "", -61)               # 广播
    pc.add_probe("11:22:33:44:55:66", "Paul-Home-2.4G", -59)  # 同 STA 定向
    pc.add_probe("aa:aa:bb:bb:cc:cc", "Neighbor-WiFi", -72)
    probes = pc.probes()
    assert len(probes) == 2
    by_sta = {p["sta"]: p for p in probes}
    assert by_sta["11:22:33:44:55:66"]["ssid"] == "Paul-Home-2.4G"
    assert by_sta["11:22:33:44:55:66"]["count"] == 2
    assert by_sta["aa:aa:bb:bb:cc:cc"]["count"] == 1


def _main():
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in funcs:
        try:
            fn()
            print("PASS  %s" % fn.__name__)
        except Exception as e:
            failed += 1
            print("FAIL  %s: %s" % (fn.__name__, e))
    print("\n%d/%d passed" % (len(funcs) - failed, len(funcs)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    _main()
