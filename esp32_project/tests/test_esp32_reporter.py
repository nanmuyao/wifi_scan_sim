#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_esp32_reporter.py —— M3 上报通道消息格式单测（阶段9）

覆盖：串口 +SNIFF:AP / +SNIFF:PROBE 文本格式（隐藏 SSID、广播探测）、
WebSocket JSON 快照结构（与设计文档 3.4 对齐）、JSON 可回读。

运行：cd esp32_project && python3 tests/test_esp32_reporter.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from esp32_ap_parser import parse_ap_record  # noqa: E402
from esp32_collector import ApCollector, ProbeCollector  # noqa: E402
import esp32_reporter as reporter  # noqa: E402


def test_format_serial_ap_visible():
    ap = parse_ap_record({
        "ssid": "Paul-Home-2.4G", "bssid": "aa:bb:cc:dd:ee:01",
        "rssi": -52, "channel": 6, "authmode": 3,
    })
    line = reporter.format_serial_ap(ap)
    assert line == "+SNIFF:AP,aa:bb:cc:dd:ee:01,Paul-Home-2.4G,-52,6,WPA2_PSK"


def test_format_serial_ap_hidden():
    ap = parse_ap_record({
        "ssid": "", "bssid": "aa:bb:cc:dd:ee:03",
        "rssi": -70, "channel": 6, "authmode": 0,
    })
    line = reporter.format_serial_ap(ap)
    assert line == "+SNIFF:AP,aa:bb:cc:dd:ee:03,<hidden>,-70,6,OPEN"


def test_format_serial_probe():
    assert reporter.format_serial_probe("11:22:33:44:55:66", "", -61) == \
        '+SNIFF:PROBE,"<broadcast>",11:22:33:44:55:66,-61'
    assert reporter.format_serial_probe("11:22:33:44:55:66", "Home", -59) == \
        '+SNIFF:PROBE,"Home",11:22:33:44:55:66,-59'


def test_json_snapshot_structure():
    ap = parse_ap_record({
        "ssid": "Paul-Home-2.4G", "bssid": "aa:bb:cc:dd:ee:01",
        "rssi": -52, "channel": 6, "authmode": 3,
    })
    hidden = parse_ap_record({
        "ssid": "", "bssid": "aa:bb:cc:dd:ee:02",
        "rssi": -70, "channel": 6, "authmode": 0,
    })
    probes = [{"sta": "11:22:33:44:55:66", "ssid": "<broadcast>",
               "rssi": -61, "count": 1}]
    snap = reporter.build_json_snapshot(
        [(ap, 3), (hidden, 1)], probes, channel=6, ts_ms=1710000000000)

    assert snap["type"] == "snapshot"
    assert snap["ts_ms"] == 1710000000000
    assert snap["channel"] == 6
    assert len(snap["aps"]) == 2
    assert snap["aps"][0]["bssid"] == "aa:bb:cc:dd:ee:01"
    assert snap["aps"][0]["ssid"] == "Paul-Home-2.4G"
    assert snap["aps"][0]["beacons"] == 3
    assert snap["aps"][1]["ssid"] == "<hidden>"
    assert snap["probes"] == probes


def test_json_snapshot_roundtrip():
    ap = parse_ap_record({
        "ssid": "Neighbor", "bssid": "aa:bb:cc:dd:ee:09",
        "rssi": -55, "channel": 11, "authmode": 4,
    })
    text = reporter.dump_json_snapshot([(ap, 2)], [], channel=11)
    obj = json.loads(text)
    assert obj["type"] == "snapshot"
    assert obj["aps"][0]["ssid"] == "Neighbor"
    assert obj["aps"][0]["beacons"] == 2
    assert obj["probes"] == []


def test_json_snapshot_from_collector():
    """端到端：collector 聚合结果直接可序列化为快照。"""
    col = ApCollector()
    col.add_records([
        {"ssid": "A", "bssid": "aa:bb:cc:dd:ee:01", "rssi": -50, "channel": 6, "authmode": 3},
        {"ssid": "A", "bssid": "aa:bb:cc:dd:ee:01", "rssi": -44, "channel": 6, "authmode": 3},
        {"ssid": "", "bssid": "aa:bb:cc:dd:ee:02", "rssi": -70, "channel": 1, "authmode": 0},
    ])
    pc = ProbeCollector()
    pc.add_probe("11:22:33:44:55:66", "", -61)
    snap = reporter.build_json_snapshot(col.items(), pc.probes(), channel=6)
    assert len(snap["aps"]) == 2
    assert snap["aps"][0]["beacons"] == 2
    assert snap["aps"][1]["ssid"] == "<hidden>"
    assert len(snap["probes"]) == 1
    assert snap["probes"][0]["ssid"] == "<broadcast>"


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
