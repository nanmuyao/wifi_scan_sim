#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_esp32_consumer.py —— M4 数据消费/消息解析逻辑单测

覆盖：WebSocket snapshot 解析、容错（非法 JSON / 未知类型 / 字段缺失）、
RSSI 排序、信道分布、展示统计、+SNIFF 串口文本解析（AP/PROBE/坏行）、
WebSocket 文本帧编码与订阅端 URL 解析。

运行：python3 esp32_project/tests/test_esp32_consumer.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import esp32_consumer as consumer  # noqa: E402
import esp32_bridge as bridge      # noqa: E402
import esp32_sub_cli as subcli     # noqa: E402


def _snapshot(**over):
    msg = {
        "type": "snapshot",
        "ts_ms": 1710000000123,
        "channel": 6,
        "aps": [
            {"bssid": "aa:bb:cc:dd:ee:01", "ssid": "Home",
             "rssi": -52, "channel": 6, "beacons": 5, "authmode_name": "WPA2"},
            {"bssid": "aa:bb:cc:dd:ee:02", "ssid": "",
             "rssi": -70, "channel": 1, "beacons": 2},
            {"bssid": "aa:bb:cc:dd:ee:03", "ssid": "Lab",
             "rssi": None, "channel": None, "beacons": 1},
        ],
        "probes": [{"sta": "11:22:33:44:55:66", "ssid": "Home",
                    "rssi": -59, "count": 3}],
    }
    msg.update(over)
    return msg


def test_parse_message_ok():
    import json
    msg = consumer.parse_message(json.dumps(_snapshot()))
    assert msg is not None and msg["type"] == "snapshot"
    assert len(msg["aps"]) == 3


def test_parse_message_bad_json():
    assert consumer.parse_message("{not-json") is None
    assert consumer.parse_message("") is None
    assert consumer.parse_message(None) is None


def test_parse_message_not_snapshot():
    assert consumer.parse_message('{"type":"ping"}') is None
    assert consumer.parse_message("42") is None
    assert consumer.parse_message("[]") is None


def test_normalize_ap_defaults():
    ap = consumer.normalize_ap({"bssid": "AA:BB:CC:DD:EE:01",
                                "ssid": "NoAuth"})
    assert ap["rssi"] is None
    assert ap["channel"] is None
    assert ap["authmode"] == "-"
    assert ap["bssid"] == "aa:bb:cc:dd:ee:01"
    assert ap["ssid"] == "NoAuth"


def test_normalize_ap_hidden():
    ap = consumer.normalize_ap({"bssid": "aa:bb:cc:dd:ee:02", "ssid": ""})
    assert ap["ssid"] == "<hidden>"
    ap = consumer.normalize_ap({"bssid": "aa:bb:cc:dd:ee:02",
                                "ssid": b"\x00\x00"})
    assert ap["ssid"] == "<hidden>"


def test_rank_aps_rssi_desc():
    aps = [{"rssi": -60, "bssid": "a"}, {"rssi": -40, "bssid": "b"},
           {"rssi": None, "bssid": "c"}, {"rssi": -55, "bssid": "d"}]
    ranked = consumer.rank_aps(aps)
    assert [a["bssid"] for a in ranked] == ["b", "d", "a", "c"]


def test_channel_distribution():
    dist = consumer.channel_distribution([
        {"channel": 6, "rssi": -50}, {"channel": 6, "rssi": -51},
        {"channel": 1, "rssi": -70}, {"channel": None, "rssi": None}])
    assert dist == {6: 2, 1: 1}


def test_build_view_stats():
    view = consumer.build_view(_snapshot())
    assert view["channel"] == 6
    assert view["totals"]["ap_total"] == 3
    assert view["totals"]["ap_unique"] == 3
    assert view["totals"]["probe_total"] == 1
    assert view["totals"]["displayed"] == 3
    assert view["ap_rows"][0]["bssid"] == "aa:bb:cc:dd:ee:01"
    assert view["ap_rows"][-1]["rssi"] is None  # 无 RSSI 排末尾
    assert view["channel_stats"][6] == 1


def test_build_view_missing_aps():
    view = consumer.build_view({"type": "snapshot", "ts_ms": 1, "aps": []})
    assert view["totals"]["ap_total"] == 0
    assert view["channel_stats"] == {}
    view2 = consumer.build_view({"type": "snapshot", "ts_ms": 2})
    assert view2["totals"]["ap_total"] == 0


def test_authmode_missing_ok():
    view = consumer.build_view(_snapshot())
    row = [a for a in view["ap_rows"]
           if a["bssid"] == "aa:bb:cc:dd:ee:02"][0]
    assert row["authmode"] == "-"


def test_serial_parse_ap_line():
    text = "+SNIFF:AP,aa:bb:cc:dd:ee:01,Home-2.4G,-52,6,WPA2_PSK"
    parsed = consumer.parse_serial_lines(text)
    assert len(parsed["aps"]) == 1
    assert parsed["probes"] == []
    assert parsed["skipped"] == 0
    ap = parsed["aps"][0]
    assert ap["bssid"] == "aa:bb:cc:dd:ee:01"
    assert ap["ssid"] == "Home-2.4G"
    assert ap["rssi"] == -52 and ap["channel"] == 6
    assert ap["authmode"] == "WPA2_PSK"


def test_serial_parse_probe_line():
    text = '+SNIFF:PROBE,"Paul-Home-2.4G",11:22:33:44:55:66,-59'
    parsed = consumer.parse_serial_lines(text)
    assert len(parsed["probes"]) == 1
    p = parsed["probes"][0]
    assert p["sta"] == "11:22:33:44:55:66"
    assert p["ssid"] == "Paul-Home-2.4G"
    assert p["rssi"] == -59


def test_serial_parse_bad_lines_skipped():
    text = ("+SNIFF:AP,aa:bb:cc:dd:ee:01,Home,-52,6,WPA2\n"
            "garbage line\n"
            "+SNIFF:UNKNOWN,...\n")
    parsed = consumer.parse_serial_lines(text)
    assert len(parsed["aps"]) == 1
    assert parsed["skipped"] == 2


def test_serial_parse_empty():
    parsed = consumer.parse_serial_lines("")
    assert parsed["aps"] == [] and parsed["probes"] == []
    assert parsed["skipped"] == 0


def test_format_cli_table():
    view = consumer.build_view(_snapshot())
    table = consumer.format_cli_table(view)
    assert "Home" in table and "aa:bb:cc:dd:ee:01" in table
    assert "信道分布" in table


def test_ws_frame_encode_lengths():
    f1 = bridge.encode_text_frame("abc")
    assert f1[0] == 0x81 and f1[1] == 3 and f1[2:] == b"abc"
    long_125 = "x" * 125
    f2 = bridge.encode_text_frame(long_125)
    assert f2[1] == 125
    long_126 = "x" * 126
    f3 = bridge.encode_text_frame(long_126)
    assert f3[1] == 126
    import struct as _st
    assert _st.unpack(">H", f3[2:4])[0] == 126
    big = "x" * 70000
    f4 = bridge.encode_text_frame(big)
    assert f4[1] == 127
    assert _st.unpack(">Q", f4[2:10])[0] == 70000


def test_subcli_url_parse():
    host, port, path = subcli._parse_url("ws://127.0.0.1:8765/ws")
    assert (host, port, path) == ("127.0.0.1", 8765, "/ws")
    host2, port2, path2 = subcli._parse_url("ws://localhost/")
    assert (host2, port2, path2) == ("localhost", 80, "/")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            passed += 1
            print("PASS %s" % fn.__name__)
        except AssertionError as e:
            print("FAIL %s: %s" % (fn.__name__, e))
    total = len(fns)
    print("\n%d/%d passed" % (passed, total))
    sys.exit(0 if passed == total else 1)
