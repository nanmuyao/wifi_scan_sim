#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_esp32_parser.py —— M1 直扫结果解析单测（阶段9）

覆盖：可见 AP、隐藏 SSID（空串 / 全 NUL 字节）、BSSID 多种形态归一、
authmode 越界、SSID 超长截断、非法记录拒绝、批量解析跳过计数。

运行：cd esp32_project && python3 tests/test_esp32_parser.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import esp32_ap_parser as parser  # noqa: E402


def test_parse_visible_ap():
    ap = parser.parse_ap_record({
        "ssid": "Paul-Home-2.4G",
        "bssid": "AA:BB:CC:DD:EE:01",
        "rssi": -52,
        "channel": 6,
        "authmode": 3,
    })
    assert ap is not None
    assert ap.ssid == "Paul-Home-2.4G"
    assert ap.hidden is False
    assert ap.bssid == "aa:bb:cc:dd:ee:01"
    assert ap.rssi == -52
    assert ap.channel == 6
    assert ap.authmode == 3
    assert ap.authmode_name == "WPA2_PSK"


def test_parse_hidden_ssid_empty():
    ap = parser.parse_ap_record({
        "ssid": "", "bssid": "aa:bb:cc:dd:ee:03",
        "rssi": -70, "channel": 6, "authmode": 0,
    })
    assert ap is not None
    assert ap.hidden is True
    assert ap.ssid == ""
    assert ap.as_dict()["ssid"] == "<hidden>"


def test_parse_hidden_ssid_nul_bytes():
    ap = parser.parse_ap_record({
        "ssid": b"\x00\x00\x00\x00", "bssid": "aa:bb:cc:dd:ee:04",
        "rssi": -66, "channel": 1, "authmode": 3,
    })
    assert ap is not None
    assert ap.hidden is True
    assert ap.ssid == ""


def test_parse_bssid_variants():
    cases = [
        ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:01"),
        ("AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:01"),
        ("aa-bb-cc-dd-ee-01", "aa:bb:cc:dd:ee:01"),
        ("aabbccddee01", "aa:bb:cc:dd:ee:01"),
        (bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]), "aa:bb:cc:dd:ee:01"),
    ]
    for raw, expected in cases:
        ap = parser.parse_ap_record({
            "ssid": "X", "bssid": raw, "rssi": -60, "channel": 6, "authmode": 0,
        })
        assert ap is not None, "bssid=%r should parse" % (raw,)
        assert ap.bssid == expected, "bssid=%r -> %s" % (raw, ap.bssid)


def test_parse_invalid_bssid_rejected():
    for bad in ("aa:bb:cc:dd:ee", "aabbccddee0", "zz:bb:cc:dd:ee:01", 12345):
        ap = parser.parse_ap_record({
            "ssid": "X", "bssid": bad, "rssi": -60, "channel": 6, "authmode": 0,
        })
        assert ap is None, "bssid=%r should be rejected" % (bad,)


def test_parse_authmode_unknown():
    ap = parser.parse_ap_record({
        "ssid": "X", "bssid": "aa:bb:cc:dd:ee:09",
        "rssi": -60, "channel": 6, "authmode": 99,
    })
    assert ap is not None
    assert ap.authmode_name == "UNKNOWN"
    ap2 = parser.parse_ap_record({
        "ssid": "X", "bssid": "aa:bb:cc:dd:ee:0a",
        "rssi": -60, "channel": 6, "authmode": None,
    })
    assert ap2 is not None
    assert ap2.authmode_name == "UNKNOWN"


def test_parse_ssid_too_long_truncated():
    long_ssid = "A" * 40
    ap = parser.parse_ap_record({
        "ssid": long_ssid, "bssid": "aa:bb:cc:dd:ee:0b",
        "rssi": -60, "channel": 6, "authmode": 3,
    })
    assert ap is not None
    assert len(ap.ssid) == 32


def test_parse_invalid_record_rejected():
    assert parser.parse_ap_record(None) is None
    assert parser.parse_ap_record("not-a-dict") is None
    # rssi/channel 非法
    assert parser.parse_ap_record({
        "ssid": "X", "bssid": "aa:bb:cc:dd:ee:0c",
        "rssi": "bad", "channel": 6, "authmode": 0,
    }) is None
    assert parser.parse_ap_record({
        "ssid": "X", "bssid": "aa:bb:cc:dd:ee:0c",
        "rssi": -60, "channel": None, "authmode": 0,
    }) is None


def test_parse_batch_skipped_count():
    records = [
        {"ssid": "A", "bssid": "aa:bb:cc:dd:ee:01", "rssi": -50, "channel": 1, "authmode": 0},
        {"ssid": "", "bssid": "aa:bb:cc:dd:ee:02", "rssi": -60, "channel": 6, "authmode": 3},
        {"ssid": "B", "bssid": "bad-bssid", "rssi": -55, "channel": 6, "authmode": 0},
    ]
    aps, skipped = parser.parse_ap_records(records)
    assert len(aps) == 2
    assert skipped == 1
    assert aps[0].ssid == "A"
    assert aps[1].hidden is True


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
