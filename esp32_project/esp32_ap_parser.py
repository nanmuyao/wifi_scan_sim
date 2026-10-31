#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esp32_ap_parser.py —— ESP32 直扫结果解析（阶段9 / M1）

把 ESP-IDF `esp_wifi_scan_start()` / `esp_wifi_scan_get_ap_records()` 返回的
AP 记录（wifi_ap_record_t，真机数据或仿真构造数据）标准化为统一 ApInfo 结构，
覆盖以下边界：
  - 隐藏 SSID：ssid 为空串或全 NUL 字节 → hidden=True，展示名 '<hidden>'
  - SSID 超 32 字节：截断（ESP32 协议栈上限 32）
  - BSSID 多种形态归一：冒号分隔 / 短横分隔 / 无分隔 hex / bytes[6]
  - authmode 越界或缺失：authmode_name='UNKNOWN'（记录仍保留）
  - rssi / channel 非法类型、bssid 非法 → 拒绝该记录

数据源说明（无硬件仿真路径）：
  - 真机：wifi_ap_record_t 的字段（ssid/bssid/rssi/channel/authmode）
  - 仿真：esp32_sim.py 构造的字典列表（字段与 wifi_ap_record_t 对齐）

纯标准库实现，无第三方依赖。
"""

import re

# ESP-IDF wifi_auth_mode_t 枚举名映射（v5.x）
WIFI_AUTHMODE_NAMES = {
    0: "OPEN",
    1: "WEP",
    2: "WPA_PSK",
    3: "WPA2_PSK",
    4: "WPA_WPA2_PSK",
    5: "WPA2_ENTERPRISE",
    6: "WPA3_PSK",
    7: "WPA2_WPA3_PSK",
    8: "WPA3_ENT_192",
}

_BSSID_COLON = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_BSSID_DASH = re.compile(r"^([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}$")
_BSSID_HEX = re.compile(r"^[0-9a-fA-F]{12}$")


class ApInfo(object):
    """标准化的 AP 记录。"""

    __slots__ = ("ssid", "hidden", "bssid", "rssi", "channel",
                 "authmode", "authmode_name")

    def __init__(self, ssid, hidden, bssid, rssi, channel, authmode, authmode_name):
        self.ssid = ssid
        self.hidden = hidden
        self.bssid = bssid
        self.rssi = rssi
        self.channel = channel
        self.authmode = authmode
        self.authmode_name = authmode_name

    def as_dict(self):
        return {
            "bssid": self.bssid,
            "ssid": "<hidden>" if self.hidden else self.ssid,
            "rssi": self.rssi,
            "channel": self.channel,
            "authmode": self.authmode_name,
        }

    def __repr__(self):
        return "ApInfo(%s %s rssi=%d ch=%d %s)" % (
            self.bssid,
            "<hidden>" if self.hidden else self.ssid,
            self.rssi,
            self.channel,
            self.authmode_name,
        )


def normalize_bssid(raw):
    """BSSID 归一化为小写冒号分隔 'aa:bb:cc:dd:ee:ff'；非法返回 None。"""
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray, list, tuple)):
        b = bytes(raw)
        if len(b) != 6:
            return None
        return ":".join("%02x" % x for x in b)
    s = str(raw).strip()
    if _BSSID_COLON.match(s):
        return s.lower()
    if _BSSID_DASH.match(s):
        return s.lower().replace("-", ":")
    if _BSSID_HEX.match(s):
        return ":".join(s[i:i + 2] for i in range(0, 12, 2)).lower()
    return None


def decode_ssid(raw):
    """解码 SSID：bytes/str → str，去尾部 NUL；返回 (ssid, hidden)。"""
    if raw is None:
        return "", True
    if isinstance(raw, str):
        s = raw
    else:
        try:
            s = bytes(raw).decode("utf-8", errors="replace")
        except Exception:
            return "", True
    s = s.rstrip("\x00")
    hidden = s == ""
    return s, hidden


def parse_ap_record(record):
    """解析单条 ESP-IDF AP 记录（字典形式），返回 ApInfo；非法记录返回 None。"""
    if not isinstance(record, dict):
        return None

    ssid_raw = record.get("ssid")
    ssid, hidden = decode_ssid(ssid_raw)
    if len(ssid) > 32:
        ssid = ssid[:32]

    bssid = normalize_bssid(record.get("bssid"))
    if bssid is None:
        return None

    try:
        rssi = int(record.get("rssi"))
        channel = int(record.get("channel"))
    except (TypeError, ValueError):
        return None

    authmode = record.get("authmode")
    try:
        authmode = int(authmode)
    except (TypeError, ValueError):
        authmode = -1
    name = WIFI_AUTHMODE_NAMES.get(authmode, "UNKNOWN")

    return ApInfo(ssid=ssid, hidden=hidden, bssid=bssid, rssi=rssi,
                  channel=channel, authmode=authmode, authmode_name=name)


def parse_ap_records(records):
    """批量解析，返回 (aps, skipped_count)。"""
    if not records:
        return [], 0
    aps, skipped = [], 0
    for rec in records:
        ap = parse_ap_record(rec)
        if ap is None:
            skipped += 1
        else:
            aps.append(ap)
    return aps, skipped
