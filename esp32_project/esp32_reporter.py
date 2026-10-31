#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esp32_reporter.py —— 上报通道与消息格式（阶段9 / M3）

定义两类输出通道的消息格式，并在 PC 仿真中直接演示：

  1. 串口文本（+SNIFF 风格，兼容阶段2 报告格式与 tools/serial_wifi_plot.py）
       +SNIFF:AP,<bssid>,<ssid|hidden>,<rssi>,<ch>,<authmode>
       +SNIFF:PROBE,"<ssid>",<sta mac>,<rssi>
     （广播探测 ssid 记 <broadcast>）

  2. WebSocket JSON 快照（对齐 docs/ESP32版设计文档.md 3.4 的 snapshot 结构）
       {
         "type": "snapshot",
         "ts_ms": 1710000000000,
         "channel": 6,
         "aps": [{"bssid": "...", "ssid": "...", "rssi": -52,
                  "channel": 6, "beacons": 120}],
         "probes": [{"sta": "...", "ssid": "...", "rssi": -61, "count": 3}]
       }

纯标准库实现（json / time），无第三方依赖。
"""

import json
import time


def format_serial_ap(ap):
    """单条 AP 的串口文本：+SNIFF:AP,<bssid>,<ssid>,<rssi>,<ch>,<authmode>"""
    ssid = "<hidden>" if ap.hidden else (ap.ssid if ap.ssid else "<hidden>")
    return "+SNIFF:AP,%s,%s,%d,%d,%s" % (
        ap.bssid, ssid, ap.rssi, ap.channel, ap.authmode_name)


def format_serial_probe(sta_mac, ssid, rssi):
    """单条探测的串口文本：+SNIFF:PROBE,"<ssid>",<sta mac>,<rssi>"""
    ssid = ssid if ssid else "<broadcast>"
    return '+SNIFF:PROBE,"%s",%s,%d' % (ssid, sta_mac, rssi)


def _ap_to_json(ap, seen_count):
    return {
        "bssid": ap.bssid,
        "ssid": "<hidden>" if ap.hidden else ap.ssid,
        "rssi": ap.rssi,
        "channel": ap.channel,
        "beacons": seen_count,
    }


def build_json_snapshot(aps_with_counts, probes, channel, ts_ms=None):
    """构造 WebSocket 快照字典（对齐设计文档 3.4）。"""
    if ts_ms is None:
        ts_ms = int(time.time() * 1000)
    return {
        "type": "snapshot",
        "ts_ms": ts_ms,
        "channel": channel,
        "aps": [_ap_to_json(ap, cnt) for ap, cnt in aps_with_counts],
        "probes": list(probes),
    }


def dump_json_snapshot(aps_with_counts, probes, channel, ts_ms=None):
    """JSON 序列化快照（用于仿真演示 / WebSocket 发送）。"""
    return json.dumps(build_json_snapshot(aps_with_counts, probes, channel, ts_ms),
                      ensure_ascii=False, indent=2)
