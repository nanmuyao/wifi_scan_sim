#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esp32_consumer.py —— 端侧数据消费与展示模型（阶段9 / M4）

消费 esp32_sim.py / M3 上报通道的两类输出，转换为仪表盘可直接渲染的结构：

  1. WebSocket JSON 快照（snapshot）：解析并规整为展示视图
       {"type":"snapshot","ts_ms":...,"channel":...,"aps":[...],"probes":[...]}
       aps 项对齐 M3 结构（bssid/ssid/rssi/channel/beacons），并兼容可选扩展
       字段 authmode_name（加密类型，串口/真机固件可带上）；
       probes 项为 {"sta","ssid","rssi","count"}。
  2. 串口文本（+SNIFF 风格）：按行解析 AP / PROBE 记录，供命令行订阅端消费
        +SNIFF:AP,<bssid>,<ssid|hidden>,<rssi>,<ch>,<authmode>
        +SNIFF:PROBE,"<ssid>",<sta mac>,<rssi>

所有解析均为容错式：非法 JSON / 未知消息类型 / 坏行返回 None 或跳过，
绝不因单条脏数据中断整批展示。

纯标准库实现（json / re），无第三方依赖。
"""

import json
import re

_SERIAL_AP_RE = re.compile(
    r"^\+SNIFF:AP,(?P<bssid>[0-9a-fA-F:.-]+),(?P<ssid>[^,]*),"
    r"(?P<rssi>-?\d+),(?P<ch>\d+),(?P<authmode>[^,]+)\s*$")
_SERIAL_PROBE_RE = re.compile(
    r'^\+SNIFF:PROBE,"?(?P<ssid>[^",]*)",?(?P<sta>[0-9a-fA-F:.-]+),'
    r"(?P<rssi>-?\d+)\s*$")


def parse_message(text):
    """解析一条 WebSocket 文本消息；非法 JSON 或非 snapshot 类型返回 None。"""
    if not isinstance(text, str):
        return None
    try:
        msg = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(msg, dict) or msg.get("type") != "snapshot":
        return None
    return msg


def _norm_ssid(ssid):
    if ssid is None:
        return "<hidden>"
    if isinstance(ssid, bytes):
        ssid = ssid.decode("utf-8", "replace")
    ssid = str(ssid)
    # 空串 / 全 NUL 均视为隐藏 SSID（对齐 M1 解析语义）
    if not ssid.replace("\x00", "").strip():
        return "<hidden>"
    return ssid


def normalize_ap(raw):
    """把快照中的一条 AP 原始记录规整为展示行（字段缺失时给安全默认值）。"""
    try:
        rssi = int(raw.get("rssi"))
    except (TypeError, ValueError):
        rssi = None
    try:
        channel = int(raw.get("channel"))
    except (TypeError, ValueError):
        channel = None
    try:
        beacons = int(raw.get("beacons", 1))
    except (TypeError, ValueError):
        beacons = 0
    return {
        "ssid": _norm_ssid(raw.get("ssid")),
        "bssid": str(raw.get("bssid") or "-").lower(),
        "rssi": rssi,
        "channel": channel,
        "authmode": str(raw.get("authmode_name") or "-"),
        "beacons": beacons,
    }


def rank_aps(aps, reverse=True):
    """按 RSSI 排序 AP 列表；无 RSSI 的记录排末尾。"""
    valid = [a for a in aps if a["rssi"] is not None]
    invalid = [a for a in aps if a["rssi"] is None]
    valid.sort(key=lambda a: a["rssi"], reverse=reverse)
    return valid + invalid


def channel_distribution(aps):
    """信道分布：{channel: AP 数量}（忽略无信道记录）。"""
    dist = {}
    for ap in aps:
        if ap["channel"] is None:
            continue
        dist[ap["channel"]] = dist.get(ap["channel"], 0) + 1
    return dist


def build_view(snapshot):
    """把解析后的 snapshot 转成仪表盘展示模型。

    返回 {"ts_ms","channel","ap_rows","channel_stats","totals"}，
    totals 含 ap_total（原始条数）、ap_unique（按 bssid 去重）、
    probe_total（探测条数）与更新时刻。
    """
    aps_raw = snapshot.get("aps") or []
    aps = [normalize_ap(a) for a in aps_raw]
    probes = snapshot.get("probes") or []
    return {
        "ts_ms": snapshot.get("ts_ms"),
        "channel": snapshot.get("channel"),
        "ap_rows": rank_aps(aps),
        "channel_stats": channel_distribution(aps),
        "totals": {
            "ap_total": len(aps_raw),
            "ap_unique": len({a["bssid"] for a in aps}),
            "probe_total": len(probes),
            "displayed": len(aps),
        },
    }


def parse_serial_lines(text):
    """解析 +SNIFF 串口文本，返回 {"aps": [...], "probes": [...], "skipped": n}。

    AP 行规整为与 normalize_ap 同构的展示行（authmode 为加密名）；
    坏行只计数跳过，不中断解析。
    """
    result = {"aps": [], "probes": [], "skipped": 0}
    if not text:
        return result
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _SERIAL_AP_RE.match(line)
        if m:
            result["aps"].append({
                "ssid": _norm_ssid(m.group("ssid")),
                "bssid": m.group("bssid").lower(),
                "rssi": int(m.group("rssi")),
                "channel": int(m.group("ch")),
                "authmode": m.group("authmode"),
                "beacons": 1,
            })
            continue
        m = _SERIAL_PROBE_RE.match(line)
        if m:
            result["probes"].append({
                "sta": m.group("sta").lower(),
                "ssid": _norm_ssid(m.group("ssid")),
                "rssi": int(m.group("rssi")),
                "count": 1,
            })
            continue
        result["skipped"] += 1
    return result


def format_cli_table(view):
    """把展示模型格式化为命令行表格文本（订阅端输出）。"""
    rows = view["ap_rows"]
    lines = []
    header = "%-24s %-20s %6s %6s %-12s %s" % (
        "SSID", "BSSID", "RSSI", "CH", "AUTH", "BEACONS")
    lines.append(header)
    lines.append("-" * len(header))
    for ap in rows:
        rssi = "-" if ap["rssi"] is None else ap["rssi"]
        ch = "-" if ap["channel"] is None else ap["channel"]
        lines.append("%-24s %-20s %6s %6s %-12s %s" % (
            ap["ssid"][:24], ap["bssid"], rssi, ch,
            ap["authmode"], ap["beacons"]))
    if not rows:
        lines.append("(no AP)")
    lines.append("信道分布: " + (
        ", ".join("ch%d x%d" % (ch, n) for ch, n in
                  sorted(view["channel_stats"].items()))
        if view["channel_stats"] else "(none)"))
    return "\n".join(lines)
