#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esp32_collector.py —— AP 聚合逻辑（阶段9 / M2）

按 BSSID 去重合并多轮直扫结果，支持：
  - 去重：同 BSSID 跨轮合并（seen_count 累计、RSSI/信道按策略更新）
  - 隐藏 SSID 合并：同一 BSSID 先见隐藏后见可见 SSID 时以可见为准
  - 信号排序：RSSI 降序（最强信号优先展示）
  - 信道统计：各信道 AP 数量分布
  - RSSI 保留策略：latest（最新观测）或 best（保留最强信号）

另含 ProbeCollector：按 STA MAC 聚合探测记录（广播探测记 '<broadcast>'），
为 M3 的 +SNIFF:PROBE 报告与 WebSocket snapshot 的 probes 字段提供数据。

纯标准库实现，无第三方依赖。
"""

import esp32_ap_parser as parser


class ApCollector(object):
    """按 BSSID 聚合的 AP 表。"""

    def __init__(self, rssi_policy="latest"):
        if rssi_policy not in ("latest", "best"):
            raise ValueError("rssi_policy must be 'latest' or 'best'")
        self.rssi_policy = rssi_policy
        self._aps = {}  # bssid -> [ApInfo, seen_count]

    def add(self, ap):
        """合并一条已解析的 ApInfo。"""
        key = ap.bssid
        cur = self._aps.get(key)
        if cur is None:
            self._aps[key] = [ap, 1]
            return
        cur_ap, count = cur
        # SSID 合并：优先保留可见 SSID
        if cur_ap.hidden and not ap.hidden:
            cur_ap.ssid, cur_ap.hidden = ap.ssid, False
        elif not ap.hidden:
            cur_ap.ssid = ap.ssid  # 同为可见，取最新观测的 SSID
        cur_ap.channel = ap.channel
        if self.rssi_policy == "latest":
            cur_ap.rssi = ap.rssi
        else:  # best
            cur_ap.rssi = max(cur_ap.rssi, ap.rssi)
        cur[1] = count + 1

    def add_records(self, records):
        """批量喂入 ESP-IDF 风格记录（内部走 M1 解析），返回成功解析条数。"""
        aps, _skipped = parser.parse_ap_records(records)
        for ap in aps:
            self.add(ap)
        return len(aps)

    def items(self):
        """返回 [(ApInfo, seen_count)] 列表（默认按 RSSI 降序）。"""
        items = list(self._aps.values())
        items.sort(key=lambda e: e[0].rssi, reverse=True)
        return items

    def aps(self, sort_by_rssi=True):
        """返回去重后的 ApInfo 列表。"""
        items = list(self._aps.values())
        if sort_by_rssi:
            items.sort(key=lambda e: e[0].rssi, reverse=True)
        return [e[0] for e in items]

    def top_aps(self, n):
        """按信号强度取前 n 个 AP。"""
        return self.aps(sort_by_rssi=True)[:n]

    def channel_stats(self):
        """信道统计：{channel: AP 数量}。"""
        stats = {}
        for ap in self.aps(sort_by_rssi=False):
            stats[ap.channel] = stats.get(ap.channel, 0) + 1
        return stats

    def __len__(self):
        return len(self._aps)


class ProbeCollector(object):
    """按 STA MAC 聚合的探测表（Probe Request）。"""

    def __init__(self):
        self._probes = {}  # sta_mac -> {"sta", "ssid", "rssi", "count"}

    def add_probe(self, sta_mac, ssid, rssi):
        """合并一条探测记录；广播探测（空 SSID）记 '<broadcast>'。"""
        ssid = ssid if ssid else "<broadcast>"
        key = sta_mac.lower()
        cur = self._probes.get(key)
        if cur is None:
            self._probes[key] = {"sta": key, "ssid": ssid,
                                 "rssi": rssi, "count": 1}
        else:
            cur["ssid"] = ssid
            cur["rssi"] = rssi
            cur["count"] += 1

    def probes(self):
        """返回聚合后的探测列表（按最近 RSSI 降序）。"""
        items = list(self._probes.values())
        items.sort(key=lambda p: p["rssi"], reverse=True)
        return items

    def __len__(self):
        return len(self._probes)
