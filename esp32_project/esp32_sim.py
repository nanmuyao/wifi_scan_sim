#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esp32_sim.py —— ESP32 版 M1-M3 的 PC 仿真演示（阶段9，无硬件）

模拟 ESP-IDF `esp_wifi_scan_start()` / `esp_wifi_scan_get_ap_records()` 返回的
多轮扫描记录，走通「直扫 → 解析 → 聚合 → 上报」全链路：
  - 每轮按 2.4GHz 信道轮转（1/6/11）返回一批 AP 记录
    （含隐藏 SSID、全 NUL SSID、同 BSSID 重复观测等边界）
  - M1 esp32_ap_parser 解析成 ApInfo
  - M2 esp32_collector 按 BSSID 去重聚合（含探测表）
  - M3 esp32_reporter 输出串口文本 + WebSocket JSON 快照

用法：
  python3 esp32_sim.py             # stdout 演示（串口格式 + JSON 快照）
  python3 esp32_sim.py --json-only # 只输出 JSON 快照（WebSocket 通道仿真）
  python3 esp32_sim.py --pty       # 创建 pty 虚拟串口，写入 +SNIFF 文本

纯标准库实现，无第三方依赖。
"""

import argparse
import os
import pty
import sys
import time

import esp32_ap_parser as parser
from esp32_collector import ApCollector, ProbeCollector
import esp32_reporter as reporter


def scan_round(round_no, channel):
    """模拟 ESP-IDF 一次扫描返回的 AP 记录（字典字段对齐 wifi_ap_record_t）。"""
    records = [
        {"ssid": "Paul-Home-2.4G", "bssid": "aa:bb:cc:dd:ee:01",
         "rssi": -45 - round_no, "channel": channel, "authmode": 3},
        {"ssid": b"Neighbor-WiFi", "bssid": "aa:bb:cc:dd:ee:02",
         "rssi": -58 - round_no, "channel": channel, "authmode": 4},
        {"ssid": "", "bssid": "aa:bb:cc:dd:ee:03",
         "rssi": -70 - round_no, "channel": channel, "authmode": 0},   # 隐藏 SSID（空串）
        {"ssid": b"\x00\x00\x00", "bssid": "aa:bb:cc:dd:ee:04",
         "rssi": -66 - round_no, "channel": 1, "authmode": 3},        # 全 NUL 视为隐藏
        {"ssid": "Paul-Home-2.4G", "bssid": "aa:bb:cc:dd:ee:01",
         "rssi": -41 - round_no, "channel": channel, "authmode": 3},  # 同 BSSID 重复观测
    ]
    if round_no >= 1:  # 第二轮起出现新 AP（模拟环境中新出现的网络）
        records.append({"ssid": "Lab-IoT", "bssid": "aa:bb:cc:dd:ee:05",
                        "rssi": -50 - round_no, "channel": 11, "authmode": 6})
    return records


def demo_probes():
    """预置探测记录：一条广播探测（空 SSID）+ 一条定向探测。"""
    return [
        ("11:22:33:44:55:66", "", -61),          # 广播探测
        ("11:22:33:44:55:66", "Paul-Home-2.4G", -59),  # 同 STA 定向探测
        ("aa:aa:bb:bb:cc:cc", "Neighbor-WiFi", -72),
    ]


def run_stdout():
    ap_col = ApCollector()
    probe_col = ProbeCollector()

    print("== ESP32 M1-M3 仿真演示（构造输入，无硬件）==")
    for round_no in range(3):
        channel = (1, 6, 11)[round_no % 3]
        records = scan_round(round_no, channel)

        # M1 解析
        aps, skipped = parser.parse_ap_records(records)
        print("\n[scan] round=%d channel=%d 记录=%d 解析=%d 跳过=%d" % (
            round_no + 1, channel, len(records), len(aps), skipped))

        # M2 聚合
        ap_col.add_records(records)
        for probe in demo_probes():
            probe_col.add_probe(*probe)

        # M3 串口上报（模拟固件逐条打印）
        for ap in aps:
            print(reporter.format_serial_ap(ap))
        for p in probe_col.probes():
            print(reporter.format_serial_probe(p["sta"], p["ssid"], p["rssi"]))

    # 聚合结果
    print("\n== 聚合结果（按 RSSI 降序，去重后 %d 个 AP）==" % len(ap_col))
    for ap, cnt in ap_col.items():
        print("  %s x%d  %s" % (reporter.format_serial_ap(ap), cnt, ap))
    print("  信道统计:", ap_col.channel_stats())

    # M3 WebSocket JSON 快照
    print("\n== WebSocket JSON 快照 ==")
    print(reporter.dump_json_snapshot(
        ap_col.items(), probe_col.probes(), channel=6))


def run_json_only():
    ap_col = ApCollector()
    probe_col = ProbeCollector()
    for round_no in range(3):
        channel = (1, 6, 11)[round_no % 3]
        ap_col.add_records(scan_round(round_no, channel))
    for probe in demo_probes():
        probe_col.add_probe(*probe)
    print(reporter.dump_json_snapshot(
        ap_col.items(), probe_col.probes(), channel=6))


def run_pty():
    """创建 pty 虚拟串口，写入 +SNIFF 串口文本（对齐 esp8266_sim.py 思路）。"""
    master_fd, slave_fd = pty.openpty()
    print("pty 虚拟串口: /dev/ttys%d" % os.ttyname(slave_fd).rsplit("/", 1)[-1].replace("ttys", ""))
    print("（写入 +SNIFF 文本 2 秒，可用串口工具连接读取）")
    ap_col = ApCollector()
    for round_no in range(3):
        channel = (1, 6, 11)[round_no % 3]
        aps, _ = parser.parse_ap_records(scan_round(round_no, channel))
        ap_col.add_records([vars_less(a) for a in aps])
        for ap in aps:
            os.write(master_fd, (reporter.format_serial_ap(ap) + "\r\n").encode())
        time.sleep(0.5)
    time.sleep(2)
    os.close(master_fd)
    os.close(slave_fd)


def vars_less(ap):
    """把 ApInfo 还原成记录字典（仅供 pty 演示内部使用）。"""
    return {"ssid": ap.ssid, "bssid": ap.bssid, "rssi": ap.rssi,
            "channel": ap.channel, "authmode": ap.authmode}


def main():
    argp = argparse.ArgumentParser(description="ESP32 M1-M3 PC 仿真演示")
    argp.add_argument("--json-only", action="store_true", help="只输出 JSON 快照")
    argp.add_argument("--pty", action="store_true", help="写入 pty 虚拟串口")
    args = argp.parse_args()

    if args.pty:
        run_pty()
    elif args.json_only:
        run_json_only()
    else:
        run_stdout()
    return 0


if __name__ == "__main__":
    sys.exit(main())
