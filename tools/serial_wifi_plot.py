#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
serial_wifi_plot.py —— STM32 WiFi 扫描结果实时绘图
====================================================
读取 STM32 USART2 输出的扫描行（格式与 stm32_project 的 print_aps 一致）：

    [00] ch=6  rssi=-52 enc=3 ssid=Paul-Home-2.4G

实时绘制两张图：
  左：2.4GHz 信道占用热力图（信道 x 扫描轮次 x RSSI 颜色）
  右：各 SSID 的 RSSI 随时间变化曲线

用法：
  pip install pyserial matplotlib
  python3 serial_wifi_plot.py --port /dev/tty.usbserial-XXXX --baud 115200 --rounds 30
  （Ctrl+C 结束，自动保存 wifi_scan_plot.png）

依赖：pyserial, matplotlib
"""
import argparse
import re
import sys
import time

import matplotlib.pyplot as plt
import serial

LINE_RE = re.compile(r"^\[\d+\]\s+ch=(\d+)\s+rssi=(-?\d+)\s+enc=(\d+)\s+ssid=(.*?)\s*$")


def parse_line(line):
    """解析一行扫描结果，返回 (channel, rssi, enc, ssid) 或 None。"""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)


def main():
    ap = argparse.ArgumentParser(description="STM32 WiFi 扫描实时绘图")
    ap.add_argument("--port", required=True, help="串口设备，如 /dev/tty.usbserial-XXXX")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--rounds", type=int, default=30, help="最多采集多少轮扫描")
    args = ap.parse_args()

    ser = serial.Serial(args.port, args.baud, timeout=1)
    print("打开串口 %s @ %d，等待扫描数据（Ctrl+C 结束）..." % (args.port, args.baud))

    # 数据容器
    scans = []           # 每轮: {(ch, ssid): rssi}
    all_ssids = set()
    times = []           # 每轮时间戳

    plt.ion()
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
    fig.canvas.manager.set_window_title("WiFi Scan Monitor")

    cur = {}
    last_scan_idx = -1
    try:
        while len(scans) < args.rounds:
            line = ser.readline().decode("utf-8", "replace")
            if not line:
                continue
            # 每轮扫描由 "--- scan ---" 分隔
            if "--- scan ---" in line:
                if cur and len(scans) != last_scan_idx:
                    scans.append(cur)
                    times.append(time.time())
                    last_scan_idx = len(scans)
                    print("第 %d 轮: %d 个 AP" % (len(scans), len(cur)))
                cur = {}
                continue
            r = parse_line(line)
            if r:
                ch, rssi, enc, ssid = r
                cur[(ch, ssid)] = rssi
                all_ssids.add(ssid)

            # 每轮结束后刷新画面
            if scans and len(scans) != len(times):
                scans.append(cur)
                times.append(time.time())
                last_scan_idx = len(scans)
            if not scans:
                continue

            # 左图：信道热力图
            ax1.clear()
            channels = sorted({ch for (ch, _), _ in scans[-1].items()} | {ch for ch in range(1, 14)})
            matrix = []
            x_labels = []
            for (ch, ssid), rssi in sorted(scans[-1].items(), key=lambda kv: kv[0][0]):
                matrix.append(rssi)
                x_labels.append("ch%d\n%s" % (ch, ssid[:8]))
            if matrix:
                im = ax1.imshow([matrix], aspect="auto", cmap="RdYlGn",
                                vmin=-90, vmax=-30, extent=[0, len(matrix), 0, 1])
                ax1.set_xticks(range(len(matrix)))
                ax1.set_xticklabels(x_labels, fontsize=7)
                ax1.set_yticks([])
                ax1.set_title("信道 RSSI（最近一轮）")
                fig.colorbar(im, ax=ax1, fraction=0.04, pad=0.03)

            # 右图：各 SSID RSSI 时间曲线
            ax2.clear()
            for ssid in sorted(all_ssids):
                xs, ys = [], []
                for i, s in enumerate(scans):
                    for (ch, s2), rssi in s.items():
                        if s2 == ssid:
                            xs.append(i)
                            ys.append(rssi)
                if xs:
                    ax2.plot(xs, ys, marker="o", markersize=3, label=ssid[:16])
            ax2.set_xlabel("扫描轮次")
            ax2.set_ylabel("RSSI (dBm)")
            ax2.set_title("RSSI 时间曲线")
            ax2.legend(fontsize=7, loc="best")
            ax2.grid(alpha=0.3)

            plt.draw()
            plt.pause(0.05)
    except KeyboardInterrupt:
        print("\n手动结束")
    finally:
        plt.ioff()
        fig.savefig("wifi_scan_plot.png", dpi=120)
        print("已保存 wifi_scan_plot.png（%d 轮）" % len(scans))
        ser.close()


if __name__ == "__main__":
    main()
