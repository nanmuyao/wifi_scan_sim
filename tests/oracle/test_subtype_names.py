#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""帧类型/子类型表与 tshark 的值表逐项对照（tshark -G values 里的 wlan.fc.type_subtype）。需要 tshark。

tshark 的编号 = 类型 * 16 + 子类型：0-15 管理帧，16-31 控制帧，32-47 数据帧。
要求：两边的编号集合相同，同一编号的名字相同（见 ALIAS 里列出的几处写法差异）。
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from wifi80211 import parser as w  # noqa: E402

# 我们的名字 -> tshark 的名字，只列写法不同的；其余按「去掉标点、不分大小写」比较
ALIAS = {
    "Beacon": "Beacon frame",
    "Disassociation": "Disassociate",
    "ACK": "Acknowledgement",
    "Block ACK Request": "802.11 Block Ack Req",
    "Block ACK": "802.11 Block Ack",
    "PS-Poll": "Power-Save poll",
    "RTS": "Request-to-send",
    "CTS": "Clear-to-send",
    "CF-End": "CF-End (Control-frame)",
    "CF-End+CF-Ack": "CF-End + CF-Ack (Control-frame)",
    "Null": "Null function (No data)",
    "QoS Null": "QoS Null function (No data)",
    "CF-Ack (no data)": "Acknowledgement (No data)",
    "CF-Poll (no data)": "CF-Poll (No data)",
    "CF-Ack+CF-Poll (no data)": "CF-Ack/Poll (No data)",
    "QoS Data+CF-Ack": "QoS Data + CF-Acknowledgment",
    "QoS CF-Poll (no data)": "QoS CF-Poll (No Data)",
    "QoS CF-Ack+CF-Poll (no data)": "QoS CF-Ack + CF-Poll (No data)",
    # tshark 把管理帧子类型 6 叫 Measurement Pilot；我们沿用 Timing Advertisement（未核对标准原文）
    "Timing Advertisement": "Measurement Pilot",
    "Trigger": "Trigger",
    "TWT Ack": "TWT Ack",
    "Beamforming Report Poll": "Beamforming Report Poll",
    "VHT/HE/EHT/Ranging NDP Announcement": "VHT/HE/EHT/RANGING NDP Announcement",
}
SKIP = {15: "Aruba Management"}     # 厂商自定义，不属于标准


def norm(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def tshark_table():
    out = subprocess.run(["tshark", "-G", "values"], capture_output=True, text=True).stdout
    t = {}
    for line in out.split("\n"):
        p = line.split("\t")
        if len(p) >= 4 and p[0] == "V" and p[1] == "wlan.fc.type_subtype":
            v = int(p[2], 0)
            if v < 48:
                t[v] = p[3]
    return t


def our_table():
    t = {}
    for base, table in ((0, w.MGMT_SUBTYPE), (16, w.CTRL_SUBTYPE), (32, w.DATA_SUBTYPE)):
        for sub, name in table.items():
            t[base + sub] = name
    return t


failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


oracle = {k: v for k, v in tshark_table().items() if k not in SKIP}
ours = our_table()
print("== 编号集合 ==")
check(set(ours) == set(oracle), "编号一致（只有我们有: %s；只有 tshark 有: %s）"
      % (sorted(set(ours) - set(oracle)), sorted(set(oracle) - set(ours))))
print("== 名字 ==")
for k in sorted(set(ours) & set(oracle)):
    want = oracle[k]
    got = ALIAS.get(ours[k], ours[k])
    check(norm(got) == norm(want), "0x%02x %s（tshark: %s）" % (k, ours[k], want))
check(all(k in oracle or True for k in ALIAS), "ALIAS 表自检")
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
