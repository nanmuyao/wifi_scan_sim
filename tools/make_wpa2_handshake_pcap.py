#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成含完整 WPA2 四次握手（EAPOL M1/M2/M3/M4）的 pcap 样本，
供 wpa2_handshake.py 解析验证。仅用于自建实验网络研究学习。

用法：python3 tools/make_wpa2_handshake_pcap.py
输出：tests/fixtures/wpa2_handshake.pcap
"""
import os
import sys
from scapy.all import (RadioTap, Dot11, Dot11QoS, LLC, SNAP,
                       Raw, wrpcap)

BSSID = "aa:bb:cc:dd:ee:01"
CLIENT = "11:22:33:44:55:66"
ANONCE = bytes.fromhex(
    "5d1e8a1f2c3b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6")
SNONCE = bytes.fromhex(
    "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f809")
MIC_M2 = bytes.fromhex("00112233445566778899aabbccddeeff")
MIC_M3 = bytes.fromhex("ffeeddccbbaa99887766554433221100")
MIC_M4 = bytes.fromhex("102030405060708090a0b0c0d0e0f001")
KEYDATA_M3 = bytes.fromhex("de ad be ef 01 02 03 04")  # 加密的假 KeyData（仅长度验证）


def eapol_key(key_info, replay, nonce, mic, key_data=b""):
    """构造 EAPOL-Key 帧体（Descriptor Type=2，WPA2 pairwise）。"""
    desc = b"\x02"                       # Key Descriptor Version/Type
    desc += key_info.to_bytes(2, "little")
    desc += (16).to_bytes(2, "little")   # Key Length（TKIP/CCMP=16）
    desc += replay.to_bytes(8, "little")
    desc += nonce                         # 32B
    desc += b"\x00" * 16                 # Key IV
    desc += b"\x00" * 8                  # Key RSC
    desc += b"\x00" * 8                  # Key ID
    desc += mic                           # 16B
    desc += len(key_data).to_bytes(2, "little")
    desc += key_data
    # EAPOL 头（version=2, type=3=EAPOL-Key）+ Key Descriptor；
    # 注意不要用 scapy 的 EAPOL 层拼接（会重复插入 EAPOL 头），直接 Raw 输出完整帧体
    return b"\x02\x03" + len(desc).to_bytes(2, "little") + desc


def dot11_data(payload, subtype=0):
    """802.11 QoS Data 帧（带 LLC/SNAP + EAPOL 载荷）。subtype 0=普通 Data，8=QoS Data。"""
    qos = Dot11QoS(TID=0) if subtype in (8, 9, 10, 12, 13, 14) else b""
    return (RadioTap(dBm_AntSignal=-42) /
            Dot11(type=2, subtype=subtype,
                  addr1=CLIENT, addr2=BSSID, addr3=BSSID) /
            qos /
            LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
            SNAP(OUI=0, code=0x888e) /
            Raw(payload))


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(root, "tests", "fixtures")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "wpa2_handshake.pcap")

    # M1: AP→STA  ACK=1 Secure=0 携带 ANonce
    m1 = eapol_key(0x0082, 1, ANONCE, b"\x00" * 16)
    # M2: STA→AP  Secure=1 MIC=1 携带 SNonce + MIC
    m2 = eapol_key(0x0302, 1, SNONCE, MIC_M2)
    # M3: AP→STA  ACK=1 Secure=1 MIC=1 KeyData 加密
    m3 = eapol_key(0x1382, 2, ANONCE, MIC_M3, KEYDATA_M3)
    # M4: STA→AP  Secure=1 MIC=1 Nonce 全零
    m4 = eapol_key(0x0302, 2, b"\x00" * 32, MIC_M4)

    frames = [dot11_data(m1, subtype=8), dot11_data(m2, subtype=8),
              dot11_data(m3, subtype=8), dot11_data(m4, subtype=8)]
    wrpcap(out, frames)
    print("已生成: %s（4 帧：M1/M2/M3/M4）" % out)
    print("期望握手序号: 1,2,3,4")


if __name__ == "__main__":
    main()
