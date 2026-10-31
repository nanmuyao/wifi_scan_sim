#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成含完整 WPA2 四次握手（EAPOL M1/M2/M3/M4，MIC 真实可校验）
与 CCMP 加密 QoS Data 帧（TK 加密，解密可还原 LLC/SNAP+IP）的 pcap 样本。

仅供自建实验网络研究学习（已知口令 / 自建网络，不做爆破）。

用法：python3 tools/make_wpa2_handshake_pcap.py
输出：tests/fixtures/wpa2_handshake.pcap
"""
import os
import struct
import sys

from scapy.all import RadioTap, Dot11, Dot11QoS, LLC, SNAP, Raw, wrpcap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
import wpa2_handshake as wh

BSSID = "aa:bb:cc:dd:ee:01"
CLIENT = "11:22:33:44:55:66"
PASSWORD = "password"
SSID = "IEEE"
ANONCE = wh.DEMO_ANONCE
SNONCE = wh.DEMO_SNONCE
KEYDATA_M3 = bytes.fromhex("de ad be ef 01 02 03 04")  # 加密的假 KeyData（仅长度验证）

# 加密数据帧固定输入：TID=5 上行（STA→AP），PN 递增
CCMP_TID = 5
CCMP_PN = b"\x00\x00\x00\x00\x00\x01"           # 6 字节大端（PN0 最高有效）
IP_SAMPLE = bytes.fromhex(
    "45 00 00 3c 00 01 00 00 40 06 00 00 "
    "c0 a8 01 64 c0 a8 01 01")                  # 20 字节 IPv4 头样例


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


def with_mic(eapol_frame, kck):
    """计算并填入真实 MIC（MIC 字段位于 EAPOL 头后 77 字节处）。"""
    mic = wh.compute_mic(kck, eapol_frame)
    return eapol_frame[:wh.KEY_MIC_OFFSET] + mic + eapol_frame[wh.KEY_MIC_OFFSET + 16:]


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


def dot11_ccmp_data(tk):
    """构造 CCMP 加密 QoS Data 帧（上行 STA→AP，明文=LLC/SNAP+IP）。

    nonce = 优先级(TID) ‖ A2(STA MAC) ‖ PN(13B)；
    AAD 由 MAC 头（含 QoS Control 26B）按规则屏蔽可变位得到。
    """
    bssid = bytes.fromhex(BSSID.replace(":", ""))
    client = bytes.fromhex(CLIENT.replace(":", ""))
    # FC=0x4188：QoS Data(subtype8) + type2 + ToDS(0x0100) + Protected(0x4000)
    mac_hdr = struct.pack("<H", 0x4188) + b"\x00\x00"
    mac_hdr += bssid + client + bssid
    mac_hdr += b"\x10\x00"                    # Seq Control：seq=1, frag=0
    mac_hdr += b"\x05\x00"                    # QoS Control：TID=5
    aad = wh.ccmp_build_aad(mac_hdr)
    plaintext = b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + IP_SAMPLE
    hdr, ct, mic = wh.ccmp_encrypt(tk, CCMP_TID, client, CCMP_PN,
                                   aad, plaintext)
    return RadioTap(dBm_AntSignal=-42) / Raw(mac_hdr + hdr + ct + mic), plaintext


def main():
    pmk = wh.derive_pmk(PASSWORD.encode("utf-8"), SSID.encode("utf-8"))
    bssid = bytes.fromhex(BSSID.replace(":", ""))
    client = bytes.fromhex(CLIENT.replace(":", ""))
    kck, kek, tk = wh.derive_ptk(pmk, bssid, client, ANONCE, SNONCE)

    out_dir = os.path.join(ROOT, "tests", "fixtures")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "wpa2_handshake.pcap")

    # M1: AP→STA  ACK=1 Secure=0 携带 ANonce（无 MIC）
    m1 = eapol_key(0x0082, 1, ANONCE, b"\x00" * 16)
    # M2: STA→AP  Secure=1 MIC=1 携带 SNonce + 真实 MIC
    m2 = with_mic(eapol_key(0x0302, 1, SNONCE, b"\x00" * 16), kck)
    # M3: AP→STA  ACK=1 Secure=1 MIC=1 KeyData 加密 + 真实 MIC
    m3 = with_mic(eapol_key(0x1382, 2, ANONCE, b"\x00" * 16, KEYDATA_M3), kck)
    # M4: STA→AP  Secure=1 MIC=1 Nonce 全零 + 真实 MIC
    m4 = with_mic(eapol_key(0x0302, 2, b"\x00" * 32, b"\x00" * 16), kck)

    frames = [dot11_data(m1, subtype=8), dot11_data(m2, subtype=8),
              dot11_data(m3, subtype=8), dot11_data(m4, subtype=8)]

    ccmp_frame, plaintext = dot11_ccmp_data(tk)
    frames.append(ccmp_frame)

    wrpcap(out, frames)
    print("已生成: %s（4 帧握手 + 1 帧 CCMP 加密 QoS Data）" % out)
    print("PMK  = %s" % pmk.hex())
    print("KCK  = %s" % kck.hex())
    print("KEK  = %s" % kek.hex())
    print("TK   = %s" % tk.hex())
    print("加密明文 = %s" % plaintext.hex())
    print("期望握手序号: 1,2,3,4（MIC 由 KCK 计算，可正向校验；改错口令不一致）")


if __name__ == "__main__":
    main()
