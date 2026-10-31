#!/usr/bin/env python3
"""生成一批 802.11 WiFi 包（含管理帧/加密数据帧/EAPOL 握手）并保存为 pcap，
供手写解析器 wifi_frame_parser.py 验证。仅用于自建实验网络研究学习。"""
from scapy.all import (Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
                       Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11Deauth,
                       Dot11Action, Dot11QoS, Dot11Elt, RadioTap, Raw, wrpcap)
from scapy.layers.l2 import LLC, SNAP
from scapy.layers.eap import EAPOL

BSSID = "aa:bb:cc:dd:ee:01"
CLIENT = "11:22:33:44:55:66"

frames = []

# 1) Beacon：实验 AP LabNet，信道 6，WPA2-PSK
frames.append(RadioTap(dBm_AntSignal=-42) /
              Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=BSSID, addr3=BSSID) /
              Dot11Beacon(beacon_interval=0x0064, cap=0x2111) /
              Dot11Elt(ID=0, info=b"LabNet") /
              Dot11Elt(ID=3, info=b"\x06") /
              Dot11Elt(ID=48, info=b"\x00\x00\x00\x00"))

# 2) Probe Request：客户端探测 LabNet
frames.append(RadioTap(dBm_AntSignal=-55) /
              Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2=CLIENT, addr3="ff:ff:ff:ff:ff:ff") /
              Dot11ProbeReq() /
              Dot11Elt(ID=0, info=b"LabNet"))

# 3) Probe Response
frames.append(RadioTap(dBm_AntSignal=-42) /
              Dot11(type=0, subtype=5, addr1=CLIENT, addr2=BSSID, addr3=BSSID) /
              Dot11ProbeResp(beacon_interval=0x0064, cap=0x2111) /
              Dot11Elt(ID=0, info=b"LabNet"))

# 4) Authentication（Open System）
frames.append(RadioTap(dBm_AntSignal=-55) /
              Dot11(type=0, subtype=11, addr1=BSSID, addr2=CLIENT, addr3=BSSID) /
              Dot11Auth(algo=0, seqnum=1, status=0))

# 5) Association Request
frames.append(RadioTap(dBm_AntSignal=-55) /
              Dot11(type=0, subtype=0, addr1=BSSID, addr2=CLIENT, addr3=BSSID) /
              Dot11AssoReq(cap=0x2111, listen_interval=10) /
              Dot11Elt(ID=0, info=b"LabNet"))

# 6) Association Response
frames.append(RadioTap(dBm_AntSignal=-42) /
              Dot11(type=0, subtype=1, addr1=CLIENT, addr2=BSSID, addr3=BSSID) /
              Dot11AssoResp(cap=0x2111, status=0, AID=0xC000))

# 7) EAPOL M1（四步握手第一帧，明文：AP -> STA 携带 ANonce）
frames.append(RadioTap(dBm_AntSignal=-42) /
              Dot11(type=2, subtype=0, proto=0, addr1=CLIENT, addr2=BSSID, addr3=BSSID) /
              LLC(dsap=0x88, ssap=0x88, ctrl=3) /
              SNAP(OUI=0, code=0x888e) /
              EAPOL(version=2, type=3) /
              Raw(bytes.fromhex(
                  "0203007502010a00000000000000000000000000000000" +
                  "5d1e8a1f2c3b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e" +
                  "000000000000000000000000000000000000000000000000" +
                  "000000000000000000000000000000000000000000000000" +
                  "0000000000000000000000000000")))

# 8) WPA2 加密数据帧（QoS Data，protected=1，CCMP 假密文，上行）
frames.append(RadioTap(dBm_AntSignal=-58) /
              Dot11(type=2, subtype=8, FCfield=0x41, addr1=BSSID, addr2=CLIENT, addr3=BSSID) /
              Dot11QoS(TID=0) /
              Raw(bytes.fromhex("aabbccddeeff00112233445566778899" +
                                "aabbccddeeff00112233445566778899")))
# 下行：AP -> 客户端
frames.append(RadioTap(dBm_AntSignal=-42) /
              Dot11(type=2, subtype=8, FCfield=0x41, addr1=CLIENT, addr2=BSSID, addr3=BSSID) /
              Dot11QoS(TID=5) /
              Raw(bytes.fromhex("00112233445566778899aabbccddeeff" +
                                "00112233445566778899aabbccddeeff")))

# 9) Deauthentication（reason=7：STA 离开）
frames.append(RadioTap(dBm_AntSignal=-55) /
              Dot11(type=0, subtype=12, addr1=BSSID, addr2=CLIENT, addr3=BSSID) /
              Dot11Deauth(reason=7))

# 10) Action（类别 7：频谱管理）
frames.append(RadioTap(dBm_AntSignal=-50) /
              Dot11(type=0, subtype=13, addr1=BSSID, addr2=CLIENT, addr3=BSSID) /
              Dot11Action() /
              Raw(b"\x07\x01\x02"))

out = "/Users/Paul/Library/Application Support/com.tencent.mac.marvis/MarvisData/User/oAN1i2ejv5WYgqR2t_qD7u2-bH4Y/workspace/conv_b09aa01adb1f40638b95eb8d9dca0a79/temp/wifi_demo_parse.pcap"
wrpcap(out, frames)
print(f"[+] wrote {len(frames)} frames -> {out}")
