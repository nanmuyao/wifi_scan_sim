#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""eapol.parse / message_number / zero_mic，以及 frames80211 的帧迭代（手工拼的帧）。真实帧由 tests/oracle/test_eapol_diff.py 对照 tshark。"""
import os
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "oracle"))
from wifi80211 import eapol  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
import synth  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def key_frame(ki, desc=2, nonce=b"", mic_len=16, mic=None, data=b"", replay=1, key_len=16, rsc=bytes(8), kid=bytes(8), iv=bytes(16), version=2):
    body = bytes([desc]) + struct.pack(">HHQ", ki, key_len, replay) + (nonce or bytes(32)).ljust(32, b"\x00") + iv + rsc + kid
    body += (mic if mic is not None else bytes(mic_len)) + struct.pack(">H", len(data)) + data
    return bytes([version, 3]) + struct.pack(">H", len(body)) + body


print("== 字段（全部大端）==")
n = bytes(range(32))
e = eapol.parse(key_frame(0x008a, nonce=n, replay=0x0102030405060708, key_len=16, rsc=b"\x01" * 8, kid=b"\x02" * 8, iv=b"\x03" * 16))
check((e["version"], e["type"], e["descriptor"], e["key_length"], e["replay_counter"]) == (2, 3, 2, 16, 0x0102030405060708), "版本 2、类型 3、描述符 2、Key Length 16、Replay Counter 按大端")
check(e["nonce"] == n and e["iv"] == b"\x03" * 16 and e["rsc"] == b"\x01" * 8 and e["key_id"] == b"\x02" * 8 and e["mic"] == bytes(16) and e["data"] == b"", "Nonce / IV / RSC / Key ID / MIC / 空 Key Data 的位置")
check(e["key_info"]["raw"] == 0x008a and e["length"] == 95 and not e["truncated"] and e["mic_len"] == 16, "Key Info 按大端读（00 8a -> 0x008a），长度 95")
check(eapol.parse(key_frame(0x1234 & 0xFFFF))["key_info"]["raw"] == 0x1234, "Key Info 的两个字节没有颠倒（0x1234）")
e = eapol.parse(key_frame(0x0102, data=b"abc", replay=0x0100))
check(e["replay_counter"] == 0x0100 and e["data_length"] == 3 and e["data"] == b"abc", "Replay Counter 0x0100（不是 0x00010000…）；Key Data 3 字节")

print("== Key Info 的位 ==")
for name, bit in (("pairwise", 0x0008), ("install", 0x0040), ("ack", 0x0080), ("mic", 0x0100), ("secure", 0x0200), ("error", 0x0400),
                  ("request", 0x0800), ("encrypted", 0x1000), ("smk", 0x2000)):
    k = eapol.key_info(bit)
    others = [x for x in ("pairwise", "install", "ack", "mic", "secure", "error", "request", "encrypted", "smk") if x != name and k[x]]
    check(k[name] is True and not others, "0x%04x 只置 %s" % (bit, name))
check(eapol.key_info(0x0003)["version"] == 3 and eapol.key_info(0x0030)["index"] == 3 and eapol.key_info(0x0010)["index"] == 1, "版本是 bit0-2；密钥序号是 bit4-5")
check(eapol.key_info(0x008a)["version"] == 2 and eapol.key_info(0x0088)["version"] == 0 and eapol.key_info(0x0089)["version"] == 1, "0x008a / 0x0088 / 0x0089 = 版本 2 / 0 / 1")

print("== 握手消息号 ==")
M = lambda ki, nonce=b"\x01" * 32: eapol.parse(key_frame(ki, nonce=nonce))["message"]       # noqa: E731
check(M(0x008a) == 1 and M(0x13ca) == 3 and M(0x010a) == 2 and M(0x030a) == 4, "WPA2：0x008a = M1，0x13ca = M3，0x010a = M2，0x030a = M4")
check(M(0x0088) == 1 and M(0x13c8) == 3 and M(0x0108) == 2 and M(0x0308) == 4, "版本 0（AKM 决定）：同样的位型")
check(M(0x010a, nonce=bytes(32)) == 4 and M(0x010a) == 2, "无 Ack、有 MIC、非 Secure：Nonce 全 0 是 M4（WPA1 的 M4 没有 Secure 位），非 0 是 M2")
check(M(0x030a, nonce=bytes(32)) == 4 and M(0x030a, nonce=b"\x01" * 32) == 4, "带 Secure 位、Key Data 为空就是 M4，不看 Nonce")
MD = lambda ki, nonce, data: eapol.parse(key_frame(ki, nonce=nonce, data=data))["message"]       # noqa: E731
check(MD(0x030a, b"\x01" * 32, b"\x30\x14" + bytes(20)) == 2, "重新握手的 M2：带 Secure 位，但有 SNonce 和 Key Data（RSN 元素）= M2")
check(MD(0x030a, bytes(32), b"\x30\x14" + bytes(20)) == 4 and MD(0x030a, b"\x01" * 32, b"") == 4, "Nonce 全 0 或 Key Data 为空，仍是 M4")
check(M(0x018a) == 3 and M(0x01ca) == 3, "成对 + Ack + MIC 就是 M3，不要求 Install 位（有没有都是）")
check(eapol.parse(key_frame(0x0080))["message"] is None and eapol.parse(key_frame(0x0280))["message"] is None, "组消息：只有 Ack 没有 MIC，不是 G1")
check(eapol.parse(key_frame(0x1382))["message"] == "G1", "组密钥握手：成对位为 0、Ack + MIC = G1")
check(eapol.parse(key_frame(0x0302))["message"] == "G2", "成对位为 0、MIC 无 Ack = G2")
check(eapol.parse(key_frame(0x0008))["message"] is None and eapol.parse(key_frame(0x0000))["message"] is None, "认不出的位型：None")

print("== MIC 长度 ==")
for m in (16, 24, 32):
    e = eapol.parse(key_frame(0x010a, nonce=n, mic_len=m, mic=bytes(range(1, m + 1)), data=b"d" * 22))
    check(e["mic_len"] == m and e["mic"] == bytes(range(1, m + 1)) and e["data"] == b"d" * 22 and e["data_length"] == 22, "MIC %d 字节：由长度关系推出，MIC 与 Key Data 的位置对" % m)
frame = key_frame(0x0088, mic_len=24, data=b"x" * 22)
check(eapol.parse(frame, mic_len=24)["mic_len"] == 24 and eapol.parse(frame, mic_len=16)["mic_len"] == 16, "显式给定 mic_len 就按它解（认证方式决定）")
incons = bytearray(key_frame(0x0088, mic_len=24, data=b""))
incons += b"\x00" * 22
incons[2:4] = struct.pack(">H", len(incons) - 4)
check(eapol.parse(bytes(incons))["mic_len"] == 16 and eapol.parse(bytes(incons), mic_len=24)["mic_len"] == 24 and eapol.parse(bytes(incons), mic_len=24)["data_length"] == 0,
      "Key Data Length 写 0 但尾部多出字节（真实抓包里有）：长度关系推不出，退回 16；给定 24 就对")

# 长度关系对 16 和 24 都吻合的帧：取最短的（16）
amb_data = bytearray(40)
amb_data[6:8] = struct.pack(">H", 40 - 8)            # 假如 MIC 是 24 字节，Key Data Length 字段落在这里，值 = 32，与总长度吻合
amb = eapol.parse(key_frame(0x010a, nonce=n, data=bytes(amb_data)))
check(amb["mic_len"] == 16 and amb["data_length"] == 40, "16 和 24 都自洽的帧：取最短的 16（长度关系有歧义时的约定）")
check(eapol.parse(key_frame(0x010a, nonce=n, data=bytes(amb_data)), mic_len=24)["mic_len"] == 24, "歧义时显式给定 24 就按 24")
check(eapol.parse(bytes(incons), mic_len=24)["data"] == b"", "声明的 Key Data 长度之外的尾部字节不进 data（长度 0 就是空）")

print("== 残缺与不是 Key ==")
check(eapol.parse(bytes([2, 0, 0, 5, 1, 2, 3, 4, 5])) is None and eapol.parse(bytes([2, 1, 0, 0])) is None and eapol.parse(b"\x02") is None, "EAPOL-Packet / Start / 太短：None")
frame = key_frame(0x008a, data=b"hello")
e = eapol.parse(frame[:-3])
check(e["truncated"] and e["data_length"] == 5 and e["data"] == b"he", "Key Data 被截断：truncated，data 取到哪算哪，声明长度保留")
e = eapol.parse(frame[:50])
check(e["truncated"] and "key_info" not in e, "连固定部分都不全：truncated，只有 EAPOL 头的字段")
e = eapol.parse(frame[:4 + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8 + 5])
check(e["truncated"] and e["mic"] == bytes(5) and e["data"] == b"", "MIC 之后连 Key Data Length 都没有")
check(eapol.parse(frame + b"extra")["data"] == b"hello" and not eapol.parse(frame + b"extra")["truncated"], "报文后面多出的字节（以太网填充）忽略")

print("== zero_mic ==")
m16 = bytes(range(1, 17))
f1 = key_frame(0x010a, nonce=n, mic=m16, data=b"data")
z = eapol.zero_mic(f1, 16)
check(len(z) == len(f1) and z[:81] == f1[:81] and z[81:97] == bytes(16) and z[97:] == f1[97:], "只清零 MIC 的 16 字节，其余不变（MIC 在偏移 81）")
f2 = key_frame(0x0108, nonce=n, mic_len=24, mic=bytes(range(1, 25)), data=b"data")
z = eapol.zero_mic(f2, 24)
check(z[81:105] == bytes(24) and z[105:] == f2[105:] and eapol.parse(z, mic_len=24)["data"] == b"data", "MIC 24 字节同理")

print("== 帧迭代 / EAPOL 提取（链路类型 105，无 radiotap）==")
EK = key_frame(0x008a, nonce=n)
llc = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
pk = [synth.frame(2, 0, 0, 1, body=llc + EK), synth.frame(2, 8, 1, 0, qos=0, body=llc + EK), synth.frame(2, 0, 0, 1, prot=1, body=llc + EK),
      synth.frame(2, 0, 0, 1, body=b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + EK), synth.frame(0, 8, body=b"\x00" * 20), b"\x00"]
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "t.pcap")
    synth.write_pcap(path, pk)
    frames = list(fr.iter_frames(path))
    check([f.n for f in frames] == [1, 2, 3, 4, 5], "帧号从 1 起；放不进 MAC 头的垃圾帧（1 字节）跳过，帧号不错位")
    got = [fr.eapol_payload(f) for f in frames]
    check(got[0] == EK and got[1] == EK, "未加密数据帧里 LLC/SNAP + 0x888e 之后的 EAPOL；QoS 数据帧同样（头长度含 QoS 控制字段）")
    check(got[2] is None and got[3] is None and got[4] is None, "受保护的帧、以太类型不是 0x888e、管理帧：None")
    check(frames[0].body == llc + EK and frames[0].fcs_ok is None, "body 是 MAC 头之后的字节；没有 FCS 时 fcs_ok 是 None")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
