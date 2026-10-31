#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wpa2_handshake 单元测试：
- 4.1.1 PMK 推导：802.11i 标准向量（password / IEEE）
- 4.1.2 EAPOL 解析：手工构造 M1~M4 验证字段与握手区分
- pcap fixture：tests/fixtures/wpa2_handshake.pcap 全链路验证
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import wpa2_handshake as wh

ANONCE = bytes.fromhex("5d1e8a1f2c3b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6")
SNONCE = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f809")


def build_eapol_key(key_info, replay=1, nonce=b"\x00" * 32,
                    mic=b"\x00" * 16, key_data=b"", desc_type=2):
    body = bytes([desc_type]) + struct.pack("<H", key_info)
    body += struct.pack("<H", 16)
    body += struct.pack("<Q", replay)
    body += nonce + b"\x00" * 16 + b"\x00" * 8 + b"\x00" * 8 + mic
    body += struct.pack("<H", len(key_data)) + key_data
    return b"\x01\x03" + struct.pack("<H", len(body)) + body


def build_dot11_data(eapol, subtype=8):
    fc = struct.pack("<H", 0x0008 | (subtype << 4))  # Data, 无保护位
    hdr = fc + b"\x00" * 2 + b"\x02" * 6 + b"\x01" * 6 + b"\x03" * 6 + b"\x00\x00"
    qos = b"\x00\x00" if subtype in (8, 9, 10, 12, 13, 14) else b""
    llc_snap = b"\xaa\xaa\x03\x00\x00\x00" + b"\x88\x8e"
    return hdr + qos + llc_snap + eapol


FAIL_COUNT = [0]


def t(name, cond, extra=""):
    if not cond:
        FAIL_COUNT[0] += 1
        print("  [FAIL] %s %s" % (name, extra))
        return False
    print("  [PASS] %s" % name)
    return True


def main():
    del FAIL_COUNT[:]

    # ---- 4.1.1 PMK ----
    print("[4.1.1] PMK 推导（PBKDF2-HMAC-SHA1）")
    pmk = wh.derive_pmk(b"password", b"IEEE")
    t("password/IEEE == 802.11i 标准向量",
      pmk.hex() == wh.PMK_STD_VECTOR, pmk.hex())
    pmk2 = wh.derive_pmk(b"password", b"OtherSSID")
    t("不同 SSID 产生不同 PMK", pmk2 != pmk)
    pmk3 = wh.derive_pmk(b"diffpass", b"IEEE")
    t("不同口令产生不同 PMK", pmk3 != pmk)

    # ---- 4.1.2 单帧解析 ----
    print("[4.1.2] EAPOL-Key 解析（手工构造帧）")
    m1 = build_eapol_key(0x0082, 1, ANONCE)
    e = wh.parse_eapol_key(m1)
    t("M1 解析：descriptor_type=2, type=EAPOL-Key",
      e.get("descriptor_type") == 2 and e.get("type") == 3)
    t("M1 Key Info：ACK=1 Secure=0", e["key_info"]["ack"] and not e["key_info"]["secure"])
    t("M1 ANonce 提取一致", e["nonce"] == ANONCE)
    t("M1 MIC 为空", e["key_mic"] == b"\x00" * 16)
    t("M1 握手序号=1", wh.classify_handshake(e) == 1)

    m2 = build_eapol_key(0x0302, 1, SNONCE, mic=b"\x10" * 16)
    e = wh.parse_eapol_key(m2)
    t("M2 Key Info：Secure=1 ACK=0 MIC=1",
      e["key_info"]["secure"] and not e["key_info"]["ack"] and e["key_info"]["mic"])
    t("M2 SNonce 提取一致", e["nonce"] == SNONCE)
    t("M2 握手序号=2", wh.classify_handshake(e) == 2)

    m3 = build_eapol_key(0x1382, 2, ANONCE, mic=b"\x20" * 16, key_data=b"\xde\xad\xbe\xef")
    e = wh.parse_eapol_key(m3)
    t("M3 Key Info：ACK=1 Secure=1 Enc=1",
      e["key_info"]["ack"] and e["key_info"]["secure"] and e["key_info"]["encrypted_key_data"])
    t("M3 KeyData 长度=4", e["key_data_length"] == 4 and e["key_data"] == b"\xde\xad\xbe\xef")
    t("M3 握手序号=3", wh.classify_handshake(e) == 3)

    m4 = build_eapol_key(0x0302, 2, b"\x00" * 32, mic=b"\x30" * 16)
    e = wh.parse_eapol_key(m4)
    t("M4 Nonce 全零", not any(e["nonce"]))
    t("M4 握手序号=4", wh.classify_handshake(e) == 4)

    # ---- 从 802.11 帧提取 EAPOL ----
    print("[4.1.2] eapol_from_dot11 提取")
    dot = build_dot11_data(m1)
    got = wh.eapol_from_dot11(dot)
    t("QoS Data 帧提取 EAPOL 一致", got == m1)
    dot_plain = build_dot11_data(m1, subtype=0)
    t("普通 Data 帧（无 QoS）提取一致", wh.eapol_from_dot11(dot_plain) == m1)
    non_eapol = build_dot11_data(b"\x45" * 20)  # IPv4 载荷
    non_eapol = non_eapol[:32] + b"\x08\x00" + non_eapol[34:]  # 将 EtherType 改为 0x0800
    t("非 EAPOL（IPv4 0x0800）返回 None", wh.eapol_from_dot11(non_eapol) is None)
    t("管理帧返回 None", wh.eapol_from_dot11(b"\x80\x00" + b"\x00" * 30) is None)

    # ---- pcap fixture 全链路 ----
    print("[4.1.2] pcap 全链路（tests/fixtures/wpa2_handshake.pcap）")
    fx = os.path.join(ROOT, "tests", "fixtures", "wpa2_handshake.pcap")
    if not os.path.exists(fx):
        t("fixture 存在（先运行 tools/make_wpa2_handshake_pcap.py）", False)
    else:
        frames = wh.extract_handshake_from_pcap(fx)
        t("发现 4 条 EAPOL-Key 帧", len(frames) == 4, "实际 %d" % len(frames))
        t("握手序号序列为 [1,2,3,4]",
          [f["msg"] for f in frames] == [1, 2, 3, 4],
          str([f["msg"] for f in frames]))
        if len(frames) >= 4:
            t("M1 ANonce 一致", frames[0]["nonce"] == ANONCE)
            t("M2 SNonce 一致", frames[1]["nonce"] == SNONCE)
            t("M3 与 M1 同 ANonce", frames[2]["nonce"] == frames[0]["nonce"])
            t("M3 KeyData 长度=8", frames[2]["key_data_length"] == 8)
            t("M4 带 MIC 且无 Nonce", frames[3]["key_mic"] != b"\x00" * 16
              and not any(frames[3]["nonce"]))

        # ---- 4.1.3 PTK 推导 ----
        print("[4.1.3] PTK 推导（PRF-512，Pairwise key expansion）")
        pmk = wh.derive_pmk(b"password", b"IEEE")
        ap_mac = bytes.fromhex("aabbccddee01")
        sta_mac = bytes.fromhex("112233445566")
        kck, kek, tk = wh.derive_ptk(pmk, ap_mac, sta_mac, ANONCE, SNONCE)
        t("三段各 16 字节", len(kck) == len(kek) == len(tk) == 16)
        t("KCK 与 make 脚本输出一致",
          kck.hex() == "55117df421dd537a8b95d05fc36fba2a", kck.hex())
        t("KEK 与 make 脚本输出一致",
          kek.hex() == "173c5e220e0265d1ad40888dd46ecd1c", kek.hex())
        t("TK 与 make 脚本输出一致",
          tk.hex() == "f77887165b497356b9e7d2afd8fa716b", tk.hex())
        kck2, _, _ = wh.derive_ptk(pmk, sta_mac, ap_mac, SNONCE, ANONCE)
        t("min/max 排序与入参顺序无关", kck2 == kck)
        prf = wh.prf_512(pmk, wh.PTK_A_LABEL, b"\x00" * 16)
        t("prf_512 输出 64 字节", len(prf) == 64)
        t("prf_512 确定性", prf == wh.prf_512(pmk, wh.PTK_A_LABEL, b"\x00" * 16))

        # ---- 4.1.4 MIC 校验（HMAC-SHA1 前 16 字节，仅 descriptor v2）----
        print("[4.1.4] MIC 校验（KCK + HMAC-SHA1）")
        m2_frame = frames[1]["raw_eapol"]
        t("fixture 提取含 raw_eapol", "raw_eapol" in frames[1] and len(m2_frame) > 90)
        t("M2 原始帧 MIC 非零", m2_frame[wh.KEY_MIC_OFFSET:wh.KEY_MIC_OFFSET + 16] != b"\x00" * 16)
        zeroed = wh.zero_key_mic(m2_frame)
        t("zero_key_mic 将 MIC 清零", zeroed[wh.KEY_MIC_OFFSET:wh.KEY_MIC_OFFSET + 16] == b"\x00" * 16
          and zeroed[:wh.KEY_MIC_OFFSET] == m2_frame[:wh.KEY_MIC_OFFSET]
          and zeroed[wh.KEY_MIC_OFFSET + 16:] == m2_frame[wh.KEY_MIC_OFFSET + 16:])
        t("compute_mic 与帧内 MIC 一致",
          wh.compute_mic(kck, m2_frame) == m2_frame[wh.KEY_MIC_OFFSET:wh.KEY_MIC_OFFSET + 16])
        t("正向：口令正确 → MIC 一致", wh.verify_mic(kck, m2_frame) is True)
        t("反向：错口令（随机 KCK）→ 不一致",
          wh.verify_mic(b"\xaa" * 16, m2_frame) is False)
        m3_frame = frames[2]["raw_eapol"]
        m4_frame = frames[3]["raw_eapol"]
        t("M3 正向校验", wh.verify_mic(kck, m3_frame) is True)
        t("M4 正向校验", wh.verify_mic(kck, m4_frame) is True)
        m2_tkip = build_eapol_key(0x0302, 1, SNONCE, mic=b"\x11" * 16, desc_type=1)
        t("TKIP(desc v1) 跳过校验返回 False", wh.verify_mic(kck, m2_tkip) is False)

        # ---- 4.1.5 CCMP 解密（AES-128-CCM，手写拼装）----
        print("[4.1.5] CCMP 解密（AES-128-CCM）")
        iv = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
        aad_demo = b"\xaa" * 22
        ct, enc_mic = wh.ccm_encrypt(tk, iv, aad_demo, b"hello ccmp!")
        back, ok = wh.ccm_decrypt(tk, iv, aad_demo, ct, enc_mic)
        t("CCM 往返还原明文且 MIC 通过", back == b"hello ccmp!" and ok)
        bad, bok = wh.ccm_decrypt(b"\x00" * 16, iv, aad_demo, ct, enc_mic)
        t("CCM 错密钥 MIC 失败", not bok)
        mac26 = struct.pack("<H", 0x4108) + b"\x00\x00" + b"\x02" * 6 + b"\x01" * 6 + b"\x03" * 6 + b"\x10\x00" + b"\x05\x00"
        aad26 = wh.ccmp_build_aad(mac26)
        t("QoS(26B) AAD 长度=26", len(aad26) == 26, len(aad26))
        diff = [i for i in range(26) if aad26[i] != mac26[i]]
        t("AAD 仅屏蔽 FC 高字节可变位与 Seq 序号位",
          diff == [1, 22], str(diff))

        # 从 fixture 提取 CCMP 加密 QoS Data 帧并解密
        from wifi80211.parser import read_pcap, strip_radiotap
        _, raw_pkts, _ = read_pcap(fx)
        ccmp = None
        for rec in raw_pkts:
            dot = strip_radiotap(rec[4])
            if dot is None or len(dot) < 34:
                continue
            fc = int.from_bytes(dot[:2], "little")
            if ((fc >> 2) & 3) == 2 and (fc & 0x4000):
                ccmp = dot
                break
        t("fixture 含 CCMP 加密 QoS Data 帧", ccmp is not None)
        if ccmp is not None:
            pt, mok = wh.decrypt_ccmp_frame(tk, ccmp)
            t("解密 MIC 校验通过", mok)
            t("还原 LLC/SNAP + IPv4 头",
              pt[:8] == bytes.fromhex("aaaa030000000800"), pt[:8].hex())
            t("还原 IP 头样例一致",
              pt[8:28] == bytes.fromhex("4500003c0001000040060000c0a80164c0a80101"), pt[8:28].hex())
            pt2, mok2 = wh.decrypt_ccmp_frame(b"\x00" * 16, ccmp)
            t("错 TK 解密 MIC 校验失败", not mok2)

    n_fail = FAIL_COUNT[0] if FAIL_COUNT else 0
    print("\n结果: %s" % ("全部通过" if n_fail == 0 else "%d 项失败" % n_fail))
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
