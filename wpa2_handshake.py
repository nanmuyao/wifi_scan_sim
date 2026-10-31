#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wpa2_handshake.py — WPA2/WPA 密钥派生与 EAPOL 四次握手解析（纯手写、少依赖）

阶段 4（P1）：
  4.1.1 PMK 推导：PBKDF2-HMAC-SHA1(password, ssid, 4096, 32)（802.11i 标准向量）
  4.1.2 EAPOL 解析：从 pcap 数据帧中提取 EAPOL-Key，区分握手 1/4、2/4、3/4、4/4，
        取 ANonce / SNonce / MIC / Key Info。

仅依赖 Python 标准库（hashlib / struct / argparse），802.11 容器解析复用
wifi_frame_parser.read_pcap / strip_radiotap，不引入第三方包。

用法：
  # PMK 推导（标准向量：password / IEEE）
  python3 wpa2_handshake.py --pmk --password password --ssid IEEE

  # 解析含四次握手的 pcap（tests/fixtures/wpa2_handshake.pcap 由
  # tools/make_wpa2_handshake_pcap.py 用 scapy 生成）
  python3 wpa2_handshake.py --pcap tests/fixtures/wpa2_handshake.pcap
"""

import argparse
import hashlib
import struct

try:
    from wifi_frame_parser import read_pcap, strip_radiotap
except ImportError:  # 允许从任意目录直接运行
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from wifi_frame_parser import read_pcap, strip_radiotap

# IEEE 802.11i §8.5.1.3：PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 256 bits)
PMK_SALT_SSID = b"IEEE"          # 标准向量使用的 SSID（roadmap 4.1.1）
PMK_ITERATIONS = 4096
PMK_LEN = 32

# 标准向量（roadmap 4.1.1 验收基准）：password / IEEE
PMK_STD_VECTOR = ("f42c6fc52df0ebef9ebb4b90b38a5f90"
                  "2e83fe1b135a70e23aed762e9710a12e")


# ---------------------------------------------------------------------------
# 4.1.1 PMK 推导
# ---------------------------------------------------------------------------
def derive_pmk(password: bytes, ssid: bytes,
               iterations: int = PMK_ITERATIONS,
               length: int = PMK_LEN) -> bytes:
    """PBKDF2-HMAC-SHA1 派生 PMK（802.11i 标准流程）。"""
    return hashlib.pbkdf2_hmac("sha1", password, ssid, iterations, length)


def pmk_hex(password, ssid):
    return derive_pmk(password.encode("utf-8"), ssid.encode("utf-8")).hex()


# ---------------------------------------------------------------------------
# 4.1.2 EAPOL-Key 解析（802.11i §8.5.2 / RFC 5216 风格 EAPOL-Key 描述符）
# ---------------------------------------------------------------------------
# EAPOL 帧体：Version(1) Type(1) Length(2) | Key Descriptor...
# Key Descriptor（WPA2 使用 Descriptor Type=2）：
#   DescriptorType(1) KeyInfo(2) KeyLen(2) ReplayCounter(8) Nonce(32)
#   KeyIV(16) RSC(8) KeyID(8) MIC(16) KeyDataLen(2) KeyData(...)
EAPOL_HDR = 4            # Version+Type+Length
KEY_DESC_BASE = 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8 + 16 + 2
KEY_DESC_TOTAL = EAPOL_HDR + KEY_DESC_BASE   # 98 字节（不含 KeyData）

# Key Info 位定义（2 字节小端）
KI_DESCRIPTOR_VERSION_MASK = 0x0007
KI_KEY_TYPE              = 0x0008   # bit3: 1=Pairwise, 0=Group
KI_INSTALL               = 0x0040   # bit6
KI_ACK                   = 0x0080   # bit7: AP 要求应答（M1/M3 置位）
KI_MIC                   = 0x0100   # bit8: 含 MIC
KI_SECURE                = 0x0200   # bit9: Secure bit（M2/M3/M4 置位）
KI_ERROR                 = 0x0400   # bit10
KI_REQUEST               = 0x0800   # bit11
KI_ENCRYPTED_KEY_DATA    = 0x1000   # bit12: KeyData 加密（M3 常见）
KI_SMK_MESSAGE           = 0x2000   # bit13


def parse_key_info(kb: int) -> dict:
    """Key Info 位分解。"""
    return {
        "descriptor_version": kb & KI_DESCRIPTOR_VERSION_MASK,
        "key_type": bool(kb & KI_KEY_TYPE),
        "install": bool(kb & KI_INSTALL),
        "ack": bool(kb & KI_ACK),
        "mic": bool(kb & KI_MIC),
        "secure": bool(kb & KI_SECURE),
        "error": bool(kb & KI_ERROR),
        "request": bool(kb & KI_REQUEST),
        "encrypted_key_data": bool(kb & KI_ENCRYPTED_KEY_DATA),
        "raw": kb,
    }


def parse_eapol_key(payload: bytes) -> dict:
    """解析完整 EAPOL-Key 帧体（含 4 字节 EAPOL 头）。

    返回字段：version/type/length/descriptor_type/key_info 位分解/
    key_length/replay_counter/nonce/key_iv/key_rsc/key_id/key_mic/
    key_data_length/key_data。数据不足时返回部分字段 + 'truncated'。
    """
    if len(payload) < EAPOL_HDR:
        return {"error": "EAPOL 帧过短"}
    ver, typ, ln = payload[0], payload[1], struct.unpack("<H", payload[2:4])[0]
    out = {"version": ver, "type": typ, "length": ln, "truncated": False}
    if typ != 3:   # 3 = EAPOL-Key
        out["error"] = "非 EAPOL-Key（type=%d）" % typ
        return out
    if len(payload) < KEY_DESC_TOTAL:
        out["truncated"] = True
        return out
    p = payload[EAPOL_HDR:]
    out["descriptor_type"] = p[0]
    ki = struct.unpack("<H", p[1:3])[0]
    out["key_info"] = parse_key_info(ki)
    out["key_length"] = struct.unpack("<H", p[3:5])[0]
    out["replay_counter"] = struct.unpack("<Q", p[5:13])[0]
    out["nonce"] = p[13:45]                  # Key Nonce（32 字节）
    out["key_iv"] = p[45:61]
    out["key_rsc"] = p[61:69]
    out["key_id"] = p[69:77]
    out["key_mic"] = p[77:93]                # Key MIC（16 字节）
    kdlen = struct.unpack("<H", p[93:95])[0]
    out["key_data_length"] = kdlen
    out["key_data"] = p[95:95 + kdlen] if len(p) >= 95 + kdlen else b""
    if len(p) < 95 + kdlen:
        out["truncated"] = True
    return out


def classify_handshake(e: dict) -> int:
    """根据 Key Info / Nonce / MIC 判断 EAPOL-Key 属于握手第几条（1~4）。

    依据（802.11i 四次握手状态机）：
      M1 (AP→STA)：ACK=1, Secure=0，携带 ANonce；
      M2 (STA→AP)：ACK=0, Secure=1，携带 SNonce + MIC；
      M3 (AP→STA)：ACK=1, Secure=1，携带 ANonce + MIC + KeyData；
      M4 (STA→AP)：ACK=0, Secure=1，Nonce 全零，仅 MIC。
    """
    if "key_info" not in e or "nonce" not in e:
        return 0
    ki = e["key_info"]
    ack, sec = ki["ack"], ki["secure"]
    nonce_zero = not any(e["nonce"])
    if ack and not sec:
        return 1
    if ack and sec:
        return 3
    if sec and not ack and not nonce_zero:
        return 2
    if sec and not ack and nonce_zero:
        return 4
    return 0


def eapol_from_dot11(dot11: bytes) -> bytes:
    """从 802.11 数据帧体提取 LLC/SNAP + EAPOL 载荷；非 EAPOL 返回 None。

    数据帧布局：MAC 头(24) [+ QoS Control(2, subtype 8 系)] + LLC/SNAP(8)
    [AA AA 03 00 00 00 + EtherType 2B] + 载荷。EtherType 0x888e = EAPOL。
    """
    if len(dot11) < 24:
        return None
    fc = struct.unpack("<H", dot11[:2])[0]
    sub = (fc >> 4) & 0x0F
    fam = (fc >> 2) & 0x03
    if fam != 2:                       # 非数据帧
        return None
    off = 24
    if sub in (8, 9, 10, 12, 13, 14) and len(dot11) >= off + 2:
        off += 2                       # QoS Control
    if len(dot11) < off + 8:
        return None
    llc = dot11[off:off + 8]
    if llc[:6] != b"\xaa\xaa\x03\x00\x00\x00":
        return None
    etype = struct.unpack(">H", llc[6:8])[0]
    if etype != 0x888e:
        return None
    return dot11[off + 8:]


def extract_handshake_from_pcap(path: str) -> list:
    """扫描 pcap 中所有 EAPOL-Key 帧，按时间序解析并附握手序号。"""
    linktype, pkts, nanosec = read_pcap(path)
    frames = []
    for ts_sec, ts_frac, incl_len, orig_len, body in pkts:
        dot11 = body
        if linktype == 127:
            dot11 = strip_radiotap(body)
        elif linktype == 1:            # Ethernet 容器：跳过以太头
            dot11 = body[14:] if len(body) > 14 else body
        eapol = eapol_from_dot11(dot11)
        if not eapol:
            continue
        e = parse_eapol_key(eapol)
        if "error" in e or "key_info" not in e:
            continue
        e["t"] = ts_sec + ts_frac / (1e9 if nanosec else 1e6)
        e["msg"] = classify_handshake(e)
        frames.append(e)
    return frames


# ---------------------------------------------------------------------------
# 输出辅助
# ---------------------------------------------------------------------------
def hex_short(b: bytes, n: int = 16) -> str:
    return b[:n].hex()


def print_pmk(args):
    pmk = derive_pmk(args.password.encode("utf-8"),
                     args.ssid.encode("utf-8"))
    print("# PMK（PBKDF2-HMAC-SHA1, 4096 次, 32 字节）")
    print("password = %s" % args.password)
    print("ssid     = %s" % args.ssid)
    print("PMK      = %s" % pmk.hex())
    print("标准向量  = %s" % PMK_STD_VECTOR)
    print("一致      = %s" % (pmk.hex() == PMK_STD_VECTOR))


def print_pcap(args):
    frames = extract_handshake_from_pcap(args.pcap)
    if not frames:
        print("未在 %s 中发现 EAPOL-Key 帧" % args.pcap)
        return
    print("# EAPOL-Key 帧：%d 条（%s）" % (len(frames), args.pcap))
    for e in frames:
        ki = e["key_info"]
        m = e["msg"]
        label = {1: "1/4", 2: "2/4", 3: "3/4", 4: "4/4"}.get(m, "?" * 3)
        print("-" * 60)
        print("t=%.3f  type=%d  desc=%d  握手=%s (%s)" % (
            e["t"], e["type"], e["descriptor_type"], label,
            {0: "非握手/未知", 1: "M1 AP→STA", 2: "M2 STA→AP",
             3: "M3 AP→STA", 4: "M4 STA→AP"}.get(m, "?")))
        print("  Key Info : ver=%d ack=%d mic=%d secure=%d enc=%d raw=0x%04x"
              % (ki["descriptor_version"], ki["ack"], ki["mic"],
                 ki["secure"], ki["encrypted_key_data"], ki["raw"]))
        print("  replay   : %d" % e["replay_counter"])
        if m == 1 or m == 3:
            print("  ANonce    = %s" % hex_short(e["nonce"]))
        elif m == 2:
            print("  SNonce    = %s" % hex_short(e["nonce"]))
        else:
            print("  Nonce     = %s" % hex_short(e["nonce"]))
        print("  MIC       = %s" % hex_short(e["key_mic"]))
        print("  KeyData   : %d 字节%s" % (
            e["key_data_length"],
            "（加密）" if ki["encrypted_key_data"] else "（明文）"))


def main():
    ap = argparse.ArgumentParser(description="WPA2 PMK 推导与 EAPOL 四次握手解析")
    ap.add_argument("--pmk", action="store_true", help="推导 PMK（PBKDF2-HMAC-SHA1）")
    ap.add_argument("--password", default="password", help="口令（默认 password）")
    ap.add_argument("--ssid", default="IEEE", help="SSID（默认 IEEE，标准向量）")
    ap.add_argument("--pcap", metavar="FILE", help="解析 pcap 中的 EAPOL 握手帧")
    args = ap.parse_args()

    if args.pcap:
        print_pcap(args)
        return
    if args.pmk:
        print_pmk(args)
        return
    ap.print_help()


if __name__ == "__main__":
    main()
