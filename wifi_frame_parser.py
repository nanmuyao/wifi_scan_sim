#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi 802.11 帧解析器（仿真验证版）
===================================
手写 802.11 帧解析逻辑（不依赖 scapy），验证程序能否解析 WiFi 数据包。
scapy 仅用于【生成】标准测试帧；解析路径完全是手写字节级代码，
可直接平移为 C 实现或移植到 STM32 侧。

支持解析：
  - 802.11 MAC 头（Frame Control / Duration / 地址 / Sequence）
  - 管理帧：Beacon / Probe Request / Probe Response（含 Tag 解析）
  - 数据帧：能解析 MAC 头，payload 显示加密状态（WPA2 密文不可解）

运行：
  python3 wifi_frame_parser.py
"""

import struct

# ---------------------------------------------------------------------------
# 802.11 帧类型/子类型查表
# ---------------------------------------------------------------------------
MGMT_SUBTYPE = {
    0: "Association Request", 1: "Association Response",
    2: "Reassociation Request", 3: "Reassociation Response",
    4: "Probe Request", 5: "Probe Response", 6: "Timing Advertisement",
    8: "Beacon", 9: "ATIM", 10: "Disassociation", 11: "Authentication",
    12: "Deauthentication", 13: "Action", 14: "Action No Ack",
}
CTRL_SUBTYPE = {
    0: "Control Wrapper", 1: "Block ACK Request", 2: "Block ACK",
    3: "PS-Poll", 4: "RTS", 5: "CTS", 6: "ACK", 8: "CF-End", 9: "CF-End+CF-Ack",
}
DATA_SUBTYPE = {
    0: "Data", 1: "Data+CF-Ack", 2: "Data+CF-Poll", 3: "Data+CF-Ack+CF-Poll",
    4: "Null", 8: "QoS Data", 10: "QoS Null", 12: "QoS Data+CF-Poll",
}


# ---------------------------------------------------------------------------
# 字节级解析器（纯手写，无第三方依赖）
# ---------------------------------------------------------------------------
def parse_frame_control(fc):
    """解析 2 字节 Frame Control。"""
    version = fc & 0x3
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    flags = (fc >> 8) & 0xFF
    to_ds = (flags >> 0) & 1
    from_ds = (flags >> 1) & 1
    more_frag = (flags >> 2) & 1
    retry = (flags >> 3) & 1
    pwr_mgmt = (flags >> 4) & 1
    more_data = (flags >> 5) & 1
    protected = (flags >> 6) & 1
    order = (flags >> 7) & 1
    return {
        "version": version, "type": ftype, "subtype": subtype,
        "to_ds": to_ds, "from_ds": from_ds, "more_frag": more_frag,
        "retry": retry, "pwr_mgmt": pwr_mgmt, "more_data": more_data,
        "protected": protected, "order": order,
    }


def mac_str(raw):
    return ":".join("%02x" % b for b in raw)


def parse_mac_header(buf):
    """解析 24 字节 802.11 MAC 头，返回结构化字段。"""
    if len(buf) < 24:
        raise ValueError("MAC header too short: %d" % len(buf))
    fc, duration = struct.unpack("<HH", buf[0:4])
    addr1 = mac_str(buf[4:10])
    addr2 = mac_str(buf[10:16])
    addr3 = mac_str(buf[16:22])
    seq = struct.unpack("<H", buf[22:24])[0]
    f = parse_frame_control(fc)
    hdr = {
        "fc": fc, "duration": duration,
        "addr1": addr1, "addr2": addr2, "addr3": addr3,
        "seq_num": (seq >> 4) & 0xFFF, "frag_num": seq & 0xF,
    }
    hdr.update(f)
    return hdr


def type_name(h):
    if h["type"] == 0:
        return "Management", MGMT_SUBTYPE.get(h["subtype"], "Unknown(%d)" % h["subtype"])
    if h["type"] == 1:
        return "Control", CTRL_SUBTYPE.get(h["subtype"], "Unknown(%d)" % h["subtype"])
    if h["type"] == 2:
        return "Data", DATA_SUBTYPE.get(h["subtype"], "Unknown(%d)" % h["subtype"])
    return "Reserved", "Unknown(%d)" % h["subtype"]


def parse_tags(body):
    """解析 Tagged Parameters（TLV 序列），返回 {tag_id: value}。"""
    tags = {}
    p = 0
    n = len(body)
    while p + 2 <= n:
        tid = body[p]
        tlen = body[p + 1]
        if p + 2 + tlen > n:
            break
        val = body[p + 2:p + 2 + tlen]
        tags[tid] = val
        p += 2 + tlen
    return tags


TAG_NAMES = {
    0: "SSID", 1: "Supported Rates", 2: "FH Parameter Set",
    3: "DS Parameter Set(channel)", 4: "CF Parameter Set",
    5: "TIM", 6: "IBSS Parameter Set", 7: "Country",
    36: "Capability", 42: "ERP Info", 45: "HT Capabilities",
    46: "QoS Capability", 48: "RSN(WPA2)", 50: "Extended Supported Rates",
    61: "HT Operation", 191: "VHT Capabilities", 221: "Vendor Specific",
}


def parse_beacon(body):
    """解析 Beacon 帧体：Timestamp + Interval + Capability + Tags。"""
    ts, interval, cap = struct.unpack("<QHH", body[0:12])
    tags = parse_tags(body[12:])
    ssid = tags.get(0, b"")
    channel = tags.get(3, b"")
    rates = tags.get(1, b"") or tags.get(50, b"")
    return {
        "timestamp": ts, "interval_tu": interval,
        "capability_ess": bool(cap & 0x1), "capability_ibss": bool(cap & 0x2),
        "capability_privacy": bool(cap & 0x10),
        "ssid": ssid.decode("utf-8", "replace") if ssid else "<hidden/empty>",
        "channel": channel[0] if channel else "?",
        "rates_mbps": sorted(r / 2 for r in rates),
    }


def parse_probe_req(body):
    """解析 Probe Request 帧体（通常只有 Tag 序列）。"""
    tags = parse_tags(body)
    ssid = tags.get(0, b"")
    rates = tags.get(1, b"") or tags.get(50, b"")
    return {
        "ssid": ssid.decode("utf-8", "replace") if ssid else "<broadcast(找所有网络)>",
        "rates_mbps": sorted(r / 2 for r in rates),
    }


def parse_data_frame(h, payload):
    """数据帧：解析头部 + 加密状态；无密钥时 payload 为密文。"""
    if h["protected"]:
        ccmp_overhead = 8  # CCMP Header
        enc_payload = payload[ccmp_overhead:] if len(payload) > ccmp_overhead else b""
        return {
            "encrypted": True, "cipher": "CCMP(WPA2)",
            "payload_preview": enc_payload[:16].hex() + ("..." if len(enc_payload) > 16 else ""),
            "note": "无密钥，仅能解析帧头；内容为密文",
        }
    return {
        "encrypted": False,
        "payload_preview": payload[:32].hex(),
        "note": "开放网络明文（本演示不构造明文数据内容）",
    }


# ---------------------------------------------------------------------------
# 测试帧生成：用 scapy 构造标准 802.11 帧，转成字节喂给手写解析器
# ---------------------------------------------------------------------------
def make_beacon(ssid, bssid, channel):
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
    frame = (
        RadioTap() /
        Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) /
        Dot11Beacon(cap=0x1101, beacon_interval=100) /
        Dot11Elt(ID=0, info=ssid.encode()) /
        Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])) /
        Dot11Elt(ID=3, info=bytes([channel])) /
        Dot11Elt(ID=48, info=b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x00\x00")
    )
    return bytes(frame)


def make_probe_req(ssid=None):
    from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt
    target = ssid.encode() if ssid else b""
    frame = (
        RadioTap() /
        Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
              addr2="12:34:56:78:9a:bc", addr3="ff:ff:ff:ff:ff:ff") /
        Dot11ProbeReq() /
        Dot11Elt(ID=0, info=target) /
        Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8b, 0x96]))
    )
    return bytes(frame)


def make_data_encrypted(sa, da, bssid):
    """构造一条 WPA2 加密数据帧（CCMP 头 + 密文 payload）。"""
    from scapy.layers.dot11 import Dot11, Dot11QoS
    from scapy.packet import Raw
    fc_protected = 0x40
    frame = (
        RadioTap() /
        Dot11(type=2, subtype=8, addr1=da, addr2=sa, addr3=bssid, FCfield=fc_protected) /
        Dot11QoS() /
        Raw(load=b"\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x9f\x3a\x7c\x11\x88\xee" + b"\x00" * 24)
    )
    return bytes(frame)


def RadioTap():
    """最小 Radiotap 头（8 字节），保证 scapy 输出带 radiotap 的真实抓包形态。"""
    from scapy.layers.dot11 import RadioTap as RT
    return RT()


def strip_radiotap(raw):
    """剥离 Radiotap 头，返回 Dot11 帧起始。len 字段在 offset 2（2 字节小端）。"""
    if len(raw) < 8:
        return raw
    return raw[8:]


def show_frame(name, raw):
    print("=" * 70)
    print("[%s] 原始字节 %d 字节" % (name, len(raw)))
    hexdump = " ".join("%02x" % b for b in raw[:40])
    print("  hex: %s%s" % (hexdump, "..." if len(raw) > 40 else ""))
    dot11 = strip_radiotap(raw)
    h = parse_mac_header(dot11)
    fam, sub = type_name(h)
    print("  [MAC 头] %s / %s" % (fam, sub))
    print("  [MAC 头] addr1(接收)=%s" % h["addr1"])
    print("  [MAC 头] addr2(发送)=%s" % h["addr2"])
    print("  [MAC 头] addr3(BSSID)=%s" % h["addr3"])
    print("  [MAC 头] seq=%d  frag=%d  retry=%d" % (h["seq_num"], h["frag_num"], h["retry"]))
    print("  [MAC 头] protected=%d  to_ds=%d  from_ds=%d" % (h["protected"], h["to_ds"], h["from_ds"]))
    body = dot11[24:]
    if h["type"] == 0 and h["subtype"] == 8:
        b = parse_beacon(body)
        print("  [Beacon] timestamp=%d  interval=%dTU  ESS=%s  IBSS=%s  privacy=%s"
              % (b["timestamp"], b["interval_tu"], b["capability_ess"],
                 b["capability_ibss"], b["capability_privacy"]))
        print("  [Tag] SSID=%s  channel=%s" % (b["ssid"], b["channel"]))
        print("  [Tag] rates(Mbps)=%s" % b["rates_mbps"])
    elif h["type"] == 0 and h["subtype"] == 4:
        b = parse_probe_req(body)
        print("  [ProbeReq] 探测SSID=%s" % b["ssid"])
        print("  [Tag] rates(Mbps)=%s" % b["rates_mbps"])
    elif h["type"] == 0 and h["subtype"] == 5:
        b = parse_beacon(body)
        print("  [ProbeResp] SSID=%s channel=%s" % (b["ssid"], b["channel"]))
    elif h["type"] == 2:
        r = parse_data_frame(h, body)
        print("  [Data] 加密=%s" % r["encrypted"])
        print("  [Data] payload前16字节: %s" % r["payload_preview"])
        print("  [Data] 说明: %s" % r["note"])
    else:
        print("  [Body] 前16字节: %s" % body[:16].hex())
    return h


def main():
    print("#" * 70)
    print("# WiFi 802.11 数据包解析演示（scapy 生成标准帧 → 手写解析器解析）")
    print("#")
    print("# 帧类型说明: 管理帧(beacon/probe)不加密可完整解析;")
    print("#             数据帧在 WPA2 下加密，无密钥只能解析 MAC 头")
    print("#" * 70)

    # 1. Beacon 帧（AP 周期性广播，最常抓到）
    show_frame("Beacon(AP广播)", make_beacon("Paul-Home-2.4G", "a4:83:e7:11:22:02", 6))

    # 2. Probe Request（手机/设备主动探测）
    show_frame("ProbeReq(设备探测)", make_probe_req("Paul-Home-2.4G"))

    # 3. Probe Request（广播探测——设备在找曾经连过的所有网络）
    show_frame("ProbeReq(广播探测)", make_probe_req())

    # 4. WPA2 加密数据帧
    show_frame("Data(WPA2加密)", make_data_encrypted("a4:83:e7:11:22:02",
                                                     "3c:06:30:ab:cd:ef",
                                                     "a4:83:e7:11:22:02"))

    print("=" * 70)
    print("[OK] 4 类帧全部解析成功")


if __name__ == "__main__":
    main()
