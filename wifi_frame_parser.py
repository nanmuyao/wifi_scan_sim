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

import capture

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
# 子类型编号以 tshark 的值表为准（tests/oracle/test_subtype_names.py 逐项对照）。
# 控制帧 6 是 Control Frame Extension（DMG），帧结构不同，暂未支持。
CTRL_SUBTYPE = {
    2: "Trigger", 3: "TWT Ack", 4: "Beamforming Report Poll",
    5: "VHT/HE/EHT/Ranging NDP Announcement", 7: "Control Wrapper",
    8: "Block ACK Request", 9: "Block ACK", 10: "PS-Poll", 11: "RTS", 12: "CTS",
    13: "ACK", 14: "CF-End", 15: "CF-End+CF-Ack",
}
DATA_SUBTYPE = {
    0: "Data", 1: "Data+CF-Ack", 2: "Data+CF-Poll", 3: "Data+CF-Ack+CF-Poll",
    4: "Null", 5: "CF-Ack (no data)", 6: "CF-Poll (no data)",
    7: "CF-Ack+CF-Poll (no data)",
    8: "QoS Data", 9: "QoS Data+CF-Ack", 10: "QoS Data+CF-Poll",
    11: "QoS Data+CF-Ack+CF-Poll", 12: "QoS Null",
    14: "QoS CF-Poll (no data)", 15: "QoS CF-Ack+CF-Poll (no data)",
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


# ---------------------------------------------------------------------------
# 扩展管理帧：Authentication / Deauthentication / Association / Action
# ---------------------------------------------------------------------------
AUTH_ALGORITHM = {0: "Open System", 1: "Shared Key", 2: "Fast BSS Transition", 3: "SAE(WPA3)"}
AUTH_STATUS = {
    0: "Successful", 1: "Unspecified failure", 2: "Timeout",
    3: "Can't handle authentication", 4: "Authentication algorithm not supported",
    5: "Transaction sequence failure", 6: "Challenge failure",
    7: "Frame too long", 8: "RSN failure", 9: "Pairwise key failure",
    10: "Group key failure", 11: "AKMP not valid", 12: "Unsupported RSNE version",
    13: "Invalid RSNE capabilities", 14: "IEEE 802.1X auth failed",
    15: "Cipher suite rejected", 16: "TDLS rejected", 17: "Pending (SAE)",
}
REASON_CODE = {
    0: "Reserved", 1: "Unspecified reason", 2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending STA is leaving", 4: "Disassociated due to inactivity",
    5: "Disassociated because AP unable to handle all currently associated STAs",
    6: "Class 2 frame received from nonauthenticated STA",
    7: "Class 3 frame received from nonassociated STA",
    8: "Disassociated because sending STA is leaving BSS",
    9: "STA requesting association is not authenticated",
    10: "Disassociated because the information in the Power Capability IE is unacceptable",
    11: "Disassociated because the information in the Supported Channels IE is unacceptable",
    12: "Invalid information element",
    13: "Message integrity code (MIC) failure",
    14: "4-Way Handshake timeout", 15: "Group Key Handshake timeout",
    16: "IE in 4-Way Handshake differs from IE in association request",
    17: "Invalid group cipher", 18: "Invalid pairwise cipher",
    19: "Invalid AKMP", 20: "Unsupported RSNE version",
    21: "Invalid RSNE capabilities", 22: "IEEE 802.1X authentication failed",
    23: "Cipher suite rejected because of the proposed cipher suite",
    24: "TDLS direct-link teardown due to timeout", 25: "TDLS direct-link teardown due to malformed frame",
    26: "TDLS direct-link teardown due to peer unreachable", 27: "TDLS direct-link teardown due to unsupported setup",
    28: "Disassociated because the AP is leaving BSS", 29: "STA requesting association is not authenticated",
    30: "Disassociated due to unacceptable WLAN QoS parameters",
    31: "Needed for robust connection establishment",
    32: "Prior authentication with SAE failed", 33: "Disassociated due to timeout",
    34: "Peer MAC address in mesh PLM does not match", 35: "Peer MAC address in mesh PMSA does not match",
    36: "Peer MAC address in mesh PLMA does not match", 37: "Mesh channel switch is unauthorized",
    38: "Mesh deployment in progress",
    39: "Mesh establishment failed due to protocol violation",
    40: "Mesh establishment failed due to temporarily unavailable resources",
    41: "Mesh establishment failed due to reachability failure",
    42: "Mesh proxy service not available", 43: "Mesh proxy service not available for given peer",
    44: "Mesh PLM not configured", 45: "Mesh PLMA not configured",
    46: "Mesh PMSA not configured", 47: "Mesh channel switch unauthorized",
    48: "Mesh establishment failed due to received Disassociation frame",
}
ACTION_CATEGORY = {
    0: "Spectrum Management", 1: "QoS", 2: "DLS", 3: "Block Ack",
    4: "Public Action", 5: "Radio Measurement", 6: "Fast BSS Transition",
    7: "HT Action", 8: "SA Query", 9: "Protected Dual of Public Action",
    10: "WNM", 11: "Unprotected WNM", 12: "TDLS", 13: "Mesh Action",
    14: "Multihop Action", 15: "Self Protected Action", 16: "DMS Action",
    17: "WMM Action", 18: "FST Action", 19: "Unprotected Action", 20: "WNM",
    126: "Vendor Specific Protected", 127: "Vendor Specific",
}


def parse_auth(body):
    """Authentication 帧体：Algorithm(2) + Transaction Seq(2) + Status(2)。"""
    if len(body) < 6:
        return {"error": "Auth frame too short: %d" % len(body)}
    algo, seq, status = struct.unpack("<HHH", body[0:6])
    return {
        "auth_algorithm": AUTH_ALGORITHM.get(algo, "Unknown(%d)" % algo),
        "auth_seq": seq,
        "auth_status_code": status,
        "auth_status": AUTH_STATUS.get(status, "Unknown(%d)" % status),
    }


def parse_deauth(body):
    """Deauthentication 帧体：Reason(2)。"""
    if len(body) < 2:
        return {"error": "Deauth frame too short: %d" % len(body)}
    reason = struct.unpack("<H", body[0:2])[0]
    return {
        "deauth_reason_code": reason,
        "deauth_reason": REASON_CODE.get(reason, "Unknown(%d)" % reason),
    }


def parse_disassoc(body):
    """Disassociation 帧体：Reason(2)。"""
    if len(body) < 2:
        return {"error": "Disassoc frame too short: %d" % len(body)}
    reason = struct.unpack("<H", body[0:2])[0]
    return {
        "disassoc_reason_code": reason,
        "disassoc_reason": REASON_CODE.get(reason, "Unknown(%d)" % reason),
    }


def parse_assoc_req(body):
    """Association Request 帧体：Capability(2) + Listen Interval(2) + Tags。"""
    if len(body) < 4:
        return {"error": "AssocReq frame too short: %d" % len(body)}
    cap, listen = struct.unpack("<HH", body[0:4])
    tags = parse_tags(body[4:])
    ssid = tags.get(0, b"")
    rates = tags.get(1, b"") or tags.get(50, b"")
    return {
        "capability": cap,
        "capability_ess": bool(cap & 0x1), "capability_ibss": bool(cap & 0x2),
        "capability_privacy": bool(cap & 0x10),
        "listen_interval": listen,
        "ssid": ssid.decode("utf-8", "replace") if ssid else "<empty>",
        "rates_mbps": sorted(r / 2 for r in rates),
    }


def parse_assoc_resp(body):
    """Association Response 帧体：Capability(2) + Status(2) + AID(2) + Tags。"""
    if len(body) < 6:
        return {"error": "AssocResp frame too short: %d" % len(body)}
    cap, status, aid = struct.unpack("<HHH", body[0:6])
    tags = parse_tags(body[6:])
    rates = tags.get(1, b"") or tags.get(50, b"")
    return {
        "capability": cap, "capability_ess": bool(cap & 0x1),
        "status_code": status, "status": AUTH_STATUS.get(status, "Unknown(%d)" % status),
        "aid": aid & 0x3FFF,
        "rates_mbps": sorted(r / 2 for r in rates),
    }


def parse_action(body):
    """Action 帧体：Category(1) + Action Code(1) + 载荷。"""
    if len(body) < 2:
        return {"error": "Action frame too short: %d" % len(body)}
    cat, act = body[0], body[1]
    return {
        "action_category": ACTION_CATEGORY.get(cat, "Unknown(%d)" % cat),
        "action_code": act,
        "action_payload": body[2:].hex(),
    }


def parse_mgmt_frame(h, body):
    """按子类型分发管理帧解析。返回 dict 或 None（无帧体解析）。"""
    if h["subtype"] == 8:      # Beacon
        return parse_beacon(body)
    if h["subtype"] == 4:      # Probe Request
        return parse_probe_req(body)
    if h["subtype"] == 5:      # Probe Response
        return parse_beacon(body)
    if h["subtype"] == 0:      # Association Request
        return parse_assoc_req(body)
    if h["subtype"] == 1:      # Association Response
        return parse_assoc_resp(body)
    if h["subtype"] == 2:      # Reassociation Request（帧体同 AssocReq）
        return parse_assoc_req(body)
    if h["subtype"] == 3:      # Reassociation Response（帧体同 AssocResp）
        return parse_assoc_resp(body)
    if h["subtype"] == 11:     # Authentication
        return parse_auth(body)
    if h["subtype"] == 12:     # Deauthentication
        return parse_deauth(body)
    if h["subtype"] == 10:     # Disassociation
        return parse_disassoc(body)
    if h["subtype"] == 13:     # Action
        return parse_action(body)
    return None


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
    """剥离 Radiotap 头，返回 Dot11 帧起始。头长度是 offset 2 的 2 字节小端（不是固定值）。"""
    if len(raw) < 8:
        return raw
    hlen = struct.unpack("<H", raw[2:4])[0]
    if hlen < 8:
        return b""                 # 头长度不合法：没有可解析的 802.11 帧
    return raw[hlen:]              # 长度超过整个包时得到空串


# ---------------------------------------------------------------------------
# pcap 文件解析（真实抓包：手写 pcap 容器解析，仅依赖 struct）
# ---------------------------------------------------------------------------
def read_pcap(path):
    """读取抓包文件（pcap / pcapng，可 gzip 压缩），返回 (第一个接口的链路类型, 包列表, 是否纳秒)。

    包列表每项 (秒, 微秒, 捕获长度, 原始长度, 数据)。新代码请直接用 capture.read_capture。"""
    cap = capture.read_capture(path)
    pkts = []
    for p in cap.packets:
        sec = int(p.ts)
        pkts.append((sec, int(round((p.ts - sec) * 1e6)), p.caplen, p.origlen, p.data))
    return (cap.linktypes[0] if cap.linktypes else 0), pkts, False


LINKTYPE_NAME = {
    0: "Null/Loopback", 1: "Ethernet", 105: "IEEE 802.11", 127: "IEEE 802.11 + Radiotap",
    195: "802.11 AVS",
}


def parse_ctrl_short(buf):
    """控制帧专用解析：RTS/CTS/ACK/PS-Poll 等短帧（<24 字节，无完整 3 地址头）。"""
    fc = struct.unpack("<H", buf[:2])[0]
    f = parse_frame_control(fc)
    # Frame Control 的标志位在所有帧里都有，控制帧也不例外
    info = {k: f[k] for k in ("to_ds", "from_ds", "more_frag", "retry", "pwr_mgmt", "more_data", "protected", "order")}
    info["duration"] = struct.unpack("<H", buf[2:4])[0] if len(buf) >= 4 else None
    if f["subtype"] in (12, 13, 7):               # CTS / ACK / Control Wrapper：只有 RA
        if len(buf) >= 10:
            info["ra"] = mac_str(buf[4:10])
    elif len(buf) >= 16:                          # RTS / PS-Poll / BAR / BA / CF-End 等：RA + TA
        info["ra"] = mac_str(buf[4:10])
        info["ta"] = mac_str(buf[10:16])
    return info


def parse_pcap_file(path):
    """解析整个 pcap 文件，逐帧提取 802.11 信息。"""
    cap = capture.read_capture(path)
    linktype = cap.linktypes[0] if cap.linktypes else 0
    results = []
    for pkt in cap.packets:
        body = pkt.data
        dot11 = body
        if pkt.linktype == 127:      # Radiotap 链路层
            dot11 = strip_radiotap(body)
        elif pkt.linktype == 1:      # Ethernet（转发/本机抓包场景，剥 14 字节头）
            dot11 = body[14:] if len(body) > 14 else body
        rec = {
            "t": pkt.ts, "linktype": pkt.linktype,
            "incl": pkt.caplen, "orig": pkt.origlen, "raw": len(dot11),
        }
        if len(dot11) < 2:
            rec["error"] = "帧过短"
            results.append(rec)
            continue
        fc = struct.unpack("<H", dot11[:2])[0]
        f = parse_frame_control(fc)
        fam, sub = type_name(f)
        rec["fam"], rec["sub"] = fam, sub
        rec["ftype"], rec["fsubtype"] = f["type"], f["subtype"]   # 数字形式，差分测试按它对照 tshark
        try:
            if f["type"] == 1 or len(dot11) < 24:
                rec.update(parse_ctrl_short(dot11))
            else:
                h = parse_mac_header(dot11)
                rec.update({k: h[k] for k in (
                    "addr1", "addr2", "addr3", "seq_num", "frag_num", "duration", "protected",
                    "to_ds", "from_ds", "retry", "pwr_mgmt", "more_frag", "more_data", "order")})
                body = dot11[24:]
                if fam == "Management":
                    m = parse_mgmt_frame(h, body)
                    if m:
                        if "error" in m:
                            rec["error"] = m["error"]
                        else:
                            rec.update(m)
                            if "ssid" in m and "channel" in m:
                                rec["ssid"] = m["ssid"]
                                rec["channel"] = m["channel"]
                                rec["rates"] = m.get("rates_mbps", [])
                elif fam == "Data":
                    qos_body = body
                    if h["subtype"] & 8 and len(body) >= 2:
                        qos_body = body[2:]  # QoS Data 帧体开头有 2 字节 QoS Control
                    r = parse_data_frame(h, qos_body)
                    rec["encrypted"] = r["encrypted"]
                    rec["preview"] = r["payload_preview"]
        except Exception as e:
            rec["error"] = str(e)
        results.append(rec)
    return linktype, results


def print_pcap_report(path):
    """打印 pcap 逐帧解析报告 + 统计。"""
    linktype, results = parse_pcap_file(path)
    print("#" * 70)
    print("# pcap 解析报告: %s" % path)
    print("# 链路层: %s (%d)" % (LINKTYPE_NAME.get(linktype, "Unknown"), linktype))
    print("# 共 %d 帧" % len(results))
    print("#" * 70)
    for i, r in enumerate(results):
        print("[%02d] t=%.6f %s/%s" % (i, r["t"], r["fam"], r["sub"]))
        if "error" in r:
            print("      error: %s" % r["error"])
            continue
        if "ra" in r:
            print("      RA=%s" % r["ra"])
        if "ta" in r:
            print("      TA=%s" % r["ta"])
        if "addr1" in r:
            print("      addr1=%s" % r["addr1"])
        if "addr2" in r:
            print("      addr2=%s" % r["addr2"])
        if "addr3" in r:
            print("      addr3=%s" % r["addr3"])
        if "seq_num" in r:
            print("      seq=%d frag=%d retry=%d" % (r["seq_num"], r.get("frag_num", 0), r.get("retry", 0)))
            print("      protected=%d to_ds=%d from_ds=%d pwr_mgmt=%d"
                  % (r["protected"], r["to_ds"], r["from_ds"], r.get("pwr_mgmt", 0)))
        if "ssid" in r and "channel" in r:
            print("      SSID=%s channel=%s" % (r["ssid"], r["channel"]))
        elif r.get("fam") == "Management" and r.get("sub") == "Probe Request":
            print("      探测SSID=%s" % r["ssid"])
        if "auth_algorithm" in r:
            print("      认证算法=%s  seq=%d  status=%d (%s)"
                  % (r["auth_algorithm"], r["auth_seq"], r["auth_status_code"], r["auth_status"]))
        if "deauth_reason" in r:
            print("      deauth原因=%d (%s)" % (r["deauth_reason_code"], r["deauth_reason"]))
        if "disassoc_reason" in r:
            print("      disassoc原因=%d (%s)" % (r["disassoc_reason_code"], r["disassoc_reason"]))
        if "listen_interval" in r:
            print("      关联请求: ESS=%s IBSS=%s privacy=%s listen_interval=%d SSID=%s"
                  % (r["capability_ess"], r["capability_ibss"], r["capability_privacy"],
                     r["listen_interval"], r.get("ssid", "?")))
        if "status_code" in r:
            print("      关联响应: status=%d (%s) AID=%d"
                  % (r["status_code"], r["status"], r["aid"]))
        if "action_category" in r:
            print("      Action: category=%s code=%d payload=%s"
                  % (r["action_category"], r["action_code"], r["action_payload"]))
        if "encrypted" in r:
            print("      加密=%s payload=%s" % (r["encrypted"], r.get("preview", "")))
    # 统计
    fams = {}
    for r in results:
        fams[r.get("fam", "?")] = fams.get(r.get("fam", "?"), 0) + 1
    ssids = sorted({r["ssid"] for r in results if "ssid" in r and "channel" in r})
    enc = sum(1 for r in results if r.get("encrypted"))
    print("=" * 70)
    print("[统计] 帧类型: %s" % ", ".join("%s x%d" % (k, v) for k, v in sorted(fams.items())))
    print("[统计] 发现的 SSID: %s" % (", ".join(ssids) if ssids else "(无管理帧)"))
    if enc:
        print("[统计] 加密数据帧: %d 条（仅解析 MAC 头，payload 为密文）" % enc)
    print("[OK] pcap 解析完成")


def make_demo_pcap(path):
    """用 scapy 生成一段『仿真真实抓包』的混合流量 pcap（管理+控制+数据帧）。"""
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Elt, Dot11QoS
    from scapy.packet import Raw
    import time

    frames = []
    # 3 个 AP 的 beacon（不同信道 / 加密属性）
    aps = [
        ("Paul-Home-2.4G", "a4:83:e7:11:22:02", 6),
        ("CoffeeShop-Free", "70:3a:cb:88:99:00", 11),
        ("TP-LINK_XXXX", "c8:3a:35:12:ab:cd", 1),
    ]
    for ssid, bssid, ch in aps:
        frames.append(
            RadioTap() /
            Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) /
            Dot11Beacon(cap=0x1101, beacon_interval=100) /
            Dot11Elt(ID=0, info=ssid.encode()) /
            Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])) /
            Dot11Elt(ID=3, info=bytes([ch])) /
            Dot11Elt(ID=48, info=b"\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x00\x00")
        )
    # 定向 + 广播 probe request（手机主动扫描）
    frames.append(RadioTap() / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                                    addr2="12:34:56:78:9a:bc", addr3="ff:ff:ff:ff:ff:ff") /
                  Dot11ProbeReq() / Dot11Elt(ID=0, info=b"Paul-Home-2.4G") / Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8b, 0x96])))
    frames.append(RadioTap() / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                                    addr2="12:34:56:78:9a:bc", addr3="ff:ff:ff:ff:ff:ff") /
                  Dot11ProbeReq() / Dot11Elt(ID=0, info=b"") / Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8b, 0x96])))
    # probe response（AP 应答）
    frames.append(RadioTap() / Dot11(type=0, subtype=5, addr1="12:34:56:78:9a:bc", addr2="a4:83:e7:11:22:02", addr3="a4:83:e7:11:22:02") /
                  Dot11ProbeResp(beacon_interval=100) /
                  Dot11Elt(ID=0, info=b"Paul-Home-2.4G") / Dot11Elt(ID=3, info=bytes([6])))
    # 控制帧：RTS(11) + ACK(13)（信道竞争最常出现）
    frames.append(RadioTap() / Dot11(type=1, subtype=11, addr1="a4:83:e7:11:22:02", addr2="12:34:56:78:9a:bc"))
    frames.append(RadioTap() / Dot11(type=1, subtype=13, addr1="12:34:56:78:9a:bc"))
    # WPA2 加密数据帧（CCMP 头 + 密文）
    frames.append(RadioTap() / Dot11(type=2, subtype=8, addr1="a4:83:e7:11:22:02",
                                    addr2="12:34:56:78:9a:bc", addr3="a4:83:e7:11:22:02",
                                    FCfield=0x40) /
                  Dot11QoS() /
                  Raw(load=b"\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x9f\x3a\x7c\x11\x88\xee" + b"\x00" * 24))
    # 开放网络明文数据帧（无加密，可直接看 payload）
    frames.append(RadioTap() / Dot11(type=2, subtype=0, addr1="ff:ff:ff:ff:ff:ff",
                                    addr2="12:34:56:78:9a:bc", addr3="70:3a:cb:88:99:00") /
                  Raw(load=b"GET /index.html HTTP/1.1\r\nHost: coffee.test\r\n\r\n"))

    # 扩展管理帧：认证握手 / 关联 / 去认证 / Action
    sta, ap = "12:34:56:78:9a:bc", "a4:83:e7:11:22:02"
    # Authentication：Open System 认证成功（algo=0, seq=1, status=0）
    frames.append(RadioTap() / Dot11(type=0, subtype=11, addr1=ap, addr2=sta, addr3=ap) /
                  Raw(load=struct.pack("<HHH", 0, 1, 0)))
    # Authentication：Shared Key 认证被拒（algo=1, seq=2, status=4 算法不支持）
    frames.append(RadioTap() / Dot11(type=0, subtype=11, addr1=sta, addr2=ap, addr3=ap) /
                  Raw(load=struct.pack("<HHH", 1, 2, 4)))
    # Association Request（cap=0x1101 ESS, listen_interval=100, SSID=Paul-Home-2.4G）
    assoc_tags = b"\x00" + bytes([len("Paul-Home-2.4G".encode())]) + b"Paul-Home-2.4G" \
                 + b"\x01\x04\x82\x84\x8b\x96"
    frames.append(RadioTap() / Dot11(type=0, subtype=0, addr1=ap, addr2=sta, addr3=ap) /
                  Raw(load=struct.pack("<HH", 0x1101, 100) + assoc_tags))
    # Association Response：成功（status=0, AID=1）
    frames.append(RadioTap() / Dot11(type=0, subtype=1, addr1=sta, addr2=ap, addr3=ap) /
                  Raw(load=struct.pack("<HHH", 0x1101, 0, 0x0001) + b"\x01\x04\x82\x84\x8b\x96"))
    # Deauthentication：AP 踢出，reason=4（inactivity）
    frames.append(RadioTap() / Dot11(type=0, subtype=12, addr1=sta, addr2=ap, addr3=ap) /
                  Raw(load=struct.pack("<H", 4)))
    # Disassociation：reason=8（sending STA leaving BSS）
    frames.append(RadioTap() / Dot11(type=0, subtype=10, addr1=sta, addr2=ap, addr3=ap) /
                  Raw(load=struct.pack("<H", 8)))
    # Action：Public Action (category=4)，GAS Initial Request (code=0)
    frames.append(RadioTap() / Dot11(type=0, subtype=13, addr1=ap, addr2=sta, addr3=ap) /
                  Raw(load=bytes([4, 0, 0x50, 0x6f, 0x9a])))

    from scapy.utils import wrpcap
    wrpcap(path, frames)
    return path


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
    import argparse
    ap = argparse.ArgumentParser(description="WiFi 802.11 帧解析器（手写字节级解析）")
    ap.add_argument("--pcap", metavar="FILE",
                    help="解析真实抓包 pcap 文件（sudo tcpdump -I -i en0 -w cap.pcap 抓取）")
    ap.add_argument("--demo", action="store_true", help="生成混合流量演示 pcap 并解析")
    args = ap.parse_args()

    if args.pcap:
        print_pcap_report(args.pcap)
        return

    # 默认：演示模式，生成混合流量 pcap 并解析
    print("#" * 70)
    print("# 演示模式：scapy 生成『仿真真实抓包』混合流量 → 手写 pcap/802.11 解析")
    print("# 用法：python3 wifi_frame_parser.py --pcap <真实抓包.pcap>")
    print("#" * 70)
    demo = "demo.pcap"
    make_demo_pcap(demo)
    print("[生成] 混合流量 pcap: %s\n" % demo)
    print_pcap_report(demo)


if __name__ == "__main__":
    main()
