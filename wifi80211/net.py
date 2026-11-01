# -*- coding: utf-8 -*-
"""
解密之后的内容：LLC/SNAP 之上最小的一层网络协议解析（ARP、IPv4、IPv6、UDP、TCP、ICMP / ICMPv6、DHCP）。纯标准库。

目的不是做一个协议分析器，而是回答「解出来的明文真的有意义吗」：IPv4 头校验和、UDP / TCP / ICMP 的校验和，
只有在解密完全正确时才会吻合（密文解错一个比特，校验和就对不上），这是对解密结果的独立证明，不依赖 tshark。
每个 parse_* 对结构不对（太短、版本不对）返回 None，不抛异常。
"""
import logging
import struct

from . import dns as dns80211
from . import logs

log = logging.getLogger(__name__)

LLC_SNAP = b"\xaa\xaa\x03"
LLC_STP = b"\x42\x42\x03"
ETHERTYPES = {0x0800: "ipv4", 0x0806: "arp", 0x86dd: "ipv6", 0x888e: "eapol", 0x88c7: "preauth"}
PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}


def ip4(b):
    return ".".join(str(x) for x in b)


def ip6(b):
    return ":".join("%x" % int.from_bytes(b[i:i + 2], "big") for i in range(0, 16, 2))


def checksum(data):
    """Internet 校验和（RFC 1071）：16 位反码和的反码。奇数长度补一个 0 字节。对包含校验和字段的完整数据，结果为 0 表示吻合。"""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def parse_snap(data):
    """LLC/SNAP：AA AA 03 + OUI(3) + 以太类型(2)，后面是上层数据。不是 SNAP 返回 None。"""
    if len(data) < 8 or data[:3] != LLC_SNAP:
        return None
    et = struct.unpack(">H", data[6:8])[0]
    return {"oui": bytes(data[3:6]), "ethertype": et, "name": ETHERTYPES.get(et), "data": bytes(data[8:])}


def parse_arp(d):
    """ARP（以太网 + IPv4，28 字节）：{"op", "sha", "spa", "tha", "tpa"}。其它硬件 / 协议类型返回 None。"""
    if len(d) < 28:
        return None
    htype, ptype, hlen, plen, op = struct.unpack(">HHBBH", d[:8])
    if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4):
        return None
    return {"op": op, "sha": bytes(d[8:14]), "spa": ip4(d[14:18]), "tha": bytes(d[18:24]), "tpa": ip4(d[24:28])}


def parse_ipv4(d):
    """IPv4：{"ihl", "tos", "total_length", "id", "flags", "frag_offset", "ttl", "proto", "checksum", "checksum_ok", "src", "dst", "payload"}。
    payload 按 total_length 截取（链路层填充不算）；total_length 超过实际数据时取实际数据并标 truncated。"""
    if len(d) < 20 or d[0] >> 4 != 4:
        return None
    ihl = (d[0] & 15) * 4
    if ihl < 20 or len(d) < ihl:
        return None
    tos, total, ident, ff, ttl, proto, csum = struct.unpack(">BHHHBBH", d[1:12])
    if total < ihl:
        return None
    end = min(total, len(d))
    return {"ihl": ihl, "tos": tos, "total_length": total, "id": ident, "flags": ff >> 13, "frag_offset": ff & 0x1FFF, "ttl": ttl, "proto": proto,
            "checksum": csum, "checksum_ok": checksum(d[:ihl]) == 0, "src": ip4(d[12:16]), "dst": ip4(d[16:20]), "options": bytes(d[20:ihl]),
            "payload": bytes(d[ihl:end]), "truncated": total > len(d)}


def parse_ipv6(d):
    """IPv6：{"traffic_class", "flow", "payload_length", "next_header", "hop_limit", "src", "dst", "proto", "payload"}。
    proto / payload 跳过逐跳、路由、目的地选项、分片扩展头后的上层协议；分片偏移非 0 的分片没有上层头，proto 为 None。"""
    if len(d) < 40 or d[0] >> 4 != 6:
        return None
    vtf, plen, nh, hop = struct.unpack(">IHBB", d[:8])
    end = min(40 + plen, len(d))
    proto, p = nh, 40
    while proto in (0, 43, 60, 44) and p + 8 <= end:
        if proto == 44:
            if struct.unpack(">H", d[p + 2:p + 4])[0] >> 3:
                proto = None
                break
            nxt, p = d[p], p + 8
        else:
            nxt, p = d[p], p + (d[p + 1] + 1) * 8
        proto = nxt
    return {"traffic_class": vtf >> 20 & 0xFF, "flow": vtf & 0xFFFFF, "payload_length": plen, "next_header": nh, "hop_limit": hop,
            "src": ip6(d[8:24]), "dst": ip6(d[24:40]), "proto": proto, "payload": bytes(d[p:end]) if proto is not None else b"", "src_raw": bytes(d[8:24]), "dst_raw": bytes(d[24:40])}


def pseudo_header(ip, proto, length):
    """UDP / TCP / ICMPv6 校验和用的伪头。ip 是 parse_ipv4 或 parse_ipv6 的结果。"""
    if "src_raw" in ip:
        return ip["src_raw"] + ip["dst_raw"] + struct.pack(">IBBBB", length, 0, 0, 0, proto)
    return bytes(int(x) for x in ip["src"].split(".")) + bytes(int(x) for x in ip["dst"].split(".")) + struct.pack(">BBH", 0, proto, length)


def parse_udp(d, ip=None):
    """UDP：{"sport", "dport", "length", "checksum", "checksum_ok", "payload"}。IPv4 的校验和字段为 0 表示没算（checksum_ok 为 None）；
    没给 ip（无法算伪头）时 checksum_ok 为 None。"""
    if len(d) < 8:
        return None
    sport, dport, length, csum = struct.unpack(">HHHH", d[:8])
    if length < 8:
        return None
    seg = d[:min(length, len(d))]
    ok = None
    if ip is not None and not (csum == 0 and "src_raw" not in ip) and len(seg) == length:
        ok = checksum(pseudo_header(ip, 17, length) + seg) == 0
    return {"sport": sport, "dport": dport, "length": length, "checksum": csum, "checksum_ok": ok, "payload": bytes(d[8:min(length, len(d))])}


def parse_tcp(d, ip=None):
    """TCP：{"sport", "dport", "seq", "ack", "flags", "window", "checksum", "checksum_ok", "payload"}。"""
    if len(d) < 20:
        return None
    sport, dport, seq, ack, off_flags, window, csum, _urg = struct.unpack(">HHIIHHHH", d[:20])
    hl = (off_flags >> 12) * 4
    if hl < 20 or len(d) < hl:
        return None
    ok = None
    if ip is not None:
        ok = checksum(pseudo_header(ip, 6, len(d)) + d) == 0
    return {"sport": sport, "dport": dport, "seq": seq, "ack": ack, "flags": off_flags & 0x1FF, "window": window, "checksum": csum, "checksum_ok": ok, "payload": bytes(d[hl:])}


def parse_icmp(d, ip=None):
    """ICMP（IPv4）/ ICMPv6：{"type", "code", "checksum", "checksum_ok", "body"}。ICMPv6 的校验和含伪头，要给 ip（IPv6 的结果）。"""
    if len(d) < 4:
        return None
    t, c, csum = struct.unpack(">BBH", d[:4])
    if ip is not None and "src_raw" in ip:
        ok = checksum(pseudo_header(ip, 58, len(d)) + d) == 0
    elif ip is not None:
        ok = checksum(d) == 0
    else:
        ok = None
    return {"type": t, "code": c, "checksum": csum, "checksum_ok": ok, "body": bytes(d[4:])}


DNS_PORTS = {53, 5353}                                                  # DNS 和 mDNS，报文格式相同
DHCP_MAGIC = b"\x63\x82\x53\x63"
DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}


def parse_dhcp(d):
    """DHCP（BOOTP 固定 236 字节 + 魔数 + 选项）：{"op", "xid", "ciaddr", "yiaddr", "siaddr", "giaddr", "chaddr", "options"{码: 数据}, "message_type", "message"}。
    魔数不对或不足 240 字节返回 None。"""
    if len(d) < 240 or d[236:240] != DHCP_MAGIC:
        return None
    op, htype, hlen = d[0], d[1], d[2]
    xid = struct.unpack(">I", d[4:8])[0]
    opts, p = {}, 240
    while p < len(d):
        code = d[p]
        if code == 255:
            break
        if code == 0:
            p += 1
            continue
        if p + 2 > len(d) or p + 2 + d[p + 1] > len(d):
            break
        opts.setdefault(code, bytes(d[p + 2:p + 2 + d[p + 1]]))
        p += 2 + d[p + 1]
    mt = opts[53][0] if 53 in opts and len(opts[53]) == 1 else None
    return {"op": op, "htype": htype, "xid": xid, "ciaddr": ip4(d[12:16]), "yiaddr": ip4(d[16:20]), "siaddr": ip4(d[20:24]), "giaddr": ip4(d[24:28]),
            "chaddr": bytes(d[28:28 + min(hlen, 16)]), "options": opts, "message_type": mt, "message": DHCP_TYPES.get(mt)}


def describe(msdu):
    """一个 MSDU（LLC/SNAP 开头）-> {"layers": [...], "arp"/"ip"/"udp"/"tcp"/"icmp"/"dhcp": ..., "checksums_ok": 所有校验和是否都吻合（没有校验和可查为 None）}。
    不是 SNAP（也不是生成树的 LLC）返回 None。层名按从下到上排列，如 ["snap", "ipv4", "udp", "dhcp"]。"""
    if len(msdu) >= 3 and msdu[:3] == LLC_STP:                      # 生成树 BPDU：LLC 的 DSAP / SSAP = 0x42，不带 SNAP
        return {"layers": ["llc", "stp"], "ethertype": None, "checks": [], "stp": bytes(msdu[3:])}
    s = parse_snap(msdu)
    if s is None:
        logs.trace(log, "MSDU 不是 LLC/SNAP（%d 字节，开头 %s）", len(msdu), bytes(msdu[:8]).hex())
        return None
    out = {"layers": ["snap"], "ethertype": s["ethertype"], "checks": []}
    ip = None
    if s["name"] == "arp":
        a = parse_arp(s["data"])
        if a:
            out["layers"].append("arp")
            out["arp"] = a
        return out
    if s["name"] == "ipv4":
        ip = parse_ipv4(s["data"])
        proto = ip["proto"] if ip else None
        if ip:
            out["layers"].append("ipv4")
            out["ip"] = ip
            out["checks"].append(ip["checksum_ok"])
            if ip["frag_offset"] or ip["flags"] & 1:                 # 分片：没有完整的上层数据
                return out
    elif s["name"] == "ipv6":
        ip = parse_ipv6(s["data"])
        proto = ip["proto"] if ip else None
        if ip:
            out["layers"].append("ipv6")
            out["ip"] = ip
    else:
        return out
    if ip is None or proto is None:
        return out
    pl = ip["payload"]
    if proto == 17:
        u = parse_udp(pl, ip)
        if u:
            out["layers"].append("udp")
            out["udp"] = u
            if u["checksum_ok"] is not None:
                out["checks"].append(u["checksum_ok"])
            if {u["sport"], u["dport"]} & {67, 68}:
                dh = parse_dhcp(u["payload"])
                if dh:
                    out["layers"].append("dhcp")
                    out["dhcp"] = dh
            elif {u["sport"], u["dport"]} & DNS_PORTS:
                q = dns80211.parse(u["payload"])
                if q:
                    out["layers"].append("dns")
                    out["dns"] = q
    elif proto == 6:
        t = parse_tcp(pl, ip)
        if t:
            out["layers"].append("tcp")
            out["tcp"] = t
            out["checks"].append(t["checksum_ok"])
    elif proto in (1, 58):
        i = parse_icmp(pl, ip)
        if i:
            out["layers"].append("icmp" if proto == 1 else "icmpv6")
            out["icmp"] = i
            out["checks"].append(i["checksum_ok"])
    return out
