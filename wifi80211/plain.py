# -*- coding: utf-8 -*-
"""
没有 802.11 加密的抓包（在网关 / 路由器 / 交换机镜像口抓的，链路类型是以太网 1，或 `tcpdump -i any` 产生的 Linux cooked 113 / 276）：
读成包，判断每个包属于哪台设备、是不是设备发出的，再交给 activity.Collector——和 802.11 走同一套 DNS / TLS / HTTP / QUIC 识别和流量累计。纯标准库。

怎么判断「哪台设备、上行还是下行」（只看 IP 地址和 MAC，不看端口）：
  局域网地址 = 10/8、172.16/12、192.168/16、169.254/16、IPv6 的 fc00::/7 和 fe80::/10；公网地址 = 其它单播地址；组播 / 广播 / 未指定地址不算设备。
  1. 源是局域网、目的是公网或组播：上行，设备 = 以太网源 MAC。
  2. 源是公网、目的是局域网：下行，设备 = 以太网目的 MAC。
  3. 两端都在局域网：源 MAC 是路由器（见下）就是下行（设备 = 目的 MAC）；其余都是上行（设备 = 源 MAC）——发给路由器的是设备发出的，两个设备之间的流量按发送方记。
     （cooked 抓包没有目的 MAC：本机发出的包 pkt_type=4 是下行，设备靠 IP -> MAC 表认；别人发来的是上行。）
  4. 其它（两端都是公网、组播来源…）：不归任何设备。
  路由器 MAC 是从抓包里学的：把局域网地址的包发给公网时它的目的 MAC，和公网来的包它的源 MAC。
Linux cooked 头里没有目的 MAC：设备 MAC 只能取「别人发来的、源是局域网地址」的包的链路层源地址，并学到「IP -> MAC」，下行包靠这张表认设备；
`-i any` 会把同一个包在不同接口各抓一次，请在局域网一侧的接口上抓（`tcpdump -i eth0`），不要用 `-i any`。

重要：设备的 MAC 只有在局域网一侧才看得到。在路由器后面（WAN 一侧）、或做过 NAT 之后抓，所有包的 MAC 都是路由器的，设备分不开。
"""
import ipaddress
import struct
from collections import namedtuple

from . import activity, capture

ETHERNET, LINUX_SLL, LINUX_SLL2 = 1, 113, 276
DOT11_LINKTYPES = (105, 127)
PLAIN_LINKTYPES = (ETHERNET, LINUX_SLL, LINUX_SLL2)
LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00"
VLAN_TAGS = (0x8100, 0x88A8)
ARPHRD_ETHER = 1
PACKET_OUTGOING = 4                                                   # cooked 头里的 pkt_type：本机发出的包

# n：包号（从 1 起，和 tshark 的 frame.number 一致）；src / dst：链路层地址（小写冒号，没有是 None）；ethertype；l3：以太类型之后的字节；cooked：来自 Linux cooked 头；pkt_type：cooked 头的包类型
Packet = namedtuple("Packet", "n ts src dst ethertype l3 cooked pkt_type")
LAN_NETS = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10")]


def mac_str(b):
    return ":".join("%02x" % x for x in b)


def kind(cap):
    """"dot11" | "plain" | None：抓包里有 802.11（radiotap / 裸 802.11）就是 dot11；只有以太网 / cooked 就是 plain；别的链路类型没有支持。"""
    types = {p.linktype for p in cap.packets}
    if types & set(DOT11_LINKTYPES):
        return "dot11"
    if types & set(PLAIN_LINKTYPES):
        return "plain"
    return None


def parse_packet(n, pkt):
    """一个抓包里的包 -> Packet，不认识的链路类型 / 太短返回 None。"""
    d, lt = pkt.data, pkt.linktype
    if lt == ETHERNET:
        if len(d) < 14:
            return None
        et, off = struct.unpack(">H", d[12:14])[0], 14
        while et in VLAN_TAGS and len(d) >= off + 4:                    # 802.1Q / QinQ 标签：跳过，取里面的以太类型
            et, off = struct.unpack(">H", d[off + 2:off + 4])[0], off + 4
        return Packet(n, pkt.ts, mac_str(d[6:12]), mac_str(d[0:6]), et, d[off:], False, None)
    if lt == LINUX_SLL:
        if len(d) < 16:
            return None
        ptype, arphrd, alen = struct.unpack(">HHH", d[0:6])
        src = mac_str(d[6:12]) if arphrd == ARPHRD_ETHER and alen == 6 else None
        return Packet(n, pkt.ts, src, None, struct.unpack(">H", d[14:16])[0], d[16:], True, ptype)
    if lt == LINUX_SLL2:
        if len(d) < 20:
            return None
        proto = struct.unpack(">H", d[0:2])[0]
        arphrd, ptype, alen = struct.unpack(">HBB", d[8:12])
        src = mac_str(d[12:18]) if arphrd == ARPHRD_ETHER and alen == 6 else None
        return Packet(n, pkt.ts, src, None, proto, d[20:], True, ptype)
    return None


def iter_packets(cap):
    """cap：capture.read_capture 的结果 -> 所有认得的包（包号照抓包里的顺序数，不认得的也占号）。"""
    out = []
    for n, p in enumerate(cap.packets, 1):
        q = parse_packet(n, p)
        if q is not None:
            out.append(q)
    return out


def addresses(pkt):
    """-> (源 IP, 目的 IP) 的 ipaddress 对象；不是 IPv4 / IPv6 或头不完整返回 None。"""
    l3 = pkt.l3
    try:
        if pkt.ethertype == 0x0800 and len(l3) >= 20 and l3[0] >> 4 == 4:
            return ipaddress.IPv4Address(l3[12:16]), ipaddress.IPv4Address(l3[16:20])
        if pkt.ethertype == 0x86DD and len(l3) >= 40 and l3[0] >> 4 == 6:
            return ipaddress.IPv6Address(l3[8:24]), ipaddress.IPv6Address(l3[24:40])
    except ValueError:
        return None
    return None


def scope(a):
    """"lan" | "pub" | "other"（组播、广播、未指定、环回）。"""
    if a.is_multicast or a.is_unspecified or a.is_loopback or a == ipaddress.IPv4Address("255.255.255.255"):
        return "other"
    return "lan" if any(a in n for n in LAN_NETS if n.version == a.version) else "pub"


def learn(packets):
    """第一遍：学路由器的 MAC，和 cooked 抓包里的 IP -> MAC。-> (路由器 MAC 集合, {IP 字符串: MAC})。"""
    routers, ip_mac = set(), {}
    for p in packets:
        ad = addresses(p)
        if ad is None:
            continue
        s, d = scope(ad[0]), scope(ad[1])
        if not p.cooked:
            if s == "lan" and d == "pub" and p.dst:
                routers.add(p.dst)
            elif s == "pub" and d == "lan" and p.src:
                routers.add(p.src)
        if s == "lan" and p.src and p.pkt_type != PACKET_OUTGOING:
            ip_mac.setdefault(str(ad[0]), p.src)
    return routers, ip_mac


def classify(p, routers, ip_mac):
    """-> (设备 MAC 或 None, 上行 True / 下行 False / None)。规则见模块说明。"""
    ad = addresses(p)
    if ad is None:
        return None, None
    s, d = scope(ad[0]), scope(ad[1])
    if s == "lan" and d in ("pub", "other"):
        return (p.src if p.pkt_type != PACKET_OUTGOING else None), True
    if s == "pub" and d == "lan":
        return (ip_mac.get(str(ad[1])) if p.cooked else (None if p.dst in routers else p.dst)), False
    if s == "lan" and d == "lan":
        if p.cooked:
            if p.pkt_type == PACKET_OUTGOING:                                        # 本机（网关）发给局域网设备的包：靠 IP -> MAC 认收的是哪台
                return ip_mac.get(str(ad[1])), False
            return p.src, True
        if p.src in routers:
            return p.dst, False
        return p.src, True
    return None, None


def analyze(packets):
    """已解析的包 -> 已 finish 的 activity.Collector（.events、.flow_stats、.names、.answers）。"""
    routers, ip_mac = learn(packets)
    c = activity.Collector()
    for p in packets:
        st, up = classify(p, routers, ip_mac)
        c.feed(p.n, p.ts, st, [LLC_SNAP + struct.pack(">H", p.ethertype) + p.l3], up)
    return c.finish()
