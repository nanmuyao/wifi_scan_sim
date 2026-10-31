#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""net80211：LLC/SNAP、ARP、IPv4 / IPv6、UDP / TCP / ICMP / ICMPv6、DHCP 的最小解析和校验和。用 scapy 当独立的包构造器（它自己算校验和）；
真实抓包解密后的内容由 tests/oracle/test_net_diff.py 对 tshark。"""
import logging
import os
import struct
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IPv6ExtHdrDestOpt, ARP, DHCP, ICMP, IP, TCP, UDP, BOOTP, Ether, IPv6, ICMPv6EchoRequest, ICMPv6ND_NS, IPv6ExtHdrHopByHop, IPv6ExtHdrFragment, Raw, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wifi80211 import net  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


SNAP = lambda et: b"\xaa\xaa\x03\x00\x00\x00" + struct.pack(">H", et)       # noqa: E731
raw = lambda pkt: bytes(pkt)                                                   # noqa: E731

print("== 校验和 ==")
hdr = bytes.fromhex("4500007300004000" "4011" "0000" "c0a80001c0a800c7")
check(net.checksum(hdr) == 0xb861, "维基百科的 IPv4 头示例：校验和 0xb861")
check(net.checksum(hdr[:10] + b"\xb8\x61" + hdr[12:]) == 0, "把校验和填回去：整体为 0")
check(net.checksum(b"\x01") == net.checksum(b"\x01\x00") and net.checksum(b"") == 0xFFFF, "奇数长度补 0 字节；空数据 0xFFFF")
check(net.checksum(bytes.fromhex("0001f203f4f5f6f7")) == 0x220d, "RFC 1071 的例子（00 01 f2 03 f4 f5 f6 f7 的和 ddf2 取反 220d）")

check(net.checksum(bytes.fromhex("ffffffff0001")) == 0xFFFE, "进位要折叠到底：和是 0x1FFFF 时折一次得 0x10000，还要再折一次（结果 0xFFFE）")

print("== LLC/SNAP ==")
s = net.parse_snap(SNAP(0x0800) + b"data")
check(s == {"oui": b"\0\0\0", "ethertype": 0x0800, "name": "ipv4", "data": b"data"}, "OUI、以太类型（大端）、数据")
check(net.parse_snap(b"\xaa\xaa\x03\x00\x00\x00\x12\x34")["name"] is None and net.parse_snap(b"\xaa\xaa\x03\x00\x00\x00\x08") is None and net.parse_snap(b"\xab\xaa\x03\x00\x00\x00\x08\x00") is None, "不认识的以太类型：name 为 None；太短 / 不是 AA AA 03：None")
check(net.parse_snap(SNAP(0x86dd))["name"] == "ipv6" and net.parse_snap(SNAP(0x0806))["name"] == "arp" and net.parse_snap(SNAP(0x888e))["name"] == "eapol", "IPv6 / ARP / EAPOL 的名字")

print("== ARP ==")
a = ARP(op=2, hwsrc="02:00:00:00:00:01", psrc="10.1.2.3", hwdst="02:00:00:00:00:02", pdst="10.4.5.6")
r = net.parse_arp(raw(a))
check(r == {"op": 2, "sha": bytes.fromhex("020000000001"), "spa": "10.1.2.3", "tha": bytes.fromhex("020000000002"), "tpa": "10.4.5.6"}, "操作码、发送方 / 目标方的 MAC 和 IP 的位置")
check(net.parse_arp(raw(a)[:27]) is None and net.parse_arp(raw(ARP(hwtype=6))) is None and net.parse_arp(raw(ARP(ptype=0x86dd))) is None, "不足 28 字节 / 硬件类型不是以太网 / 协议不是 IPv4：None")

print("== IPv4 ==")
pkt = raw(IP(src="192.0.2.1", dst="198.51.100.7", ttl=33, id=0x1234, flags="DF", tos=0x10) / ICMP(type=8, id=1, seq=2) / Raw(b"hello"))
ip = net.parse_ipv4(pkt)
check((ip["ihl"], ip["tos"], ip["id"], ip["flags"], ip["frag_offset"], ip["ttl"], ip["proto"], ip["src"], ip["dst"]) == (20, 0x10, 0x1234, 2, 0, 33, 1, "192.0.2.1", "198.51.100.7"), "IPv4 头各字段")
check(ip["checksum_ok"] and ip["total_length"] == len(pkt) and ip["payload"] == pkt[20:] and not ip["truncated"], "头校验和吻合、total_length、负载")
check(net.parse_ipv4(pkt + b"\x00" * 6)["payload"] == pkt[20:], "链路层填充（total_length 之外的字节）不算负载")
check(net.parse_ipv4(pkt[:-3])["truncated"] and net.parse_ipv4(pkt[:-3])["payload"] == pkt[20:-3], "total_length 超过实际数据：truncated，负载取实际的")
bad = bytearray(pkt)
bad[8] ^= 1
check(net.parse_ipv4(bytes(bad))["checksum_ok"] is False, "TTL 变了一位：头校验和不吻合")
opt = raw(IP(src="1.1.1.1", dst="2.2.2.2", options=[]) / UDP(sport=1, dport=2) / Raw(b"x"))
ip_o = net.parse_ipv4(raw(IP(src="1.1.1.1", dst="2.2.2.2", options=b"\x01\x01\x01\x01") / UDP(sport=1, dport=2) / Raw(b"x")))
check(ip_o["ihl"] == 24 and ip_o["options"] == b"\x01\x01\x01\x01" and ip_o["checksum_ok"] and len(ip_o["payload"]) == 9, "带选项（IHL 6）：头 24 字节，选项和负载的边界")
check(net.parse_ipv4(pkt[:19]) is None and net.parse_ipv4(b"\x65" + pkt[1:]) is None and net.parse_ipv4(b"\x44" + pkt[1:]) is None and net.parse_ipv4(pkt[:2] + b"\x00\x10" + pkt[4:]) is None, "不足 20 字节 / 版本不是 4 / IHL < 5 / total_length < IHL：None")
frag = net.describe(SNAP(0x0800) + raw(IP(src="1.1.1.1", dst="2.2.2.2", flags="MF") / UDP(sport=1, dport=2) / Raw(b"x")))
check(frag["layers"] == ["snap", "ipv4"], "分片（MF 或偏移非 0）：不往上解")

print("== UDP / TCP / ICMP ==")
def stack(*layers):
    p = layers[0]
    for l in layers[1:]:
        p = p / l
    return SNAP(0x0800) + raw(p)


d = net.describe(stack(IP(src="10.0.0.1", dst="10.0.0.2"), UDP(sport=5353, dport=53), Raw(b"query")))
u = d["udp"]
check(d["layers"] == ["snap", "ipv4", "udp"] and (u["sport"], u["dport"], u["length"], u["payload"], u["checksum_ok"]) == (5353, 53, 13, b"query", True) and d["checks"] == [True, True], "UDP：端口、长度、负载、校验和（伪头）")
bad_udp = bytearray(stack(IP(src="10.0.0.1", dst="10.0.0.2"), UDP(sport=5353, dport=53), Raw(b"query")))
bad_udp[-1] ^= 1
check(net.describe(bytes(bad_udp))["udp"]["checksum_ok"] is False and net.describe(bytes(bad_udp))["checks"] == [True, False], "负载变了一位：UDP 校验和不吻合，IPv4 头仍吻合")
zero = bytearray(stack(IP(src="10.0.0.1", dst="10.0.0.2"), UDP(sport=1, dport=2), Raw(b"abcd")))
zero[34:36] = b"\x00\x00"
dz = net.describe(bytes(zero))
check(dz["udp"]["checksum_ok"] is None and dz["checks"] == [True], "IPv4 的 UDP 校验和为 0：没算，不判（None）")
t = net.describe(stack(IP(src="10.0.0.1", dst="10.0.0.2"), TCP(sport=40000, dport=80, flags="SA", seq=1000, ack=2000, window=777), Raw(b"GET")))
check(t["layers"] == ["snap", "ipv4", "tcp"] and (t["tcp"]["sport"], t["tcp"]["dport"], t["tcp"]["seq"], t["tcp"]["ack"], t["tcp"]["flags"], t["tcp"]["window"], t["tcp"]["payload"]) == (40000, 80, 1000, 2000, 0x12, 777, b"GET") and t["tcp"]["checksum_ok"], "TCP：端口、序号、确认号、标志（SYN|ACK = 0x12）、窗口、负载、校验和")
tb = bytearray(stack(IP(src="10.0.0.1", dst="10.0.0.2"), TCP(sport=1, dport=2), Raw(b"abc")))
tb[-1] ^= 1
check(net.describe(bytes(tb))["tcp"]["checksum_ok"] is False, "TCP 负载变了：校验和不吻合")
check(net.parse_tcp(bytes(19)) is None and net.parse_tcp(b"\x00" * 12 + b"\x40" + b"\x00" * 7) is None, "TCP 不足 20 字节 / 数据偏移 < 5：None")
i = net.describe(stack(IP(src="10.0.0.1", dst="10.0.0.2"), ICMP(type=8, id=7, seq=9), Raw(b"ping")))
check(i["layers"] == ["snap", "ipv4", "icmp"] and (i["icmp"]["type"], i["icmp"]["code"], i["icmp"]["checksum_ok"]) == (8, 0, True), "ICMP 回显请求：类型、校验和")
ib = bytearray(stack(IP(src="10.0.0.1", dst="10.0.0.2"), ICMP(type=8), Raw(b"ping")))
ib[-1] ^= 1
check(net.describe(bytes(ib))["icmp"]["checksum_ok"] is False, "ICMP 负载变了：校验和不吻合")
check(net.parse_udp(bytes(7)) is None and net.parse_udp(struct.pack(">HHHH", 1, 2, 7, 0)) is None and net.parse_icmp(b"\x08\x00\x00") is None, "UDP 不足 8 字节 / 长度字段 < 8；ICMP 不足 4 字节：None")
ipx = net.parse_ipv4(raw(IP(src="1.1.1.1", dst="2.2.2.2") / UDP()))
check(net.parse_udp(struct.pack(">HHHH", 1, 2, 20, 5) + b"abcd", ipx)["checksum_ok"] is None and net.parse_udp(struct.pack(">HHHH", 1, 2, 12, 5) + b"abcd")["checksum_ok"] is None, "UDP 长度字段超过实际数据：不判校验和；没给 ip：判不了")

print("== IPv6 ==")
v6 = SNAP(0x86dd) + raw(IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=64, tc=0xA0, fl=0x12345) / ICMPv6EchoRequest(id=3, seq=4, data=b"hi"))
d6 = net.describe(v6)
ip6 = d6["ip"]
check(d6["layers"] == ["snap", "ipv6", "icmpv6"] and (ip6["src"], ip6["dst"], ip6["hop_limit"], ip6["traffic_class"], ip6["flow"], ip6["next_header"]) == ("2001:db8:0:0:0:0:0:1", "2001:db8:0:0:0:0:0:2", 64, 0xA0, 0x12345, 58), "IPv6 头各字段（地址写成 8 组十六进制）")
check(d6["icmp"]["type"] == 128 and d6["icmp"]["checksum_ok"] is True and d6["checks"] == [True], "ICMPv6 回显请求：校验和含伪头，吻合")
v6b = bytearray(v6)
v6b[8 + 24 - 1] ^= 1                                                       # 改目的地址最后一个字节：伪头变了，校验和对不上
check(net.describe(bytes(v6b))["icmp"]["checksum_ok"] is False, "改了目的地址：ICMPv6 校验和不吻合（证明伪头里用了地址）")
dh = net.describe(SNAP(0x86dd) + raw(IPv6(src="fe80::1", dst="ff02::1") / IPv6ExtHdrHopByHop() / UDP(sport=5, dport=6) / Raw(b"zz")))
check(dh["layers"] == ["snap", "ipv6", "udp"] and dh["ip"]["next_header"] == 0 and dh["ip"]["proto"] == 17 and dh["udp"]["checksum_ok"] is True and dh["udp"]["payload"] == b"zz", "逐跳选项扩展头：跳过后找到 UDP，校验和仍吻合")
fg = net.describe(SNAP(0x86dd) + raw(IPv6(src="fe80::1", dst="ff02::1") / IPv6ExtHdrFragment(offset=5, m=1, nh=17) / Raw(b"zzzzzzzz")))
check(fg["layers"] == ["snap", "ipv6"] and fg["ip"]["proto"] is None, "分片偏移非 0 的 IPv6 分片：没有上层头，proto 为 None")
ff = net.describe(SNAP(0x86dd) + raw(IPv6(src="fe80::1", dst="ff02::1") / IPv6ExtHdrFragment(offset=0, m=1, nh=17) / UDP(sport=1, dport=2) / Raw(b"zz")))
check(ff["ip"]["proto"] == 17, "偏移为 0 的第一个分片：能找到上层协议")
check(net.parse_ipv6(bytes(39)) is None and net.parse_ipv6(b"\x40" + bytes(39)) is None, "IPv6 不足 40 字节 / 版本不是 6：None")
ns = net.describe(SNAP(0x86dd) + raw(IPv6(src="fe80::1", dst="ff02::1") / ICMPv6ND_NS(tgt="fe80::2")))
check(ns["icmp"]["type"] == 135 and ns["icmp"]["checksum_ok"], "邻居请求（类型 135）")
u6 = net.describe(SNAP(0x86dd) + raw(IPv6(src="::1", dst="::1") / UDP(sport=1, dport=2) / Raw(b"abc")))
z6 = bytearray(SNAP(0x86dd) + raw(IPv6(src="::1", dst="::1") / UDP(sport=1, dport=2) / Raw(b"abc")))
z6[8 + 40 + 6:8 + 40 + 8] = b"\x00\x00"
check(u6["udp"]["checksum_ok"] and net.describe(bytes(z6))["udp"]["checksum_ok"] is False, "IPv6 的 UDP 校验和为 0 是不合法的：判不吻合（IPv4 才允许 0）")

tf = net.describe(stack(IP(src="10.0.0.1", dst="10.0.0.2"), TCP(sport=1, dport=2, flags="SN"), Raw(b"x")))
check(tf["tcp"]["flags"] == 0x102, "TCP 标志取 9 位（NS 在第 8 位）：SYN|NS = 0x102")

print("== IPv6 补充 ==")
v6p = SNAP(0x86dd) + raw(IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(id=3, seq=4, data=b"hi"))
dp = net.describe(v6p + b"\x00" * 6)
check(dp["ip"]["payload"] == net.describe(v6p)["ip"]["payload"] and dp["icmp"]["checksum_ok"] is True, "IPv6 包后面的链路层填充：按 payload_length 截取，不进负载，校验和仍吻合")
do = net.describe(SNAP(0x86dd) + raw(IPv6(src="fe80::1", dst="ff02::1") / IPv6ExtHdrDestOpt() / UDP(sport=5, dport=6) / Raw(b"zz")))
check(do["layers"] == ["snap", "ipv6", "udp"] and do["ip"]["next_header"] == 60 and do["udp"]["checksum_ok"] is True, "目的地选项扩展头（60）：跳过")
fr0 = bytearray(SNAP(0x86dd) + raw(IPv6(src="fe80::1", dst="ff02::1") / IPv6ExtHdrFragment(offset=0, m=1, nh=17) / UDP(sport=1, dport=2) / Raw(b"zz")))
fr0[8 + 40 + 2:8 + 40 + 4] = b"\x00\x06"                    # 偏移 0，保留位 0b110（低 3 位里的保留位）+ M = 0：只有「偏移」那 13 位才算偏移
check(net.describe(bytes(fr0))["ip"]["proto"] == 17, "分片头的保留位不算偏移：偏移为 0 的仍是第一个分片")

print("== DHCP ==")
dhcp = raw(BOOTP(op=2, xid=0xdeadbeef, yiaddr="192.168.1.50", siaddr="192.168.1.1", chaddr=bytes.fromhex("020000000001") + bytes(10), giaddr="0.0.0.0") / DHCP(options=[("message-type", "ack"), ("server_id", "192.168.1.1"), "end"]))
dd = net.parse_dhcp(dhcp)
check((dd["op"], dd["xid"], dd["yiaddr"], dd["siaddr"], dd["chaddr"], dd["message_type"], dd["message"]) == (2, 0xdeadbeef, "192.168.1.50", "192.168.1.1", bytes.fromhex("020000000001"), 5, "ACK"), "DHCP ACK：op、xid、yiaddr、siaddr、chaddr（6 字节）、选项 53")
check(dd["options"][54] == bytes([192, 168, 1, 1]), "选项表：54（服务器标识）")
dcover = net.parse_dhcp(raw(BOOTP(xid=1) / DHCP(options=[("message-type", "discover"), "pad", ("hostname", "x"), "end"])))
check(dcover["message"] == "Discover" and dcover["options"][12] == b"x", "Discover；填充（0）被跳过，主机名选项 12")
dup = net.parse_dhcp(dhcp[:240] + bytes([53, 1, 1, 53, 1, 5, 255]))
check(dup["message_type"] == 1 and dup["options"][53] == b"\x01", "同一个选项出现两次：取第一个")
c68 = net.describe(stack(IP(src="1.1.1.1", dst="2.2.2.2"), UDP(sport=68, dport=5000), Raw(dhcp)))
c67 = net.describe(stack(IP(src="1.1.1.1", dst="2.2.2.2"), UDP(sport=5000, dport=67), Raw(dhcp)))
check(c67["layers"][-1] == "dhcp", "目的端口 67、源端口别的：也当 DHCP")
check(c68["layers"][-1] == "dhcp", "源端口 68（客户端）、目的端口别的：也当 DHCP（67 或 68 任一端即可）")
check(net.parse_dhcp(dhcp[:239]) is None and net.parse_dhcp(dhcp[:236] + b"\x00\x00\x00\x00" + dhcp[240:]) is None, "不足 240 字节 / 魔数不对：None")
trunc = net.parse_dhcp(dhcp[:240] + bytes([53, 1]))
check(trunc is not None and 53 not in trunc["options"] and trunc["message_type"] is None, "选项被截断：不收残缺的选项")
full = net.describe(stack(IP(src="192.168.1.1", dst="192.168.1.50"), UDP(sport=67, dport=68), Raw(dhcp)))
check(full["layers"] == ["snap", "ipv4", "udp", "dhcp"] and full["dhcp"]["message"] == "ACK" and full["checks"] == [True, True], "整条栈 snap/ipv4/udp/dhcp，所有校验和吻合")
check(net.describe(stack(IP(src="1.1.1.1", dst="2.2.2.2"), UDP(sport=1000, dport=2000), Raw(dhcp)))["layers"] == ["snap", "ipv4", "udp"], "端口不是 67 / 68：不当 DHCP")

print("== describe：其它 ==")
check(net.describe(b"\x42\x42\x03\x00\x00\x00\x00\x00") == {"layers": ["llc", "stp"], "ethertype": None, "checks": [], "stp": b"\x00\x00\x00\x00\x00"}, "生成树 BPDU（LLC 42 42 03）")
check(net.describe(b"\x01\x02\x03") is None and net.describe(b"") is None and net.describe(b"\x42\x42\x00\x00") is None, "不是 SNAP 也不是生成树（LLC 42 42 但控制字段不是 03）：None")
check(net.describe(SNAP(0x888e) + b"\x02\x03")["layers"] == ["snap"], "EAPOL 等别的以太类型：只到 snap")
check(net.describe(SNAP(0x0806) + b"\x00" * 10)["layers"] == ["snap"], "ARP 数据太短：只到 snap")
check(net.describe(SNAP(0x0800) + b"\x45" + bytes(5))["layers"] == ["snap"], "IPv4 数据太短：只到 snap")
check(net.ip4(bytes([1, 2, 3, 4])) == "1.2.3.4" and net.ip6(bytes(15) + b"\x01") == "0:0:0:0:0:0:0:1", "地址格式")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
