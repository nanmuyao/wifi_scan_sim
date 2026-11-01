#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TCP 上的 DNS（2 字节长度前缀）对照 tshark：scapy 构造的普通以太网 pcap，6 条连接——一段一条消息、长度前缀被拆在两个段里、一段里两条消息、
一条消息拆成三段且乱序、查询加应答、中途开始没有 SYN。每个方向里解出的 DNS 消息（方向、QR、名字、类型、应答里的 A）和 tshark 的 dns.* 字段相同。"""
import logging
import os
import struct
import subprocess
import sys
import tempfile

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, Ether, Raw, conf, wrpcap  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
from wifi80211 import activity, net, tcpstream  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


A, B = "10.2.2.2", "10.2.2.53"


def q(name, ident, qtype="A"):
    m = bytes(DNS(id=ident, rd=1, qd=DNSQR(qname=name, qtype=qtype)))
    return struct.pack(">H", len(m)) + m


def r(name, ident, addr):
    m = bytes(DNS(id=ident, qr=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type="A", rdata=addr)))
    return struct.pack(">H", len(m)) + m


def pk(src, dst, sport, dport, seq, data=b"", flags="PA"):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, ack=1, flags=flags) / Raw(data)


def conn(port, isn, client_chunks, server_data=b"", syn=True):
    """client_chunks：[(相对偏移, 字节)]，按给出的顺序发送。"""
    out = []
    if syn:
        out += [pk(A, B, port, 53, isn, flags="S"), pk(B, A, 53, port, 9000, flags="SA")]
    out += [pk(A, B, port, 53, isn + 1 + off, x) for off, x in client_chunks]
    if server_data:
        out.append(pk(B, A, 53, port, 9001, server_data))
    return out


pkts = []
m1 = q("one.example", 1)
pkts += conn(41001, 100, [(0, m1)])
m2 = q("split.length.example", 2)
pkts += conn(41002, 100, [(0, m2[:1]), (1, m2[1:8]), (8, m2[8:])])
m3, m4 = q("first.example", 3), q("second.example", 4, "AAAA")
pkts += conn(41003, 100, [(0, m3 + m4)])
m5 = q("reordered.example", 5)
pkts += conn(41004, 100, [(20, m5[20:]), (0, m5[:10]), (10, m5[10:20])])
pkts += conn(41005, 100, [(0, q("asked.example", 6))], r("asked.example", 6, "192.0.2.77") + r("asked.example", 7, "192.0.2.78"))
m7 = q("midstream.example", 8)
pkts += conn(41006, 5000, [(0, m7)], syn=False)
path = os.path.join(tempfile.gettempdir(), "dns_tcp_synth.pcap")
wrpcap(path, pkts)

cmd = ["tshark", "-r", path, "-Y", "dns && tcp", "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "dns.flags.response", "-e", "dns.qry.name",
       "-e", "dns.qry.type", "-e", "dns.a"]
theirs = []
for line in subprocess.run(cmd, capture_output=True, text=True).stdout.split("\n"):
    if line:
        sp, dp, resp, names, types, addrs = line.split("\t")
        for rs, nm, ty in zip(resp.split("|"), names.split("|"), types.split("|")):
            theirs.append((int(sp), int(dp), rs == "True", nm, int(ty)))
        theirs += [(int(sp), int(dp), "A", a, 0) for a in addrs.split("|") if a]

flows = tcpstream.Flows()
for p in pkts:
    ip = net.parse_ipv4(bytes(p[IP]))
    flows.add(ip["src"], ip["dst"], net.parse_tcp(ip["payload"], ip))
mine = []
for (src, sport, dst, dport), d in flows.dirs.items():
    for msg in activity.dns_over_tcp(d.data()):
        for qq in msg["questions"]:
            mine.append((sport, dport, msg["response"], qq["name"], qq["type"]))
        mine += [(sport, dport, "A", a["data"], 0) for a in msg["answers"] if a["type"] == 1]
# 41004 是乱序到达的一条消息：tshark 不会把乱序的段重组成 DNS 消息，我们按序号拼好了；其余 5 条连接两边完全相同
ours_only = sorted(set(mine) - set(theirs), key=str)
check(ours_only == [(41004, 53, False, "reordered.example", 1)] and not set(theirs) - set(mine), "tshark 认出的 %d 项我们全有；只多出乱序那条消息：%s" % (len(theirs), ours_only))
check(sorted([x for x in mine if x not in ours_only], key=str) == sorted(theirs, key=str), "其余 5 条连接的消息逐项相同（含多重性）")
check(len(mine) == 11 and len([x for x in mine if x[2] is False]) == 7 and len([x for x in mine if x[2] == "A"]) == 2, "共 11 项：7 个查询、2 个应答里的提问、2 条 A 记录（长度前缀被拆开、一段两条消息、一段两个应答都在内）")
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
