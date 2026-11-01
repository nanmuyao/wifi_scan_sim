#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""明文抓包（在网关 / 局域网一侧抓的）整条链对照 tshark：合成一个以太网抓包（设备 + 路由器 + 服务器：DNS 查询与应答、拆成两段的 TLS ClientHello、明文 HTTP、QUIC Initial、
一条 UDP 流和一条没有名字的 UDP 流），再把同样的包改成 Linux cooked（113 与 276）各存一份。三份抓包都用 plain.analyze 读出事件和流量，和 tshark 比：
  - 事件里的域名（dns.qry.name / tls.handshake.extensions_server_name / http.host，QUIC 的 SNI）逐项相同；
  - 设备每条 TCP / UDP 流的上下行包数和 L3 字节（tshark 的 ip.len）逐流相同（方向按源 IP 是不是设备的 IP 判断）。"""
import collections
import logging
import os
import struct
import subprocess
import sys
import tempfile

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, TCP, UDP, Raw, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import quic_build as qb  # noqa: E402
import tls_build as tb  # noqa: E402
from wifi80211 import capture, plain  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


DEV, RTR = "02:00:00:00:00:01", "02:00:00:00:00:fe"
LAN, GW, SRV, WEB, QSRV = "192.168.1.20", "192.168.1.1", "203.0.113.80", "198.51.100.9", "203.0.113.99"
t = 1700000000.0
ch = tb.records(tb.hello([tb.sni_ext("secure.example.org"), tb.alpn_ext("h2")]))
dcid = bytes.fromhex("8394c8f03e515708")
pkts = []                                   # (时间, Ether 包)


def add(dt, src, dst, ip):
    pkts.append((t + dt, Ether(src=src, dst=dst) / ip))


add(0, DEV, RTR, IP(src=LAN, dst=GW) / UDP(sport=50123, dport=53) / DNS(id=7, qd=DNSQR(qname="secure.example.org")))
add(.01, RTR, DEV, IP(src=GW, dst=LAN) / UDP(sport=53, dport=50123) / DNS(id=7, qr=1, qd=DNSQR(qname="secure.example.org"), an=DNSRR(rrname="secure.example.org", type="A", rdata=SRV)))
add(.02, DEV, RTR, IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=100, flags="S"))
add(.03, RTR, DEV, IP(src=SRV, dst=LAN) / TCP(sport=443, dport=41000, seq=900, ack=101, flags="SA"))
add(.04, DEV, RTR, IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=101, ack=901, flags="PA") / Raw(ch[:40]))
add(.05, DEV, RTR, IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=141, ack=901, flags="PA") / Raw(ch[40:]))
add(.06, RTR, DEV, IP(src=SRV, dst=LAN) / TCP(sport=443, dport=41000, seq=901, ack=141 + len(ch) - 40, flags="PA") / Raw(b"\x16\x03\x03" + b"s" * 1000))
add(1, DEV, RTR, IP(src=LAN, dst=WEB) / TCP(sport=41001, dport=80, seq=500, flags="S"))
add(1.01, RTR, DEV, IP(src=WEB, dst=LAN) / TCP(sport=80, dport=41001, seq=700, ack=501, flags="SA"))
add(1.02, DEV, RTR, IP(src=LAN, dst=WEB) / TCP(sport=41001, dport=80, seq=501, ack=701, flags="PA") / Raw(b"GET /index.html HTTP/1.1\r\nHost: Plain.Example.net:80\r\n\r\n"))
add(1.03, RTR, DEV, IP(src=WEB, dst=LAN) / TCP(sport=80, dport=41001, seq=701, ack=571, flags="PA") / Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
add(2, DEV, RTR, IP(src=LAN, dst=QSRV) / UDP(sport=52000, dport=443) / Raw(qb.build(dcid, b"\x01\x02", qb.crypto_frame(0, qb.client_hello("quic.example.com")))))
add(2.1, RTR, DEV, IP(src=QSRV, dst=LAN) / UDP(sport=443, dport=52000) / Raw(b"q" * 900))
add(3, DEV, RTR, IP(src=LAN, dst="192.0.2.50") / UDP(sport=6000, dport=6001) / Raw(b"u" * 50))
add(3.1, RTR, DEV, IP(src="192.0.2.50", dst=LAN) / UDP(sport=6001, dport=6000) / Raw(b"d" * 70))

tmp = tempfile.mkdtemp()
dev_mac = bytes.fromhex(DEV.replace(":", ""))
rtr_mac = bytes.fromhex(RTR.replace(":", ""))


def write(name, linktype, conv):
    path = os.path.join(tmp, name)
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts, p in pkts:
            b = conv(p)
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(b), len(b)) + b)
    return path


def sll_conv(p):
    up = p[Ether].src == DEV
    return struct.pack(">HHH8sH", 0 if up else 4, 1, 6, (dev_mac if up else rtr_mac) + b"\0\0", 0x0800) + bytes(p[IP])


def sll2_conv(p):
    up = p[Ether].src == DEV
    return struct.pack(">HHIHBB8s", 0x0800, 0, 3, 1, 0 if up else 4, 6, (dev_mac if up else rtr_mac) + b"\0\0") + bytes(p[IP])


files = {"以太网": write("eth.pcap", 1, bytes), "Linux cooked": write("sll.pcap", 113, sll_conv), "Linux cooked v2": write("sll2.pcap", 276, sll2_conv)}
FIELDS = ["ip.src", "ip.dst", "ip.len", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "udp.dstport", "dns.flags.response", "dns.qry.name", "tls.handshake.extensions_server_name", "http.host"]


def tshark(path):
    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "occurrence=f"] + sum((["-e", f] for f in FIELDS), [])
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    names, flows = [], collections.defaultdict(lambda: [0, 0, 0, 0])
    for line in out.split("\n"):
        if not line:
            continue
        r = dict(zip(FIELDS, (line.split("\t") + [""] * len(FIELDS))[:len(FIELDS)]))
        if r["dns.qry.name"] and r["dns.flags.response"] == "False":
            names.append(("dns", r["dns.qry.name"]))
        elif r["tls.handshake.extensions_server_name"]:
            names.append(("quic" if r["udp.dstport"] == "443" else "tls", r["tls.handshake.extensions_server_name"]))
        elif r["http.host"]:
            names.append(("http", r["http.host"].lower().split(":")[0]))
        proto, sp, dp = ("tcp", r["tcp.srcport"], r["tcp.dstport"]) if r["tcp.srcport"] else ("udp", r["udp.srcport"], r["udp.dstport"])
        up = r["ip.src"] == LAN
        key = (proto, LAN, int(sp if up else dp), r["ip.dst"] if up else r["ip.src"], int(dp if up else sp))
        f = flows[key]
        f[0 if up else 1] += 1
        f[2 if up else 3] += int(r["ip.len"])
    return sorted(names), dict(flows)


EXPECT_NAMES = sorted([("dns", "secure.example.org"), ("tls", "secure.example.org"), ("http", "plain.example.net"), ("quic", "quic.example.com")])
for label, path in files.items():
    cap = capture.read_capture(path)
    res = plain.analyze(plain.iter_packets(cap))
    ours_names = sorted((e["kind"], e["name"]) for e in res.events)
    ours_flows = {(k[1], k[2], k[3], k[4], k[5]): [v["packets_up"], v["packets_down"], v["bytes_up"], v["bytes_down"]] for k, v in res.flow_stats.items() if k[0] == DEV}
    their_names, their_flows = tshark(path)
    check(ours_names == their_names == EXPECT_NAMES, "%s：DNS / TLS / HTTP / QUIC 的 4 个域名与 tshark 逐项相同" % label)
    check(ours_flows == their_flows and len(ours_flows) == 5, "%s：设备的 5 条流，上下行包数和 L3 字节与 tshark 逐流相同" % label)
    tot = (sum(v[0] + v[1] for v in ours_flows.values()), sum(v[2] + v[3] for v in ours_flows.values()))
    check(tot == (15, 4046), "%s：设备共 %d 个包、%d 字节（表里 15 / 4046，三种链路类型的 L3 字节相同）" % (label, tot[0], tot[1]))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
