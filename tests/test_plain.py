#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plain80211：明文抓包（以太网 / 802.1Q / Linux cooked 113 与 276）读成包，认设备和上下行（局域网 / 公网地址、路由器 MAC 的学习），
交给 activity.Collector 得到事件和流量；再把命令行 `python3 -m wifi80211.report` 当子进程跑在明文抓包上。包用 scapy / struct 独立构造。
真实 tshark 对照见 tests/oracle/test_plain_e2e_diff.py。"""
import json
import logging
import os
import struct
import subprocess
import sys
import tempfile

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ICMPv6ND_NS, ICMPv6ND_RA, DNS, DNSQR, DNSRR, Dot1AD, Dot1Q, Ether, IP, IPv6, TCP, UDP, Raw, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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


def pcap_bytes(packets, linktype=1):
    """经典 pcap：[(时间, 字节)]。"""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for ts, b in packets:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(b), len(b)) + b
    return out


DEV, DEV2, RTR = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:fe"
LAN, LAN2, GW = "192.168.1.20", "192.168.1.21", "192.168.1.1"
SRV, WEB, QSRV = "203.0.113.80", "198.51.100.9", "203.0.113.99"


def eth(src, dst, ip):
    return bytes(Ether(src=src, dst=dst) / ip)


print("== 读包：以太网、VLAN、cooked ==")
ip1 = IP(src=LAN, dst=SRV) / UDP(sport=1000, dport=2000) / Raw(b"x")
cap = capture.parse_capture(pcap_bytes([(1.5, eth(DEV, RTR, ip1)), (2.5, bytes(Ether(src=DEV, dst=RTR) / Dot1Q(vlan=7) / ip1)), (3.5, bytes(Ether(src=DEV, dst=RTR) / Dot1AD(vlan=9) / Dot1Q(vlan=7) / ip1)),
                                        (4.5, b"\x00" * 13)]))
pk = plain.iter_packets(cap)
check([(p.n, p.src, p.dst, p.ethertype, p.cooked) for p in pk[:3]] == [(1, DEV, RTR, 0x800, False), (2, DEV, RTR, 0x800, False), (3, DEV, RTR, 0x800, False)] and len(pk) == 3, "以太网、802.1Q、QinQ 标签都跳过，取里面的以太类型；少于 14 字节的不要")
check(pk[0].l3 == bytes(ip1) and pk[1].l3 == bytes(ip1) and pk[2].l3 == bytes(ip1) and pk[0].ts == 1.5, "l3 就是 IP 包；时间照抓包")
sll = struct.pack(">HHH8sH", 0, 1, 6, bytes.fromhex(DEV.replace(":", "")) + b"\0\0", 0x0800) + bytes(ip1)
sll2 = struct.pack(">HHIHBB8s", 0x0800, 0, 3, 1, 0, 6, bytes.fromhex(DEV.replace(":", "")) + b"\0\0") + bytes(ip1)
p113 = plain.iter_packets(capture.parse_capture(pcap_bytes([(1, sll), (2, sll[:15])], 113)))
p276 = plain.iter_packets(capture.parse_capture(pcap_bytes([(1, sll2), (2, sll2[:19])], 276)))
check(len(p113) == 1 and (p113[0].src, p113[0].dst, p113[0].ethertype, p113[0].cooked, p113[0].pkt_type, p113[0].l3) == (DEV, None, 0x800, True, 0, bytes(ip1)), "Linux cooked（113）：源地址取头里的链路层地址，没有目的 MAC；太短不要")
check(len(p276) == 1 and (p276[0].src, p276[0].ethertype, p276[0].cooked, p276[0].pkt_type, p276[0].l3) == (DEV, 0x800, True, 0, bytes(ip1)), "Linux cooked v2（276）同样")
odd = struct.pack(">HHH8sH", 0, 772, 6, b"\0" * 8, 0x0800) + bytes(ip1)
check(plain.iter_packets(capture.parse_capture(pcap_bytes([(1, odd)], 113)))[0].src is None, "硬件类型不是以太网（环回 772）：没有 MAC")
no6 = struct.pack(">HHH8sH", 0, 1, 0, b"\0" * 8, 0x0800) + bytes(ip1)
no62 = struct.pack(">HHIHBB8s", 0x0800, 0, 3, 1, 0, 0, b"\0" * 8) + bytes(ip1)
check(plain.iter_packets(capture.parse_capture(pcap_bytes([(1, no6)], 113)))[0].src is None and plain.iter_packets(capture.parse_capture(pcap_bytes([(1, no62)], 276)))[0].src is None, "地址长度不是 6（cooked 头里没有链路层地址）：没有 MAC，不把零当成 MAC")
k = lambda lts: plain.kind(capture.parse_capture(pcap_bytes([(1, eth(DEV, RTR, ip1))], lts)))      # noqa: E731
check((k(1), k(113), k(276), k(105), k(127), k(147)) == ("plain", "plain", "plain", "dot11", "dot11", None), "kind：以太网 / cooked 是 plain，802.11 / radiotap 是 dot11，别的 None")

print("== 地址范围 ==")
A = plain.ipaddress.ip_address
check([plain.scope(A(x)) for x in ("10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.0.1", "169.254.1.1", "fd00::1", "fe80::1")] == ["lan"] * 7, "RFC1918、链路本地、IPv6 ULA / 链路本地是局域网")
check([plain.scope(A(x)) for x in ("8.8.8.8", "172.32.0.1", "100.64.0.1", "2001:db8::1", "11.0.0.1")] == ["pub"] * 5, "其它单播是公网（172.32 不在 172.16/12 里，100.64 的 CGNAT 地址不算局域网）")
check([plain.scope(A(x)) for x in ("224.0.0.251", "255.255.255.255", "0.0.0.0", "127.0.0.1", "ff02::fb", "::")] == ["other"] * 6, "组播、广播、未指定、环回不算设备也不算公网")

print("== 上下行与设备 ==")
up_pub = Ether(src=DEV, dst=RTR) / IP(src=LAN, dst=SRV) / TCP(sport=40000, dport=443)
down_pub = Ether(src=RTR, dst=DEV) / IP(src=SRV, dst=LAN) / TCP(sport=443, dport=40000)
lan_to_gw = Ether(src=DEV, dst=RTR) / IP(src=LAN, dst=GW) / UDP(sport=50000, dport=53)
gw_to_lan = Ether(src=RTR, dst=DEV) / IP(src=GW, dst=LAN) / UDP(sport=53, dport=50000)
dev_to_dev = Ether(src=DEV, dst=DEV2) / IP(src=LAN, dst=LAN2) / UDP(sport=6000, dport=6001)
mcast = Ether(src=DEV, dst="01:00:5e:00:00:fb") / IP(src=LAN, dst="224.0.0.251") / UDP(sport=5353, dport=5353)
pub_pub = Ether(src=RTR, dst=RTR) / IP(src=SRV, dst=WEB) / UDP(sport=1, dport=2)
arp = bytes(Ether(src=DEV, dst="ff:ff:ff:ff:ff:ff", type=0x0806)) + b"\0" * 28
cap = capture.parse_capture(pcap_bytes([(i, bytes(x)) for i, x in enumerate((up_pub, down_pub, lan_to_gw, gw_to_lan, dev_to_dev, mcast, pub_pub), 1)] + [(8, arp)]))
pk = plain.iter_packets(cap)
routers, ip_mac = plain.learn(pk)
check(routers == {RTR}, "路由器 MAC 从「局域网 -> 公网」的目的 MAC 和「公网 -> 局域网」的源 MAC 学到；设备的 MAC 和组播 MAC 不算")
cls = [plain.classify(p, routers, ip_mac) for p in pk]
check(cls == [(DEV, True), (DEV, False), (DEV, True), (DEV, False), (DEV, True), (DEV, True), (None, None), (None, None)], "上行取源 MAC、下行取目的 MAC；到路由器的局域网包是上行、路由器发来的是下行；设备之间按发送方记上行；组播是上行；公网到公网和 ARP 不归任何设备")
ro = plain.iter_packets(capture.parse_capture(pcap_bytes([(1, bytes(down_pub)), (2, bytes(gw_to_lan))])))
rr, mm = plain.learn(ro)
check(rr == {RTR} and [plain.classify(p, rr, mm) for p in ro] == [(DEV, False), (DEV, False)], "只看到「公网 -> 局域网」的包也能学到路由器（它的源 MAC），于是路由器发来的局域网包是下行")
nr = plain.classify(pk[1], set(), ip_mac)
check(nr == (DEV, False), "还没学到路由器时，公网 -> 局域网的包也按目的 MAC 认设备")
wan = Ether(src="02:00:00:00:00:77", dst=RTR) / IP(src=SRV, dst=LAN) / TCP(sport=443, dport=40000)
pw = plain.iter_packets(capture.parse_capture(pcap_bytes([(1, bytes(up_pub)), (2, bytes(wan))])))
r2, m2 = plain.learn(pw)
check(plain.classify(pw[1], r2, m2) == (None, False), "下行包的目的 MAC 是路由器自己（在 WAN 一侧抓的、或 NAT 之后）：认不出设备（None），不乱归")

print("== IPv6：设备自己有全球地址，路由器不能从地址范围学（Mac 上抓包发现的）==")
G6, S6, RLL = "2001:db8:1::11", "2001:db8:99::80", "fe80::1"
nd = Ether(src=RTR, dst=DEV) / IPv6(src=RLL, dst=G6) / ICMPv6ND_NS(tgt=G6)             # 路由器发给设备全球地址的邻居请求：源是链路本地，目的是全球地址
ra = Ether(src=RTR, dst="33:33:00:00:00:01") / IPv6(src=RLL, dst="ff02::1") / ICMPv6ND_RA()
v4up, v4down = up_pub, down_pub
v6up = Ether(src=DEV, dst=RTR) / IPv6(src=G6, dst=S6) / TCP(sport=41000, dport=443)
v6down = Ether(src=RTR, dst=DEV) / IPv6(src=S6, dst=G6) / TCP(sport=443, dport=41000)
mix = plain.iter_packets(capture.parse_capture(pcap_bytes([(i, bytes(x)) for i, x in enumerate((nd, v4up, v4down, v6up, v6down), 1)])))
r6, m6 = plain.learn(mix)
check(r6 == {RTR}, "邻居请求不会把设备学成路由器（路由器只有 RTR 一个）")
check([plain.classify(p, r6, m6) for p in mix][1:] == [(DEV, True), (DEV, False), (DEV, True), (DEV, False)], "IPv4 下行不再丢；IPv6 全球地址 <-> 全球地址按 MAC 判断上下行，设备是 DEV")
only6 = plain.iter_packets(capture.parse_capture(pcap_bytes([(i, bytes(x)) for i, x in enumerate((nd, ra, v6up, v6down), 1)])))
ro6, mo6 = plain.learn(only6)
check(ro6 == {RTR} and [plain.classify(p, ro6, mo6) for p in only6][2:] == [(DEV, True), (DEV, False)], "纯 IPv6 抓包：路由器从路由器通告（类型 134）的发送者学到，上下行照样认得出")
no_ra = plain.iter_packets(capture.parse_capture(pcap_bytes([(i, bytes(x)) for i, x in enumerate((nd, v6up, v6down), 1)])))
rn, mn = plain.learn(no_ra)
check(rn == set(), "纯 IPv6 而且没有路由器通告：学不到路由器，也不把设备学成路由器")
mc6 = Ether(src=DEV, dst="33:33:00:00:00:fb") / IPv6(src=G6, dst="ff02::fb") / UDP(sport=5353, dport=5353)
pm = plain.iter_packets(capture.parse_capture(pcap_bytes([(1, bytes(v4up)), (2, bytes(v4down)), (3, bytes(mc6))])))
rm, mm6 = plain.learn(pm)
check(plain.classify(pm[2], rm, mm6)[1] is not False, "IPv6 组播（目的 MAC 是组播）不会被当成下行")
RTR2 = "02:00:00:00:00:fd"
two = plain.iter_packets(capture.parse_capture(pcap_bytes([(1, bytes(v4up)), (2, bytes(Ether(src=DEV, dst=RTR2) / IP(src=LAN, dst=SRV) / TCP(sport=40002, dport=443))),
                                                           (3, bytes(Ether(src=RTR, dst=RTR2) / IPv6(src=S6, dst="2001:db8:98::1") / UDP(sport=1, dport=2)))])))
rt, mt = plain.learn(two)
check(rt == {RTR, RTR2} and plain.classify(two[2], rt, mt) == (None, None), "两个路由器之间的 IPv6 包不归任何设备（源和目的 MAC 都是路由器）")

print("== cooked：设备靠链路层源地址和 IP -> MAC ==")
def sll_pkt(ptype, mac, ipx):
    return struct.pack(">HHH8sH", ptype, 1, 6, bytes.fromhex(mac.replace(":", "")) + b"\0\0", 0x0800) + bytes(ipx)
pc = plain.iter_packets(capture.parse_capture(pcap_bytes([
    (1, sll_pkt(0, DEV, IP(src=LAN, dst=SRV) / TCP(sport=40000, dport=443))),
    (2, sll_pkt(4, RTR, IP(src=SRV, dst=LAN) / TCP(sport=443, dport=40000))),
    (3, sll_pkt(4, RTR, IP(src=LAN, dst=SRV) / TCP(sport=40001, dport=443))),
    (4, sll_pkt(0, RTR, IP(src=SRV, dst="192.168.1.99") / TCP(sport=443, dport=40000))),
    (5, sll_pkt(4, RTR, IP(src="192.168.1.50", dst=SRV) / TCP(sport=40002, dport=443)))], 113)))
rc, mc = plain.learn(pc)
check(rc == set() and mc == {LAN: DEV}, "cooked 抓包没有目的 MAC，学不到路由器；IP -> MAC 只从「别人发来的」包里学（本机发出的 pkt_type=4 不学）")
cc = [plain.classify(p, rc, mc) for p in pc[:4]]
gwdown = plain.iter_packets(capture.parse_capture(pcap_bytes([(1, sll_pkt(0, DEV, IP(src=LAN, dst=GW) / UDP(sport=5, dport=53))), (2, sll_pkt(4, RTR, IP(src=GW, dst=LAN) / UDP(sport=53, dport=5))),
                                                              (3, sll_pkt(4, RTR, IP(src=GW, dst="192.168.1.77") / UDP(sport=53, dport=5))), (4, sll_pkt(0, DEV2, IP(src=LAN2, dst=LAN) / UDP(sport=7, dport=8)))], 113)))
rg, mg = plain.learn(gwdown)
check([plain.classify(p, rg, mg) for p in gwdown] == [(DEV, True), (DEV, False), (None, False), (DEV2, True)], "cooked 里本机发给局域网设备的包（pkt_type=4，如网关的 DNS 应答）是下行，靠 IP -> MAC 认设备，认不出的 None；别人发来的局域网包是上行")
check(cc == [(DEV, True), (DEV, False), (None, True), (None, False)], "cooked：入站的局域网包取头里的地址；下行靠 IP -> MAC 认设备；本机发出的上行包、学不到 MAC 的下行包认不出设备")

print("== 端到端：事件和流量 ==")
t = 1700000000.0
seq = []
ch = tb.records(tb.hello([tb.sni_ext("secure.example.org"), tb.alpn_ext("h2")]))
http = b"GET /index.html HTTP/1.1\r\nHost: Plain.Example.net:80\r\n\r\n"
dcid = bytes.fromhex("8394c8f03e515708")
quic_dg = qb.build(dcid, b"\x01\x02", qb.crypto_frame(0, qb.client_hello("quic.example.com")))


def add(dt, pkt):
    seq.append((t + dt, bytes(pkt)))


add(0, Ether(src=DEV, dst=RTR) / IP(src=LAN, dst=GW) / UDP(sport=50123, dport=53) / DNS(id=7, qd=DNSQR(qname="secure.example.org")))
add(.01, Ether(src=RTR, dst=DEV) / IP(src=GW, dst=LAN) / UDP(sport=53, dport=50123) / DNS(id=7, qr=1, qd=DNSQR(qname="secure.example.org"), an=DNSRR(rrname="secure.example.org", type="A", rdata=SRV)))
add(.02, Ether(src=DEV, dst=RTR) / IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=100, flags="S"))
add(.03, Ether(src=RTR, dst=DEV) / IP(src=SRV, dst=LAN) / TCP(sport=443, dport=41000, seq=900, ack=101, flags="SA"))
add(.04, Ether(src=DEV, dst=RTR) / IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=101, ack=901, flags="PA") / Raw(ch[:40]))
add(.05, Ether(src=DEV, dst=RTR) / IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=141, ack=901, flags="PA") / Raw(ch[40:]))
add(.06, Ether(src=RTR, dst=DEV) / IP(src=SRV, dst=LAN) / TCP(sport=443, dport=41000, seq=901, ack=141 + len(ch) - 40, flags="PA") / Raw(b"\x16\x03\x03" + b"s" * 1000))
add(1, Ether(src=DEV, dst=RTR) / IP(src=LAN, dst=WEB) / TCP(sport=41001, dport=80, seq=500, flags="S"))
add(1.02, Ether(src=DEV, dst=RTR) / IP(src=LAN, dst=WEB) / TCP(sport=41001, dport=80, seq=501, ack=701, flags="PA") / Raw(http))
add(2, Ether(src=DEV, dst=RTR) / IP(src=LAN, dst=QSRV) / UDP(sport=52000, dport=443) / Raw(quic_dg))
add(3, Ether(src=DEV2, dst=RTR) / IP(src=LAN2, dst=SRV) / TCP(sport=42000, dport=443, seq=1, flags="S"))
add(3.1, Ether(src=DEV, dst=DEV2) / IPv6(src="fd00::20", dst="fd00::21") / UDP(sport=7, dport=8) / Raw(b"v6"))
add(4, Ether(src=RTR, dst=RTR) / IP(src=SRV, dst=WEB) / UDP(sport=1, dport=2))
cap = capture.parse_capture(pcap_bytes(seq))
res = plain.analyze(plain.iter_packets(cap))
ev = sorted((e["kind"], e["name"], e["station"]) for e in res.events)
check(ev == sorted([("dns", "secure.example.org", DEV), ("tls", "secure.example.org", DEV), ("http", "plain.example.net", DEV), ("quic", "quic.example.com", DEV)]), "DNS / TLS（拆成两段）/ HTTP / QUIC 的 4 个事件，都归到设备 MAC")
fs = {(k[1], k[2], k[3], k[4], k[5]): v for k, v in res.flow_stats.items() if k[0] == DEV}
tls = fs[("tcp", LAN, 41000, SRV, 443)]
want_up = sum(len(IP(bytes(Ether(x))[14:])) for _, x in seq[2:3] + seq[4:6])
want_down = len(IP(bytes(Ether(seq[3][1]))[14:])) + len(IP(bytes(Ether(seq[6][1]))[14:]))
check((tls["packets_up"], tls["packets_down"], tls["bytes_up"], tls["bytes_down"]) == (3, 2, want_up, want_down), "TLS 流：上行 3 个包、下行 2 个包，字节 = 各包 IP 总长度之和（%d / %d）" % (want_up, want_down))
check(("udp", LAN, 50123, GW, 53) in fs and fs[("udp", LAN, 50123, GW, 53)]["packets_down"] == 1, "DNS 流：到路由器的查询算上行，路由器的应答算下行，在同一条流里")
check({k[0] for k in res.flow_stats} == {DEV, DEV2}, "第二台设备的流单独记；设备之间的 IPv6 包按发送方记在发送方名下")
check(not any(k[2] in ("198.51.100.9", "203.0.113.80") and k[0] not in (DEV, DEV2) for k in res.flow_stats) and sum(v["packets_up"] + v["packets_down"] for v in res.flow_stats.values()) == 12, "公网到公网的包（路由器自己）不计：共 12 个包")

print("== 命令行：明文抓包不需要 --keys ==")
tmp = tempfile.mkdtemp()
cappath = os.path.join(tmp, "gw.pcap")
open(cappath, "wb").write(pcap_bytes(seq))
env = dict(os.environ, TZ="UTC", PYTHONPATH=ROOT)


def cli(*args):
    p = subprocess.run([sys.executable, "-m", "wifi80211.report", "--no-log-file"] + list(args), capture_output=True, text=True, env=env, cwd=ROOT)
    return p.returncode, p.stdout, p.stderr


rc, o, e = cli(cappath, "--format", "json", "--no-log-file")        # 不写日志文件：默认会在 stderr 印一行日志路径
doc = json.loads(o) if rc == 0 else {}
dev = next(d for d in doc.get("devices", []) if d["mac"] == DEV)
check(rc == 0 and e == "" and doc["frames"]["mode"] == "plain" and doc["frames"]["frames"] == 13 and len(doc["devices"]) == 1, "json：明文模式，13 个包，没给 --keys 也行，stderr 没有提示")
check(dev["kinds"] == {"dns": 1, "http": 1, "quic": 1, "tls": 1}, "事件种类 %s" % dev["kinds"])
check(dev["traffic"]["flows"] >= 5 and dev["traffic"]["bytes_up"] > 0 and dev["traffic"]["bytes_down"] > 0 and "other_traffic" in dev, "每台设备有流量合计和其它流量")
rc, o, e = cli(cappath, "--keys", os.path.join(tmp, "nokeys"))
check(rc == 2 and "读不了密钥文件" in e, "给了 --keys 但文件读不了：照旧报错（明文模式不放过坏参数）")
kf = os.path.join(tmp, "k.txt")
open(kf, "w").write('"wpa-pwd","whatever"\n')
rc, o, e = cli(cappath, "--keys", kf)
check(rc == 0 and "--keys 被忽略" in e and "上行" in o and "下行" in o and "流量合计" in o, "给了 --keys：提示被忽略，表格里有上行 / 下行 / 流量合计")
rc, o, e = cli(cappath, "--format", "csv")
check(rc == 0 and o.split("\n")[0].endswith("bytes_up,bytes_down,flows") and "traffic_other" in o, "csv：多 bytes_up / bytes_down / flows 三列，其它流量是 traffic_other 行")
rc, o, e = cli(cappath, "--format", "json", "--top", "1")
d1 = json.loads(o)["devices"][0]
check(rc == 0 and len(d1["other_traffic"]) <= 1 and len(d1["apps"]) <= 1, "--top 1：其它流量和应用表各只留 1 个")
rc, o, e = cli(cappath, "--top", "-1")
check(rc == 2, "--top 负数：退出码 2")
dot = os.path.join(tmp, "dot11.pcap")
open(dot, "wb").write(pcap_bytes([(1, b"\x80\x00" + b"\0" * 30)], 105))
rc, o, e = cli(dot)
check(rc == 2 and "需要 --keys" in e, "802.11 抓包不给 --keys：退出码 2，说明要 --keys")
odd = os.path.join(tmp, "odd.pcap")
open(odd, "wb").write(pcap_bytes([(1, b"\0" * 30)], 147))
rc, o, e = cli(odd)
check(rc == 2 and "链路类型不支持" in e, "不认识的链路类型：退出码 2")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
