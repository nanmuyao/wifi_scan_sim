#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""traffic80211：每条流的包数 / L3 字节 / 名字（SNI、Host、DNS 应答），按应用汇总，人读的字节数；report.attach_traffic 把流量并进报告。
包用 scapy 独立构造，经 plain.analyze 走一遍真实流程；与 tshark 的逐流对照见 tests/oracle/test_traffic_diff.py。"""
import logging
import os
import struct
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, IPv6, TCP, UDP, Raw, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import tls_build as tb  # noqa: E402
from wifi80211 import apps, capture, plain, report, traffic  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


DEV, DEV2, RTR = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:fe"
LAN, LAN2, GW = "192.168.1.20", "192.168.1.21", "192.168.1.1"


def run(pkts, times=None):
    raw = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, p in enumerate(pkts):
        b = bytes(p)
        raw += struct.pack("<IIII", (times[i] if times else 1700000000 + i), 0, len(b), len(b)) + b
    return plain.analyze(plain.iter_packets(capture.parse_capture(raw)))


def L3(p):
    return len(bytes(p[IP])) if IP in p else 40 + len(bytes(p[IPv6].payload))


up = lambda mac, ip, rest: Ether(src=mac, dst=RTR) / ip / rest         # noqa: E731
down = lambda mac, ip, rest: Ether(src=RTR, dst=mac) / ip / rest       # noqa: E731
hello = lambda name: Raw(tb.records(tb.hello([tb.sni_ext(name)])))     # noqa: E731
req = lambda host: Raw(("GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host).encode())      # noqa: E731

print("== 每条流的包数、字节、名字 ==")
a1 = up(DEV, IP(src=LAN, dst="203.0.113.1"), TCP(sport=40000, dport=443, seq=1, flags="PA") / hello("a.example.org"))
a2 = down(DEV, IP(src="203.0.113.1", dst=LAN), TCP(sport=443, dport=40000, seq=1, flags="PA") / Raw(b"s" * 500))
a3 = up(DEV, IP(src=LAN, dst="203.0.113.1"), TCP(sport=40000, dport=443, seq=1 + len(hello("a.example.org").load), flags="A") / Raw(b"x" * 100))
b1 = up(DEV, IP(src=LAN, dst="198.51.100.5"), TCP(sport=40001, dport=80, seq=1, flags="PA") / req("one.example.net"))
b2 = up(DEV, IP(src=LAN, dst="198.51.100.5"), TCP(sport=40002, dport=80, seq=1, flags="PA") / req("two.example.net"))
b3 = down(DEV, IP(src="198.51.100.5", dst=LAN), TCP(sport=80, dport=40002, seq=1, flags="PA") / Raw(b"h" * 300))
dq = up(DEV, IP(src=LAN, dst=GW), UDP(sport=50000, dport=53) / DNS(id=1, qd=DNSQR(qname="late.example.com")))
da = down(DEV, IP(src=GW, dst=LAN), UDP(sport=53, dport=50000) / DNS(id=1, qr=1, qd=DNSQR(qname="late.example.com"), an=DNSRR(rrname="late.example.com", type="A", rdata="192.0.2.77")))
u1 = up(DEV, IP(src=LAN, dst="192.0.2.77"), UDP(sport=6000, dport=6001) / Raw(b"u" * 50))
n1 = up(DEV, IP(src=LAN, dst="192.0.2.88"), UDP(sport=6002, dport=6003) / Raw(b"n" * 20))
res = run([a1, a2, a3, b1, b2, b3, dq, da, u1, n1])
fl = traffic.flows(res)
by = {(f["proto"], f["local_port"], f["remote_ip"], f["remote_port"]): f for f in fl}
f = by[("tcp", 40000, "203.0.113.1", 443)]
check((f["packets_up"], f["packets_down"], f["bytes_up"], f["bytes_down"]) == (2, 1, L3(a1) + L3(a3), L3(a2)) and (f["name"], f["via"], f["kind"]) == ("a.example.org", "sni", "tls"), "TLS 流：上行 2 包 / 下行 1 包，字节是各包 IP 总长度之和，名字来自 SNI")
check(by[("tcp", 40001, "198.51.100.5", 80)]["name"] == "one.example.net" and by[("tcp", 40002, "198.51.100.5", 80)]["name"] == "two.example.net" and by[("tcp", 40002, "198.51.100.5", 80)]["kind"] == "http", "同一台服务器同一个端口、不同客户端口的两条 HTTP 连接：各用自己的 Host，不串名字")
u = by[("udp", 6000, "192.0.2.77", 6001)]
check((u["name"], u["via"], u["kind"]) == ("late.example.com", "dns", "dns"), "没有 SNI / Host 的 UDP 流：用设备自己 DNS 应答里这个 IP 的域名补，via = dns")
n = by[("udp", 6002, "192.0.2.88", 6003)]
check(n["name"] is None and n["via"] is None and n["kind"] is None, "查不到名字就是 None，不猜")
d = by[("udp", 50000, GW, 53)]
check((d["packets_up"], d["packets_down"]) == (1, 1) and d["first"] == 1700000006 and d["last"] == 1700000007, "DNS 流：查询是上行、应答是下行，同一条流；首末时间取包的时间")
check([f["first"] for f in fl] == sorted(f["first"] for f in fl) and len(fl) == 6, "流按首次出现的时间排序，共 6 条（TLS、两条 HTTP、DNS、两条 UDP）")
dup = run([a1, a1, a1])
check(list(traffic.flows(dup))[0]["packets_up"] == 3 and list(traffic.flows(dup))[0]["bytes_up"] == 3 * L3(a1), "重传的包（同一个段发了 3 次）每次都计：口径是抓到的包，不去重")
v6 = up(DEV, IPv6(src="fd00::20", dst="2001:db8::1"), UDP(sport=7000, dport=7001) / Raw(b"v" * 30))
f6 = traffic.flows(run([v6]))[0]
check(f6["bytes_up"] == 40 + 8 + 30 and f6["remote_ip"] == "2001:db8:0:0:0:0:0:1", "IPv6：字节 = 40 + 负载长度（UDP 头 8 + 数据 30）")

rev = traffic.flows(run([a1, b1, dq], times=[1700000300, 1700000200, 1700000100]))
check([f["first"] for f in rev] == [1700000100, 1700000200, 1700000300], "流按首次出现的时间排序，不按在文件里出现的顺序（几份抓包合并后时间可能是倒的）")
nohost = up(DEV, IP(src=LAN, dst="192.0.2.99"), TCP(sport=40050, dport=80, seq=1, flags="PA") / Raw(b"GET /x HTTP/1.0\r\n\r\n"))
dq2 = up(DEV, IP(src=LAN, dst=GW), UDP(sport=50001, dport=53) / DNS(id=2, qd=DNSQR(qname="nohost.example.com")))
da2 = down(DEV, IP(src=GW, dst=LAN), UDP(sport=53, dport=50001) / DNS(id=2, qr=1, qd=DNSQR(qname="nohost.example.com"), an=DNSRR(rrname="nohost.example.com", type="A", rdata="192.0.2.99")))
fh = next(f for f in traffic.flows(run([dq2, da2, nohost])) if f["remote_port"] == 80)
check((fh["name"], fh["via"], fh["kind"]) == ("nohost.example.com", "dns", "http"), "HTTP 请求没有 Host 头：名字用 DNS 应答补，来源 via = dns（kind 仍是 http）")
import quic_build as qb  # noqa: E402
qpkt = up(DEV, IP(src=LAN, dst="203.0.113.99"), UDP(sport=52000, dport=443) / Raw(qb.build(bytes.fromhex("8394c8f03e515708"), b"\x01\x02", qb.crypto_frame(0, qb.client_hello("quic.example.com")))))
fq = traffic.flows(run([qpkt]))[0]
check((fq["name"], fq["via"], fq["kind"], fq["local_port"]) == ("quic.example.com", "sni", "quic", 52000), "QUIC 流：名字来自 Initial 里的 SNI，按设备端口对上")
from wifi80211 import activity  # noqa: E402
cl = activity.Collector()
cl.feed(1, 0.0, DEV, [plain.LLC_SNAP + b"\x08\x00" + bytes(IP(src=LAN, dst=GW) / UDP(sport=50000, dport=53) / DNS(id=1, qd=DNSQR(qname="up.none.test")))], None)
check([e["name"] for e in cl.finish().events] == ["up.none.test"] and cl.flow_stats == {}, "Collector.feed 的 up = None（方向不清楚）：事件照出，流量不计")

print("== 按应用汇总 ==")
rules = apps.Rules()
rules.add({"apps": [{"app": "甲", "category": "视频", "suffix": ["example.org", "example.com"]}, {"app": "乙", "category": "社交", "suffix": ["example.net"]}]})
agg = traffic.aggregate(rules, fl)[DEV]
a = agg["apps"]
check(sorted(a) == ["乙", "甲"] and a["甲"]["flows"] == 2 and a["乙"]["flows"] == 2 and a["甲"]["category"] == "视频", "有名字且规则认识的流归应用：a.example.org 和 late.example.com（DNS 补的）归甲，两个 example.net 归乙")
check(a["甲"]["bytes_up"] == L3(a1) + L3(a3) + L3(u1) and a["甲"]["bytes_down"] == L3(a2) and a["甲"]["packets_up"] == 3 and a["乙"]["bytes_down"] == L3(b3), "同一应用的流相加：上下行字节和包数")
check(a["甲"]["first"] == 1700000000 and a["甲"]["last"] == 1700000008, "first / last 取各流的最早和最晚")
o = agg["other"]
check(sorted(o) == ["未命名 192.0.2.88", "未命名 %s" % GW] and traffic.UNNAMED == "未命名", "没有名字的流放在 other，键是「未命名 对端 IP」（DNS 流到路由器、没名字的 UDP 流）")
check(o["未命名 192.0.2.88"]["named"] is False and o["未命名 192.0.2.88"]["bytes_up"] == L3(n1), "other 里 named = False，字节是那一个包的 IP 总长度")
r2 = apps.Rules()
only = traffic.aggregate(r2, fl)[DEV]
check(only["apps"] == {} and only["other"]["a.example.org"]["named"] is True and "late.example.com" in only["other"], "没有规则时：有名字的按名字放 other（named = True），不丢")
two = traffic.aggregate(rules, traffic.flows(run([a1, up(DEV2, IP(src=LAN2, dst="203.0.113.1"), TCP(sport=40000, dport=443, seq=1, flags="PA") / hello("a.example.org"))])))
check(sorted(two) == [DEV, DEV2] and two[DEV]["apps"]["甲"]["flows"] == 1 and two[DEV2]["apps"]["甲"]["flows"] == 1, "不同设备分开汇总（即使五元组的其它部分一样）")

print("== 人读的字节数 ==")
check([traffic.human(x) for x in (0, 1, 1023, 1024, 1536, 1048575, 1048576, 5 * 1024 ** 2 + 1024 * 512, 1024 ** 3, 3 * 1024 ** 3 + 1024 ** 3 // 2)] ==
      ["0 B", "1 B", "1023 B", "1.0 KiB", "1.5 KiB", "1024.0 KiB", "1.0 MiB", "5.5 MiB", "1.0 GiB", "3.5 GiB"], "B / KiB / MiB / GiB，1024 进制，边界上进位")

print("== 并进报告 ==")
ev = lambda ts, name, kind="tls": {"ts": ts, "station": DEV, "kind": kind, "name": name, "frame": int(ts)}       # noqa: E731
rep = report.build([ev(0, "x.example.org"), ev(5, "y.example.net")], rules)
report.attach_traffic(rep, traffic.aggregate(rules, fl))
d = rep["devices"][0]
rows = {r["app"]: r for r in d["apps"]}
check(rep["traffic"] and rows["甲"]["bytes_up"] == a["甲"]["bytes_up"] and rows["甲"]["flows"] == 2 and rows["乙"]["bytes_down"] == L3(b3) and rows["甲"]["events"] == 1, "应用行加上 bytes_up / bytes_down / flows，原来的事件数、段数不变")
check(d["traffic"] == {"bytes_up": sum(f["bytes_up"] for f in fl), "bytes_down": sum(f["bytes_down"] for f in fl), "flows": 6}, "设备合计 = 所有流之和")
check([o["name"] for o in d["other_traffic"]] == sorted((o["name"] for o in d["other_traffic"]), key=lambda n: (-(o2 := {x["name"]: x for x in d["other_traffic"]})[n]["bytes_up"] - o2[n]["bytes_down"], n)), "其它流量按总字节从大到小")
rep = report.build([ev(0, "x.example.org")], rules)
report.attach_traffic(rep, traffic.aggregate(rules, fl))
check({r["app"] for r in rep["devices"][0]["apps"]} == {"甲", "乙"} and next(r for r in rep["devices"][0]["apps"] if r["app"] == "乙")["events"] == 0 and next(r for r in rep["devices"][0]["apps"] if r["app"] == "乙")["seconds"] == 0, "只在流量里出现的应用补一行（事件 0、秒数 0）")
rep = report.build([ev(0, "x.example.org")], rules)
report.attach_traffic(rep, {})
check(rep["devices"][0]["traffic"] == {"bytes_up": 0, "bytes_down": 0, "flows": 0} and rep["devices"][0]["apps"][0]["bytes_up"] == 0 and rep["devices"][0]["other_traffic"] == [], "这台设备没有流量记录：全是 0，不报错")
rep = report.build([ev(0, "x.example.org"), ev(5, "y.example.net")], rules)
report.attach_traffic(rep, traffic.aggregate(rules, fl), top=1)
check([r["app"] for r in rep["devices"][0]["apps"]] == ["甲"] and len(rep["devices"][0]["other_traffic"]) == 1, "top = 1：应用按总流量取第一（甲 比 乙 大），其它流量只留 1 个")
rep = report.build([ev(0, "x.example.org"), ev(5, "y.example.net")], rules)
report.attach_traffic(rep, traffic.aggregate(rules, fl), top=0)
check(rep["devices"][0]["apps"] == [] and rep["devices"][0]["other_traffic"] == [], "top = 0：都不列")
tab = report.render_table(rep, {"frames": 3, "protected": 0, "decrypted": 0, "mode": "plain"})
check("3 个包（明文，无需解密）" in tab and "流量合计" in tab and report.TRAFFIC_NOTE in tab and tab.rstrip().endswith(report.LIMITS), "明文模式的表头、流量合计、口径说明；局限说明仍在最后")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
