#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""activity80211：从解密后的明文读出每台设备的 DNS 查询和 TLS SNI，汇总成时间线。帧用假的 Frame（只有 n / ts / h），明文用 scapy 构造；
真实抓包里的 DNS 对照 tshark 见 tests/oracle/test_activity_diff.py。"""
import logging
import os
import struct
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, TCP, UDP, Raw, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import quic_build as qb  # noqa: E402
import tls_build as tb  # noqa: E402
from wifi80211 import activity, frames  # noqa: E402
from wifi80211 import dns as dns_  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


SNAP = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"
SNAP6 = b"\xaa\xaa\x03\x00\x00\x00\x86\xdd"
PHONE, TV, AP = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:aa"
LAN = {PHONE: "192.168.1.10", TV: "192.168.1.20"}


def up(mac):                                                           # 设备 -> AP
    return {"to_ds": 1, "from_ds": 0, "sa": mac, "da": AP}


def down(mac):                                                         # AP -> 设备
    return {"to_ds": 0, "from_ds": 1, "sa": AP, "da": mac}


class World:
    def __init__(self):
        self.frames, self.dec, self.t = [], {}, 100.0

    def add(self, h, pkt, dt=1.0):
        snap = SNAP6 if IPv6 in pkt else SNAP
        self.t += dt
        n = len(self.frames) + 1
        self.frames.append(frames.Frame(n, self.t, b"", h, b"", True))
        self.dec[n] = {"how": "pairwise", "msdus": [snap + bytes(pkt)]}

    def dns(self, mac, name, answer=None, dt=1.0, qtype="A"):
        ip = LAN[mac]
        self.add(up(mac), IP(src=ip, dst="192.168.1.1") / UDP(sport=50000, dport=53) / DNS(id=1, qd=DNSQR(qname=name, qtype=qtype)), dt)
        if answer:
            self.add(down(mac), IP(src="192.168.1.1", dst=ip) / UDP(sport=53, dport=50000) / DNS(id=1, qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type="A", rdata=answer)))

    def tls(self, mac, server, hello, sport=40000, cuts=(), dt=1.0, syn=True):
        ip, seq = LAN[mac], 1000
        if syn:
            self.add(up(mac), IP(src=ip, dst=server) / TCP(sport=sport, dport=443, seq=seq - 1, flags="S"), dt)
            self.add(down(mac), IP(src=server, dst=ip) / TCP(sport=443, dport=sport, seq=7000, ack=seq, flags="SA"), 0.01)
        data = tb.records(hello, cuts)
        step = 40 if cuts else len(data)                               # 有 cuts 时同时把字节流切成 40 字节一段，让 TLS 记录和 TCP 段的边界错开
        for rec in (data[i:i + step] for i in range(0, len(data), step)):
            self.add(up(mac), IP(src=ip, dst=server) / TCP(sport=sport, dport=443, seq=seq, flags="PA") / Raw(rec), 0.01)
            seq += len(rec)


    def tcp(self, mac, server, dport, chunks, sport=41000, syn=True, down_chunks=()):
        """chunks：[(相对偏移, 字节)]，按给出的顺序由设备发出；down_chunks：服务器发回的 [(相对偏移, 字节)]。"""
        ip, c0, s0 = LAN[mac], 1000, 7000
        if syn:
            self.add(up(mac), IP(src=ip, dst=server) / TCP(sport=sport, dport=dport, seq=c0 - 1, flags="S"))
            self.add(down(mac), IP(src=server, dst=ip) / TCP(sport=dport, dport=sport, seq=s0 - 1, ack=c0, flags="SA"), 0.01)
        for off, data in chunks:
            self.add(up(mac), IP(src=ip, dst=server) / TCP(sport=sport, dport=dport, seq=c0 + off, flags="PA") / Raw(data), 0.01)
        for off, data in down_chunks:
            self.add(down(mac), IP(src=server, dst=ip) / TCP(sport=dport, dport=sport, seq=s0 + off, ack=c0, flags="PA") / Raw(data), 0.01)

    def quic(self, mac, server, datagrams, sport=50500, dt=1.0):
        for dg in datagrams:
            self.add(up(mac), IP(src=LAN[mac], dst=server) / UDP(sport=sport, dport=443) / Raw(dg), dt)


hello = lambda *names: tb.hello([tb.sni_ext(*names)] if names else [])                              # noqa: E731

print("== DNS 与 TLS ==")
w = World()
w.dns(PHONE, "www.example.com", "93.184.216.34")
w.tls(PHONE, "93.184.216.34", hello("www.example.com"))
w.dns(TV, "video.cdn.test", "203.0.113.5")
w.tls(TV, "203.0.113.5", hello("video.cdn.test"), sport=40001)
ev = activity.build(w.frames, w.dec)
check([(e["station"], e["kind"], e["name"]) for e in ev] == [(PHONE, "dns", "www.example.com"), (PHONE, "tls", "www.example.com"), (TV, "dns", "video.cdn.test"), (TV, "tls", "video.cdn.test")],
      "两台设备各查一次、各连一次：事件按时间排好，归到各自的 MAC")
check(ev[1]["server"] == "93.184.216.34" and ev[1]["port"] == 443 and ev[1]["via"] == "sni" and ev[0]["qtype"] == 1 and ev[0]["server"] == "192.168.1.1", "TLS 事件带服务器 IP、端口、来源 sni；DNS 事件带类型和问的服务器")
check(ev[1]["ts"] < ev[2]["ts"] and ev[1]["ts"] == w.frames[2].ts, "TLS 事件的时间是连接里第一个客户端段的时间（SYN）")

print("== 设备归属 ==")
w = World()
w.add({"to_ds": 1, "from_ds": 1, "sa": PHONE, "da": AP}, IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=50000, dport=53) / DNS(qd=DNSQR(qname="wds.test")))
w.add({"to_ds": 0, "from_ds": 0, "sa": PHONE, "da": AP}, IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=50000, dport=53) / DNS(qd=DNSQR(qname="ibss.test")))
check(activity.build(w.frames, w.dec) == [], "WDS（to_ds 和 from_ds 同时置位）和 IBSS：分不出哪个是设备，不产生事件")
check(activity.station_of({"to_ds": 0, "from_ds": 1, "sa": AP, "da": "01:00:5e:00:00:fb"}) is None, "AP 发出的组播帧：不归任何设备（是转发的副本）")
w = World()
w.add({"to_ds": 0, "from_ds": 1, "sa": AP, "da": "01:00:5e:00:00:fb"}, IP(src="192.168.1.10", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="relay.local")))
check(activity.build(w.frames, w.dec) == [], "AP 转发出来的 mDNS 副本不产生事件（不会和设备自己发的那一帧重复）")
check(activity.station_of(up(PHONE)) == PHONE and activity.station_of(down(TV)) == TV, "发往 AP 的取源地址，AP 发来的取目的地址")

print("== TLS 的各种情况 ==")
w = World()
w.tls(PHONE, "198.51.100.1", hello("split.example"), cuts=(20, 50))
ev = activity.build(w.frames, w.dec)
check([(e["name"], e["via"]) for e in ev] == [("split.example", "sni")], "ClientHello 被拆在三个 TLS 记录、好几个 TCP 段里（两种边界不重合）：拼起来读出 SNI")
w = World()
w.tls(PHONE, "198.51.100.2", hello(), sport=40002)
check(activity.build(w.frames, w.dec) == [], "没有 SNI、也没有先前的 DNS 应答：不猜名字，不产生事件")
w = World()
w.dns(PHONE, "nosni.example", "198.51.100.3")
w.tls(PHONE, "198.51.100.3", hello())
ev = activity.build(w.frames, w.dec)
check([(e["kind"], e["name"], e.get("via")) for e in ev] == [("dns", "nosni.example", None), ("tls", "nosni.example", "dns")], "没有 SNI：用这台设备自己先前 DNS 应答里的 IP -> 域名，via 标 dns")
w = World()
w.dns(TV, "other.example", "198.51.100.4")
w.tls(PHONE, "198.51.100.4", hello())
check([e["kind"] for e in activity.build(w.frames, w.dec)] == ["dns"], "别的设备查到的 IP 不能借给这台设备用")
w = World()
w.tls(PHONE, "198.51.100.5", hello("late.example"), syn=False)
check([e["name"] for e in activity.build(w.frames, w.dec)] == ["late.example"], "没抓到握手（中途开始）：照样按段读出，客户端是先出现的方向")
w = World()
w.add(up(PHONE), IP(src="192.168.1.10", dst="198.51.100.6") / TCP(sport=40003, dport=443, seq=5000, flags="PA") / Raw(b"GET / HTTP/1.1\r\n\r\n"))
check(activity.build(w.frames, w.dec) == [], "不是 TLS 的 TCP 流：没有事件")

print("== QUIC ==")
dcid, scid = bytes.fromhex("8394c8f03e515708"), b"\x01\x02"
w = World()
w.dns(PHONE, "video.example", "203.0.113.50")
w.quic(PHONE, "203.0.113.50", [qb.build(dcid, scid, qb.crypto_frame(0, qb.client_hello("video.example")))])
ev = activity.build(w.frames, w.dec)
check([(e["kind"], e["name"], e["via"], e["server"], e["port"]) for e in ev[1:]] == [("quic", "video.example", "sni", "203.0.113.50", 443)], "一个 QUIC Initial：从 SNI 得到域名，kind 标 quic")
w = World()
ch = qb.client_hello("split.quic.example", extra=1500)
w.quic(PHONE, "203.0.113.51", [qb.build(dcid, scid, qb.crypto_frame(900, ch[900:]), pn=3), qb.build(dcid, scid, qb.crypto_frame(0, ch[:900]), pn=2)])
check([e["name"] for e in activity.build(w.frames, w.dec)] == ["split.quic.example"], "ClientHello 超过一个包、两个包乱序到达：按偏移拼起来")
w = World()
w.quic(PHONE, "203.0.113.52", [qb.build(dcid, scid, qb.crypto_frame(900, ch[900:]), pn=3)])
check(activity.build(w.frames, w.dec) == [], "只收到后半段（前半段丢了）：读不出 ClientHello，没有事件")
w = World()
w.dns(PHONE, "nosni.quic", "203.0.113.53")
w.quic(PHONE, "203.0.113.53", [qb.build(dcid, scid, qb.crypto_frame(0, qb.client_hello(None)))])
check([(e["kind"], e["name"], e.get("via")) for e in activity.build(w.frames, w.dec)] == [("dns", "nosni.quic", None), ("quic", "nosni.quic", "dns")], "QUIC 的 ClientHello 没有 SNI：同样用这台设备先前 DNS 应答里的 IP")
w = World()
w.add(up(PHONE), IP(src=LAN[PHONE], dst="203.0.113.54") / UDP(sport=50501, dport=443) / Raw(bytes([0xC3]) + os.urandom(1300)))
w.add(up(PHONE), IP(src=LAN[PHONE], dst="203.0.113.54") / UDP(sport=50501, dport=443) / Raw(b"\x40" + os.urandom(1300)))
check(activity.build(w.frames, w.dec) == [], "长得像 Initial 但认证不过 / 短包头的 UDP 载荷：没有事件，不报错")

print("== mDNS 与 DNS 应答 ==")
w = World()
w.add(up(PHONE), IP(src="192.168.1.10", dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="_ipp._tcp.local", qtype="PTR")))
w.add(down(PHONE), IP(src="192.168.1.1", dst="192.168.1.10") / UDP(sport=53, dport=50000) / DNS(qr=1, qd=DNSQR(qname="resp.test"), an=DNSRR(rrname="resp.test", type="A", rdata="1.2.3.4")))
ev = activity.build(w.frames, w.dec)
check([(e["kind"], e["name"], e["qtype"]) for e in ev] == [("mdns", "_ipp._tcp.local", 12)], "mDNS 的查询单独标 mdns；DNS 应答本身不算设备的访问")

w = World()
w.add(up(PHONE), IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=50000, dport=5000) / DNS(qd=DNSQR(qname="notdns.test")))
check(activity.build(w.frames, w.dec) == [], "不是 53 / 5353 端口的 UDP 不当 DNS（它碰巧能解成 DNS 报文也不算）")
w = World()
w.add(up(PHONE), IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=50000, dport=53) / DNS(qd=DNSQR(qname="six.test", qtype="AAAA")))
w.add(down(PHONE), IP(src="192.168.1.1", dst="192.168.1.10") / UDP(sport=53, dport=50000) / DNS(qr=1, qd=DNSQR(qname="six.test"), an=DNSRR(rrname="six.test", type="AAAA", rdata="2001:db8::7")))
w.add(down(PHONE), IP(src="192.168.1.1", dst="192.168.1.10") / UDP(sport=5353, dport=50000) / DNS(qr=1, qd=DNSQR(qname="spoof.test"), an=DNSRR(rrname="spoof.test", type="A", rdata="198.51.100.9")))
w.tls(PHONE, "198.51.100.9", hello(), sport=40010)
v6 = "2001:db8::7"
for rec in (tb.records(hello()),):
    w.add(up(PHONE), IPv6(src="fd00::10", dst=v6) / TCP(sport=40011, dport=443, seq=1, flags="PA") / Raw(rec))
check([(e["kind"], e["name"]) for e in activity.build(w.frames, w.dec)] == [("dns", "six.test"), ("tls", "six.test")], "AAAA 应答进了 IP -> 域名表：IPv6 连接没有 SNI 时也能认出名字")
w = World()
w.tls(PHONE, "198.51.100.1", hello("a.example"), sport=40020)
w.tls(TV, "198.51.100.1", hello("b.example"), sport=40020)
check(sorted((e["station"], e["name"]) for e in activity.build(w.frames, w.dec)) == [(PHONE, "a.example"), (TV, "b.example")], "两台设备用同一个源端口连同一个服务器（地址不同）：各归各的")
w = World()
w.tls(PHONE, "198.51.100.1", hello("order.example"), sport=40021)
w.frames, w.dec = w.frames[1:], {i + 1: v for i, v in enumerate(list(w.dec.values())[1:])}
w.frames = [frames.Frame(i + 1, f.ts, b"", f.h, b"", True) for i, f in enumerate(w.frames)]
check([e["name"] for e in activity.build(w.frames, w.dec)] == ["order.example"], "只抓到 SYN+ACK 之后的部分（服务器方向先出现）：客户端按谁发出了 ClientHello 认，不靠 SYN")

print("== 时间线与汇总 ==")
evs = [{"ts": t, "station": PHONE, "name": n, "kind": k, "frame": i} for i, (t, n, k) in enumerate([(0, "a.test", "dns"), (10, "a.test", "tls"), (200, "a.test", "dns"), (15, "b.test", "dns")])]
evs.sort(key=lambda e: e["ts"])
s = activity.sessions(evs, gap=60)
check([(x["name"], x["start"], x["end"], x["count"]) for x in s] == [("a.test", 0, 10, 2), ("b.test", 15, 15, 1), ("a.test", 200, 200, 1)], "相邻不超过 60 秒合成一段，隔了 190 秒另起一段；不同名字互不影响")
check(len(activity.sessions([dict(e, ts=t) for e, t in zip(evs[:2] * 1, (0, 60))], gap=60)) == 1 and len(activity.sessions([dict(e, ts=t) for e, t in zip(evs[:2], (0, 61))], gap=60)) == 2, "间隔正好等于 gap 还算同一段，超过 1 秒就另起")
check(s[0]["kinds"] == {"dns", "tls"}, "一段里记下出现过的事件种类")
check(activity.sessions(evs, gap=5) != s and len(activity.sessions(evs, gap=5)) == 4, "gap 参数：5 秒时 0 和 10 就分开了（共 4 段）")
check(activity.summary(evs) == {PHONE: {"a.test": 3, "b.test": 1}}, "汇总：每台设备每个名字的次数")

print("== HTTP ==")
REQ = lambda path, host=b"www.example.com", extra=b"": b"GET " + path + b" HTTP/1.1\r\nHost: " + host + b"\r\n" + extra + b"\r\n"          # noqa: E731
w = World()
w.tcp(PHONE, "198.51.100.20", 80, [(0, REQ(b"/index.html", b"WWW.Example.COM:8080"))])
ev = [e for e in activity.build(w.frames, w.dec) if e["kind"] == "http"]
check([(e["name"], e["method"], e["path"], e["port"], e["server"], e["via"]) for e in ev] == [("www.example.com", "GET", "/index.html", 80, "198.51.100.20", "host")], "HTTP 请求：Host 转小写并去掉端口；方法、路径、服务器、端口")
check(ev[0]["station"] == PHONE and ev[0]["ts"] == w.frames[0].ts, "事件的设备和时间（连接的第一个段）")
r1, r2 = REQ(b"/a", b"one.test"), REQ(b"/b", b"two.test")
w = World()
w.tcp(PHONE, "198.51.100.21", 80, [(0, r1 + r2)])
check([(e["name"], e["path"]) for e in activity.build(w.frames, w.dec) if e["kind"] == "http"] == [("one.test", "/a"), ("two.test", "/b")], "一个段里两个请求（流水线）：各出一个事件，按顺序")
w = World()
body = b"x=1&y=2"
post = b"POST /form HTTP/1.1\r\nHost: post.test\r\nContent-Length: %d\r\n\r\n" % len(body) + body
w.tcp(PHONE, "198.51.100.22", 80, [(0, post + REQ(b"/after", b"post.test"))])
check([(e["method"], e["path"]) for e in activity.build(w.frames, w.dec) if e["kind"] == "http"] == [("POST", "/form"), ("GET", "/after")], "有 Content-Length 的请求体被跳过，后面的请求照样读到（体里即使有 CRLFCRLF 也不当成请求）")
tricky = b"GET /fake HTTP/1.1\r\nHost: inner.test\r\n\r\n"
post2 = b"POST /up HTTP/1.1\r\nHost: up.test\r\nContent-Length: %d\r\n\r\n" % len(tricky) + tricky
w = World()
w.tcp(PHONE, "198.51.100.23", 80, [(0, post2)])
check([e["path"] for e in activity.build(w.frames, w.dec) if e["kind"] == "http"] == ["/up"], "请求体里长得像请求的内容不算")
w = World()
w.tcp(PHONE, "198.51.100.24", 80, [(0, REQ(b"/" + b"a" * 300))])
check(len([e for e in activity.build(w.frames, w.dec) if e["kind"] == "http"][0]["path"]) == 200, "路径截到 200 个字符")
w = World()
whole = REQ(b"/split", b"split.test", b"X-Pad: " + b"p" * 100 + b"\r\n")
w.tcp(PHONE, "198.51.100.25", 80, [(0, whole[:30]), (30, whole[30:80]), (80, whole[80:])])
check([e["name"] for e in activity.build(w.frames, w.dec) if e["kind"] == "http"] == ["split.test"], "请求头被拆在三个 TCP 段里：拼起来读")
w = World()
w.tcp(PHONE, "198.51.100.26", 80, [(0, whole[:60])])
check([e for e in activity.build(w.frames, w.dec) if e["kind"] == "http"] == [], "请求头没收全（没有空行）：不产生事件")
w = World()
w.dns(PHONE, "nohost.test", "198.51.100.27")
w.tcp(PHONE, "198.51.100.27", 80, [(0, b"GET /old HTTP/1.0\r\n\r\n")], sport=41001)
check([(e["kind"], e["name"], e["via"]) for e in activity.build(w.frames, w.dec) if e["kind"] == "http"] == [("http", "nohost.test", "dns")], "没有 Host 头（HTTP/1.0）：用这台设备先前 DNS 应答里的 IP -> 域名")
w = World()
w.tcp(PHONE, "198.51.100.28", 80, [(0, b"GET /old HTTP/1.0\r\n\r\n")])
check([e for e in activity.build(w.frames, w.dec) if e["kind"] == "http"] == [], "没有 Host 也没有 DNS 应答：不猜")
w = World()
w.tcp(PHONE, "198.51.100.29", 80, [(0, REQ(b"/v6", b"[2001:db8::5]:8080")), (len(REQ(b"/v6", b"[2001:db8::5]:8080")), REQ(b"/e", b"EMPTY."))])
check([e["name"] for e in activity.build(w.frames, w.dec) if e["kind"] == "http"] == ["2001:db8::5", "empty."], "Host 是 [IPv6]:端口 时去掉括号和端口；末尾的点保留")
w = World()
a1, a2, a3 = REQ(b"/one", b"gap.test"), REQ(b"/lost", b"gap.test"), REQ(b"/three", b"gap.test")
w.tcp(PHONE, "198.51.100.30", 80, [(0, a1), (len(a1) + len(a2), a3)])
check([e["path"] for e in activity.build(w.frames, w.dec) if e["kind"] == "http"] == ["/one", "/three"], "中间丢了一个请求：缺口前后恰好从请求行开始的两段都读")
w = World()
w.tcp(PHONE, "198.51.100.31", 80, [(0, a1), (len(a1) + 10, b"garbage-in-the-middle")])
check([e["path"] for e in activity.build(w.frames, w.dec) if e["kind"] == "http"] == ["/one"], "缺口之后的段不是从请求行开始：不当请求")
w = World()
w.tcp(PHONE, "198.51.100.32", 80, [(0, b"\x16\x03\x01\x00\x05hello")])
check([e for e in activity.build(w.frames, w.dec) if e["kind"] == "http"] == [], "不是 HTTP 的流没有 http 事件")
check(activity.http_requests(b"GET / HTTP/1.1\r\nhost: lower.test\r\nHOST: second.test\r\n\r\n")[0]["host"] == "lower.test" and activity.http_requests(b"get / HTTP/1.1\r\n\r\n") == [] and activity.http_requests(b"GET / HTTP/1.1 \r\n\r\n") == [], "Host 头名字不分大小写、多个取第一个；小写方法 / 请求行尾多空格不认")
check(activity.http_requests(b"GET / HTTP/1.1\r\nHost: x.test\r\nContent-Length: abc\r\n\r\nGET /n HTTP/1.1\r\nHost: x.test\r\n\r\n")[1]["path"] == "/n", "Content-Length 不是数字：当 0")
check(activity.http_requests(b"GET / HTTP/1.1\r\nHost: x.test\r\nContent-Length: 100\r\n\r\nshort")[0]["path"] == "/" and len(activity.http_requests(b"GET / HTTP/1.1\r\nHost: x.test\r\nContent-Length: 100\r\n\r\nshort")) == 1, "请求体没到齐：这个请求算，后面没有更多")
check(activity._host_name("") is None and activity._host_name(":80") is None and activity._host_name("a.b:") == "a.b" and activity._host_name("a:b:c") == "a:b:c", "Host 值的边界：空、只有端口、端口为空、冒号多于一个（裸 IPv6）原样")

check([activity.http_requests(m + b" /x HTTP/1.1\r\nHost: m.test\r\n\r\n")[0]["method"] for m in (b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE", b"GET", b"POST")] ==
      ["HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE", "GET", "POST"], "九种请求方法都认")
check([r["path"] for r in activity.http_requests(REQ(b"/a") + b"junk\r\n\r\n" + REQ(b"/x"))] == ["/a"], "后面不是请求行：停下，不往后逐字节找")
check(activity._host_name("host:abc") == "host:abc" and activity._host_name("host:80") == "host", "端口不是数字的不当端口去掉")

print("== TCP 上的 DNS ==")
frame_ = lambda name, ident, qtype="A": (lambda m: struct.pack(">H", len(m)) + m)(bytes(DNS(id=ident, rd=1, qd=DNSQR(qname=name, qtype=qtype))))          # noqa: E731
resp_ = lambda name, ident, addr: (lambda m: struct.pack(">H", len(m)) + m)(bytes(DNS(id=ident, qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type="A", rdata=addr))))     # noqa: E731
m1, m2 = frame_("tcp.one.test", 1), frame_("tcp.two.test", 2, "AAAA")
w = World()
w.tcp(PHONE, "192.168.1.1", 53, [(0, m1[:1]), (1, m1[1:9]), (9, m1[9:] + m2)], sport=41100)
ev = [e for e in activity.build(w.frames, w.dec) if e["kind"] == "dns"]
check([(e["name"], e["qtype"], e["transport"], e["port"], e["server"]) for e in ev] == [("tcp.one.test", 1, "tcp", 53, "192.168.1.1"), ("tcp.two.test", 28, "tcp", 53, "192.168.1.1")],
      "长度前缀被拆开 + 一个段里两条消息：两个查询事件，transport=tcp")
w = World()
w.dns(PHONE, "udp.test", "198.51.100.40")
check([e["transport"] for e in activity.build(w.frames, w.dec) if e["kind"] == "dns"] == ["udp"], "UDP 的 DNS 事件 transport=udp")
w = World()
w.add(up(PHONE), IP(src=LAN[PHONE], dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="x.local", qtype="PTR")))
check([e["transport"] for e in activity.build(w.frames, w.dec)] == ["udp"], "mDNS 事件 transport=udp")
w = World()
w.tcp(PHONE, "192.168.1.1", 53, [(0, m1[:-3])], sport=41101)
check([e for e in activity.build(w.frames, w.dec) if e["kind"] == "dns"] == [], "最后一条消息没收全：不产生事件")
w = World()
w.tcp(PHONE, "192.168.1.1", 53, [(0, frame_("asked.tcp", 3))], sport=41102, down_chunks=[(0, resp_("asked.tcp", 3, "198.51.100.41"))])
w.tcp(PHONE, "198.51.100.41", 443, [(0, tb.records(hello()))], sport=41103)
check([(e["kind"], e["name"], e.get("via")) for e in activity.build(w.frames, w.dec)] == [("dns", "asked.tcp", None), ("tls", "asked.tcp", "dns")], "TCP 上的 DNS 应答也进 IP -> 域名表：后面没有 SNI 的 TLS 连接能认出名字")
w = World()
w.tcp(PHONE, "192.168.1.1", 53, [(0, resp_("notaquery.test", 4, "198.51.100.42"))], sport=41104)
w.tcp(PHONE, "198.51.100.42", 443, [(0, tb.records(hello()))], sport=41107)
check(activity.build(w.frames, w.dec) == [], "客户端方向发出的「应答」不算查询，也不记入 IP -> 域名表")
w = World()
w.tcp(PHONE, "192.168.1.1", 5300, [(0, m1)], sport=41105)
check([e for e in activity.build(w.frames, w.dec) if e["kind"] == "dns"] == [], "不是 53 端口的 TCP 不当 DNS")
check(activity.dns_over_tcp(b"\x00\x64" + m1) == [], "长度前缀声明的比实际多（消息没收全）：整条丢掉，里面碰巧是一条完整消息也不读")
w = World()
w.tcp(PHONE, "192.168.1.1", 53, [(0, frame_("server.sent.query", 9)[:0])], sport=41106, down_chunks=[(0, frame_("backwards.test", 9))])
check([e for e in activity.build(w.frames, w.dec) if e["kind"] == "dns"] == [], "服务器方向发出的查询（方向反了）不算设备的查询")
check(activity.dns_over_tcp(b"\x00\x03abc" + m1) == [dns_.parse(m1[2:])] and activity.dns_over_tcp(b"\x00") == [] and activity.dns_over_tcp(b"") == [], "解不出的消息跳过但长度照算；不足 2 字节 / 空：没有消息")

print("== DNS over TLS ==")
w = World()
w.tcp(PHONE, "9.9.9.9", 853, [(0, tb.records(hello("dns.quad9.net")))], sport=41200)
ev = activity.build(w.frames, w.dec)
check([(e["kind"], e["name"], e["via"], e["port"], e["server"]) for e in ev] == [("dot", "dns.quad9.net", "sni", 853, "9.9.9.9")], "853 端口上的 ClientHello：kind=dot，名字取 SNI（不再同时产生 tls 事件）")
w = World()
w.dns(PHONE, "known.resolver", "9.9.9.10")
w.tcp(PHONE, "9.9.9.10", 853, [(0, tb.records(hello()))], sport=41201)
check([(e["kind"], e["name"], e.get("via")) for e in activity.build(w.frames, w.dec)] == [("dns", "known.resolver", None), ("dot", "9.9.9.10", "ip")], "没有 SNI：名字用服务器 IP，via=ip（不借 DNS 应答）")
w = World()
w.tcp(PHONE, "9.9.9.11", 853, [(0, b"hello, not tls")], sport=41202)
check(activity.build(w.frames, w.dec) == [], "853 端口上不是 TLS：没有事件")
w = World()
w.tcp(PHONE, "9.9.9.12", 443, [(0, tb.records(hello("dns.example")))], sport=41203)
check([e["kind"] for e in activity.build(w.frames, w.dec)] == ["tls"], "同样的 ClientHello 在 443 端口仍是 tls")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
