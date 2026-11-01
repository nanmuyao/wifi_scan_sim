#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""内容层的日志（docs/日志规范.md）：出了问题日志要说明信息在哪一步丢的。用合成的明文抓包 / 假的 802.11 帧跑 activity / plain / tcpstream / quic / apps / traffic / report，
用挂在 wifi80211 日志上的处理器收集记录，断言级别、消息和数字：干净的运行没有 WARNING；ClientHello 缺开头 / 缺口之后 / 带 ECH / 没有 SNI；QUIC 认证失败 / 版本不认得 / CRYPTO 不完整；
校验和不对的占比；认不出设备（WAN 一侧、cooked 地址）；规则认不出大多数域名时的提示；不带密钥。"""
import logging
import os
import re
import struct
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import quic_build as qb  # noqa: E402
import tls_build as tb  # noqa: E402
from wifi80211 import activity, apps, capture, dns, frames, logs, plain, quic, report, tcpstream, tls, traffic  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


class Catch(logging.Handler):
    def __init__(self):
        super().__init__(logs.TRACE)
        self.records = []

    def emit(self, record):
        self.records.append((record.levelname, record.name, record.getMessage()))


class capture_logs:
    """with capture_logs() as c: ... ；c.records 是 [(级别, 模块名, 消息)]。"""

    def __init__(self, level=logging.DEBUG):
        self.level = level

    def __enter__(self):
        self.h = Catch()
        self.root = logging.getLogger("wifi80211")
        self.old = self.root.level
        self.root.setLevel(self.level)
        self.root.addHandler(self.h)
        return self.h

    def __exit__(self, *a):
        self.root.removeHandler(self.h)
        self.root.setLevel(self.old)


def msgs(c, level=None, mod=None):
    return [m for lv, name, m in c.records if (level is None or lv == level) and (mod is None or name == "wifi80211." + mod)]


def has(c, text, level=None):
    return any(text in m for m in msgs(c, level))


DEV, RTR = "02:00:00:00:00:01", "02:00:00:00:00:fe"
LAN, SRV = "192.168.1.20", "203.0.113.80"
t = [1000.0]


def pkt(n, ip, src=DEV, dst=RTR):
    t[0] += 0.01
    return plain.Packet(n, t[0], src, dst, 0x0800, bytes(ip), False, None)


def up(ip, n):
    return pkt(n, ip, DEV, RTR)


def down(ip, n):
    return pkt(n, ip, RTR, DEV)


def tcp_conn(sport, dport, hello_records, server=SRV, syn=True, cut=None, start=100):
    """一条 TCP 连接的包（上行 / 下行已区分）：SYN、SYN+ACK、客户端数据段。cut：[(偏移, 长度)] 给了就只发这些片段（造缺口）。"""
    out = []
    if syn:
        out += [("u", IP(src=LAN, dst=server) / TCP(sport=sport, dport=dport, seq=start - 1, flags="S")), ("d", IP(src=server, dst=LAN) / TCP(sport=dport, dport=sport, seq=900, ack=start, flags="SA"))]
    for off, ln in (cut or [(0, len(hello_records))]):
        out.append(("u", IP(src=LAN, dst=server) / TCP(sport=sport, dport=dport, seq=start + off, ack=901, flags="PA") / Raw(hello_records[off:off + ln])))
    return out


def run_plain(items):
    packets = [(up if d == "u" else down)(ip, i + 1) for i, (d, ip) in enumerate(items)]
    return plain.analyze(packets)


hello_sni = lambda name, *ext: tb.records(tb.hello([tb.sni_ext(name)] + list(ext)))      # noqa: E731

print("== 干净的运行 ==")
dnsq = ("u", IP(src=LAN, dst="192.168.1.1") / UDP(sport=50000, dport=53) / DNS(id=1, qd=DNSQR(qname="clean.example.org")))
dnsa = ("d", IP(src="192.168.1.1", dst=LAN) / UDP(sport=53, dport=50000) / DNS(id=1, qr=1, qd=DNSQR(qname="clean.example.org"), an=DNSRR(rrname="clean.example.org", type="A", rdata=SRV)))
with capture_logs() as c:
    res = run_plain([dnsq, dnsa] + tcp_conn(41000, 443, hello_sni("clean.example.org")))
check(len(res.events) == 2 and not msgs(c, "WARNING") and not msgs(c, "ERROR"), "DNS + 带 SNI 的 TLS：2 个事件，没有 WARNING 和 ERROR")
check(has(c, "读到 1 个 ClientHello（其中 DoT 0）；没有 SNI 0（用 DNS 补上名字 0，没名字 0）；带 ECH 0", "INFO") and has(c, "事件 2 个，来自 1 台设备", "INFO"), "INFO：ClientHello 的各项数字、事件和设备数")
check(has(c, "认出 1 台设备；路由器 MAC 学到 1 个（%s）" % RTR, "INFO") and has(c, "方向判断：上行 3，下行 2", "INFO"), "plain：认出的设备数、学到的路由器 MAC、上下行判断的个数")
check(has(c, "协议层：") and has(c, "snap/ipv4/tcp 3") and has(c, "snap/ipv4/udp/dns 2"), "协议层组合的计数")
check(has(c, "TCP：1 条连接（2 个方向，1 个方向有数据）", "INFO") and not has(c, "缺包"), "TCP 重组小结：1 条连接，没有缺口")
check(has(c, "设备 %s：dns 1、tls 1" % DEV, "DEBUG"), "DEBUG：每台设备的事件种类")
check(not any(re.search(r"[0-9a-fA-F]{32,}", m) for _l, _n, m in c.records), "日志里没有 16 字节以上的十六进制串（没有密钥、随机数）")

print("== ClientHello 读不到的各种原因 ==")
hello_bytes = hello_sni("lost.example.org")
with capture_logs() as c:
    res = run_plain(tcp_conn(41001, 443, hello_bytes, cut=[(30, len(hello_bytes) - 30)]))
check(res.events == [] and has(c, "起点就缺 1", "WARNING") and has(c, "缺 30 字节", "WARNING"), "SYN 之后的前 30 字节没到：WARNING 说明起点就缺 1 个方向，TCP 缺口的字节数")
with capture_logs() as c:
    res = run_plain(tcp_conn(41002, 443, b"junkjunk!" + b"X" * 20 + hello_bytes, cut=[(0, 9), (29, len(hello_bytes))]))
check(has(c, "缺口之后才有 ClientHello 1", "WARNING") and res.events == [], "开头是别的数据、缺口之后才是 ClientHello：WARNING 点出「缺口之后才有 ClientHello 1」")
with capture_logs() as c:
    res = run_plain(tcp_conn(41003, 443, hello_bytes[:40]))
check(has(c, "tls_truncated 1", "WARNING") and res.events == [], "ClientHello 只到一半（读不到 SNI）：WARNING 的 tls_truncated 为 1")
with capture_logs() as c:
    res = run_plain(tcp_conn(41004, 443, hello_sni("ech.example.org", tb.ext(0xfe0d, b"\x00" * 12))))
check([e["name"] for e in res.events] == ["ech.example.org"] and has(c, "带 ECH 1（SNI 是外层公开名", "INFO"), "带 ECH：名字照取，但日志记「带 ECH 1」并说明 SNI 是外层公开名")
with capture_logs() as c:
    res = run_plain(tcp_conn(41005, 443, tb.records(tb.hello([tb.alpn_ext("h2")]))))
check(res.events == [] and has(c, "没有 SNI 1（用 DNS 补上名字 0，没名字 1）", "INFO") and has(c, "包读了，但一个访问事件也没有", "WARNING"), "没有 SNI、也没有先前的 DNS 应答：没名字 1；一个事件也没有时给 WARNING")
with capture_logs() as c:
    res = run_plain([dnsq, dnsa] + tcp_conn(41006, 443, tb.records(tb.hello([tb.alpn_ext("h2")]))))
check([e["via"] for e in res.events if e["kind"] == "tls"] == ["dns"] and has(c, "没有 SNI 1（用 DNS 补上名字 1，没名字 0）", "INFO") and has(c, "1 个事件的名字来自这台设备自己先前的 DNS 应答", "INFO"), "没有 SNI 但有 DNS 应答：用 DNS 补名字，日志里记 1 个")
with capture_logs() as c:
    run_plain(tcp_conn(41007, 443, b"\x16\x03\x03\x00\x05\x02\x00\x00\x01\x03") + tcp_conn(41008, 8888, b"BINARYPROTO" * 3) + tcp_conn(41009, 443, b"\x16\x03\x03\x00\x05\x0b\x00\x00\x01\x00"))
check(has(c, "TLS 不是 ClientHello 1，服务器方向 1，其它协议 1", "DEBUG") and not has(c, "ClientHello / 请求没读到"), "ServerHello 记成「服务器方向」、证书消息记成「不是 ClientHello」、二进制协议记成「其它协议」：都不算信息丢失，没有 WARNING")

print("== DoT、没有 Host 的 HTTP、MSDU 不是 SNAP ==")
with capture_logs() as c:
    res = run_plain(tcp_conn(41100, 853, hello_sni("dot.example.org")))
check([e["kind"] for e in res.events] == ["dot"] and has(c, "读到 1 个 ClientHello（其中 DoT 1）", "INFO"), "853 端口的 ClientHello：记成 DoT 1")
nohost = b"GET /x HTTP/1.0\r\n\r\n"
with capture_logs() as c:
    res = run_plain(tcp_conn(41101, 80, nohost, server="198.51.100.20"))
check(res.events == [] and has(c, "HTTP：读到 1 个请求（Host 缺失用 DNS 补名 0，没名字 1）", "INFO"), "HTTP 请求没有 Host、也没有 DNS 应答：没名字 1")
dns2 = ("d", IP(src="192.168.1.1", dst=LAN) / UDP(sport=53, dport=50000) / DNS(id=2, qr=1, qd=DNSQR(qname="nohost.example.org"), an=DNSRR(rrname="nohost.example.org", type="A", rdata="198.51.100.21")))
with capture_logs() as c:
    res = run_plain([dns2] + tcp_conn(41102, 80, nohost, server="198.51.100.21"))
check([e["name"] for e in res.events if e["kind"] == "http"] == ["nohost.example.org"] and has(c, "HTTP：读到 1 个请求（Host 缺失用 DNS 补名 1，没名字 0）", "INFO"), "HTTP 请求没有 Host、但有这台设备的 DNS 应答：用 DNS 补名 1")
col = activity.Collector()
with capture_logs() as c:
    col.feed(1, 1.0, DEV, [b"\x00" * 20, b"\x01\x02\x03"])
    col.finish()
check(has(c, "2 个 MSDU 不是 LLC/SNAP", "INFO"), "不是 LLC/SNAP 的 MSDU：记个数")

print("== QUIC ==")
dcid, scid = bytes.fromhex("8394c8f03e515708"), b"\x01\x02"
good = qb.build(dcid, scid, qb.crypto_frame(0, qb.client_hello("quic.example.org")))
bad_auth = bytearray(good)
bad_auth[200] ^= 0xFF
unknown_ver = bytearray(good)
unknown_ver[1:5] = b"\x1a\x2a\x3a\x4a"
short = b"\x40" + os.urandom(1300)
q1, q2 = qb.client_hello("split.quic.example", extra=1500)[:900], qb.client_hello("split.quic.example", extra=1500)[900:]


def quic_items(*datagrams, server="198.51.100.7"):
    return [("u", IP(src=LAN, dst=server) / UDP(sport=52000 + i, dport=443) / Raw(bytes(d))) for i, d in enumerate(datagrams)]


with capture_logs() as c:
    res = run_plain(quic_items(good))
check([e["name"] for e in res.events] == ["quic.example.org"] and has(c, "QUIC：1 个连接，ClientHello 读全并有名字 1，CRYPTO 流不完整 0", "INFO") and not msgs(c, "WARNING"), "正常的 QUIC Initial：1 个连接，名字有了，没有 WARNING")
with capture_logs() as c:
    res = run_plain(quic_items(bad_auth, good, unknown_ver, short))
check(len(res.events) == 1 and has(c, "QUIC：3 个数据报里解开 1 个 Initial 包（1 个连接）", "DEBUG") and has(c, "没解开的数据报：认证失败（不是客户端 Initial，或内容被改） 1、QUIC 版本不认得 1", "DEBUG"), "认证失败、版本不认得的数据报各记 1 个（DEBUG，所有 QUIC 流汇总成一行）；短包头的 UDP 载荷根本不当 Initial 看；好的那个仍读出名字")
with capture_logs() as c:
    res = run_plain(quic_items(qb.build(dcid, scid, qb.crypto_frame(900, q2), pn=3)))
check(res.events == [] and has(c, "1 个 QUIC 连接的 CRYPTO 流不完整", "WARNING") and has(c, "CRYPTO 流不完整 1", "INFO"), "只收到后半段：WARNING 说明 CRYPTO 流不完整、没有名字")
with capture_logs() as c:
    run_plain(quic_items(qb.build(dcid, scid, qb.crypto_frame(0, qb.client_hello(None)))))
check(has(c, "没有 SNI 1，没名字 1", "INFO"), "QUIC 的 ClientHello 没有 SNI 也没有 DNS：记「没有 SNI 1，没名字 1」")
with capture_logs() as c:
    res = run_plain(quic_items(qb.build(dcid, scid, qb.crypto_frame(0, b"\x01\x00\x00\x04abcd"))))
check(res.events == [] and has(c, "CRYPTO 流不完整 0，读不出 1", "INFO"), "CRYPTO 流是完整的握手消息，但里面读不出 ClientHello：记「读不出 1」")
ech_hello = tb.hello([tb.sni_ext("echq.example.org"), tb.ext(0xfe0d, b"\x00" * 12)])
with capture_logs() as c:
    res = run_plain(quic_items(qb.build(dcid, scid, qb.crypto_frame(0, ech_hello))))
check([e["name"] for e in res.events] == ["echq.example.org"] and has(c, "带 ECH 1", "INFO") and "QUIC：1 个连接" in [m for m in msgs(c, "INFO") if m.startswith("QUIC")][0], "QUIC 的 ClientHello 带 ECH：名字照取，记「带 ECH 1」")
with capture_logs() as c:
    run_plain(quic_items(qb.build(dcid, scid, qb.crypto_frame(900, q2), pn=3)))
check(has(c, "QUIC：1 个数据报里解开 1 个 Initial 包（1 个连接），ClientHello 读全 0 个、CRYPTO 流不完整 1 个；没解开的数据报：无", "DEBUG"), "DEBUG 的 QUIC 汇总行也记 CRYPTO 流不完整 1 个")

print("== 校验和、分片、解析不了 ==")
good_ip = IP(src=LAN, dst=SRV) / UDP(sport=50001, dport=7777) / Raw(b"x" * 20)
bad_bytes = bytearray(bytes(good_ip))
bad_bytes[-1] ^= 0xFF
items = [("u", good_ip)] * 9
with capture_logs() as c:
    run_plain(items + [("u", IP(bytes(bad_bytes)))])
check(has(c, "1 个包（10%）的校验和不对", "WARNING"), "10 个包里 1 个校验和不对（10%）：WARNING，并说明多半是解密不对或抓包机的校验和卸载")
with capture_logs() as c:
    run_plain(items * 5 + [("u", IP(bytes(bad_bytes)))])
check(has(c, "1 个包（2%）的校验和不对", "INFO") and not has(c, "校验和不对", "WARNING"), "46 个包里 1 个（2%）：低于 5% 只记 INFO")
frag = IP(src=LAN, dst=SRV, flags="MF", frag=0, proto=17) / Raw(b"\x00" * 40)
with capture_logs() as c:
    run_plain([("u", frag), ("u", good_ip)])
check(has(c, "1 个 IPv4 分片没有重组", "INFO"), "IPv4 分片：记个数，说明不读上层")
broken_dns = ("u", IP(src=LAN, dst="192.168.1.1") / UDP(sport=50002, dport=53) / Raw(b"\x00\x01"))
with capture_logs() as c:
    run_plain([broken_dns, ("u", good_ip)])
check(has(c, "1 个发往 DNS 端口的 UDP 包解不出 DNS 报文", "INFO"), "发往 53 端口却解不出 DNS：记个数")

print("== 认不出设备 ==")
wan = [("u", IP(src="198.51.100.%d" % (i + 1), dst="203.0.113.9") / TCP(sport=40000 + i, dport=443, seq=1, flags="A")) for i in range(12)]
with capture_logs() as c:
    run_plain(wan)
check(has(c, "100% 的 IP 包两端都是公网地址：抓的多半是路由器 WAN 一侧", "WARNING") and has(c, "一台设备也没认出来", "WARNING") and has(c, "12 个包认不出设备：两端都是公网 / 组播 / 广播地址 12", "INFO"), "全是公网到公网：WARNING 指出多半抓在 WAN 一侧，一台设备也没认出来，并给原因计数")
mixed = [("u", IP(src=LAN, dst=SRV) / TCP(sport=40500 + i, dport=443, seq=1, flags="A")) for i in range(4)] + wan[:8]
with capture_logs() as c:
    run_plain(mixed)
check(has(c, "67% 的 IP 包两端都是公网地址", "WARNING"), "12 个 IP 包里 8 个两端都是公网（67%）：已经够警告（阈值是一半，不是几乎全部）")
with capture_logs() as c:
    run_plain(wan[:9])
check(not has(c, "两端都是公网地址：抓的多半是", "WARNING"), "只有 9 个 IP 包：样本太少，不下「抓在 WAN 一侧」的结论")
arp_pkts = [plain.Packet(i, 1.0, DEV, "ff:ff:ff:ff:ff:ff", 0x0806, b"\0" * 28, False, None) for i in range(20)]
with capture_logs() as c:
    plain.analyze(arp_pkts + [up(ip, 100 + i) for i, (_d, ip) in enumerate(wan)])
check(has(c, "100% 的 IP 包两端都是公网地址", "WARNING") and has(c, "不是 IP 包（ARP、LLDP、STP 等） 20", "INFO"), "ARP 不算 IP 包：20 个 ARP + 12 个公网到公网，占比按 IP 包算（100%），不被 ARP 稀释")
cooked_only = [plain.Packet(i, 1.0, DEV, None, 0x0800, bytes(IP(src=LAN, dst="192.168.1.99") / UDP(sport=1, dport=2)), True, 0) for i in range(3)]
with capture_logs() as c:
    plain.analyze(cooked_only)
check(not has(c, "没学到路由器的 MAC", "WARNING"), "cooked 抓包本来就学不到路由器 MAC：不为它发警告")
arp = plain.Packet(1, 1.0, DEV, "ff:ff:ff:ff:ff:ff", 0x0806, b"\0" * 28, False, None)
with capture_logs() as c:
    plain.analyze([arp])
check(has(c, "1 个包认不出设备：不是 IP 包（ARP、LLDP、STP 等） 1", "INFO"), "ARP：原因记成「不是 IP 包」")
with capture_logs() as c:
    plain.analyze([pkt(1, IP(src=LAN, dst="192.168.1.99") / UDP(sport=1, dport=2))])
check(has(c, "没学到路由器的 MAC", "WARNING"), "只有局域网内部的往来、没学到路由器：WARNING")


class FakeCap:
    def __init__(self, items):
        self.packets = items


class P:
    def __init__(self, data, linktype):
        self.data, self.linktype, self.ts = data, linktype, 1.0


sll_bad = struct.pack(">HHH8sH", 0, 772, 6, b"\0" * 8, 0x0800) + bytes(good_ip)                   # arphrd 772 = 环回，不是以太网
sll_ok = struct.pack(">HHH8sH", 0, 1, 6, bytes.fromhex(DEV.replace(":", "")) + b"\0\0", 0x0800) + bytes(good_ip)
with capture_logs() as c:
    got = plain.iter_packets(FakeCap([P(sll_bad, 113), P(sll_ok, 113), P(b"\x00" * 5, 1), P(sll_ok, 113)]))
check(len(got) == 3 and has(c, "读到 4 个包；链路类型：以太网 1，Linux cooked v1 3", "INFO") and has(c, "1 个包太短或链路类型不认得", "WARNING") and has(c, "1 个 cooked 包的链路层地址不是 6 字节以太网 MAC", "WARNING"), "cooked 地址不是以太网 MAC / 包太短：WARNING 带个数和建议（别用 -i any）")

print("== 802.11 里不归设备的帧 ==")
AP = "02:00:00:00:00:aa"
SNAP = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"


def f80211(n, h, ip):
    return frames.Frame(n, 100.0 + n, b"", h, b"", True), {"how": "pairwise", "msdus": [SNAP + bytes(ip)]}


fa, da = f80211(1, {"to_ds": 0, "from_ds": 1, "sa": AP, "da": "01:00:5e:00:00:fb"}, IP(src=LAN, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="x.local")))
fb, db = f80211(2, {"to_ds": 1, "from_ds": 1, "sa": DEV, "da": AP}, IP(src=LAN, dst=SRV) / UDP(sport=1, dport=2))
with capture_logs() as c:
    activity.analyze([fa, fb], {1: da, 2: db})
check(has(c, "1 个帧不归任何设备：AP 发出的组播 / 广播帧（转发的副本）", "INFO") and has(c, "1 个帧不归任何设备：WDS / IBSS（分不出哪个是设备）", "INFO") and has(c, "另有 2 个不归任何设备", "INFO"), "AP 转发的组播副本、WDS：各记 1 个，原因不同")

print("== tcpstream / tls / dns 的小结 ==")


def seg(seq, data=b"", flags="A", cs_ok=True, rev=False):
    ip, (sp, dp) = (IP(src=SRV, dst=LAN), (2, 1)) if rev else (IP(src=LAN, dst=SRV), (1, 2))
    p = net_tcp(bytes(ip / TCP(sport=sp, dport=dp, seq=seq, flags=flags) / Raw(data)))
    return p if cs_ok else dict(p, checksum_ok=False)


def net_tcp(raw):
    from wifi80211 import net
    ip = net.parse_ipv4(raw)
    return net.parse_tcp(ip["payload"], ip)


f = tcpstream.Flows()
f.add(LAN, SRV, seg(10, flags="S"))
f.add(LAN, SRV, seg(11, b"abc"))
f.add(LAN, SRV, seg(20, b"def"))
f.add(LAN, SRV, seg(40, b"junk", cs_ok=False))
f.add(SRV, LAN, seg(500, b"mid", rev=True))
s = f.summary()
check(s == {"connections": 1, "directions": 2, "with_data": 2, "with_gap": 1, "missing_bytes": 6, "no_syn": 1, "bad_checksum": 1}, "Flows.summary：1 条连接 2 个方向，1 个方向有 6 字节缺口，1 个方向没有 SYN，1 个坏校验和的段被丢")
with capture_logs() as c:
    f.log_summary()
check(has(c, "1 个方向中途缺包，一共缺 6 字节", "WARNING") and has(c, "1 个方向没抓到 SYN", "INFO") and has(c, "1 个段因校验和不对被丢掉", "WARNING"), "log_summary：缺口、没有 SYN、坏校验和各一条")
with capture_logs() as c:
    tcpstream.Flows().log_summary()
check(c.records == [], "没有 TCP 流时不写日志")
check(f.dirs[(LAN, 1, SRV, 2)].missing_bytes() == 6 and tcpstream.Direction().missing_bytes() == 0, "missing_bytes：缺口之间的字节数；空方向 0")
check([tls.diagnose(x)[0] for x in (b"", b"GET / HTTP/1.1", b"\x16\x03\x03\x00\x05\x02\x00\x00\x01\x03", tb.records(tb.hello([tb.sni_ext("a.test")]))[:40], tb.records(tb.hello([tb.sni_ext("a.test")])))] == ["empty", "not_tls", "not_hello", "truncated", "ok"], "tls.diagnose：没有数据 / 不是 TLS / 不是 ClientHello / 被截断 / 可读")
with capture_logs(logs.TRACE) as c:
    dns.parse(b"\x00\x01")
    dns.parse(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03abc")
check(len(msgs(c, "TRACE", "dns")) == 2 and "只有 2 字节" in msgs(c, "TRACE", "dns")[0], "dns：解析不了的报文只在 TRACE 级别留一条原因")
with capture_logs(logging.DEBUG) as c:
    dns.parse(b"\x00\x01")
check(c.records == [], "级别 DEBUG 时逐包的 TRACE 不输出")

print("== 应用归类的提示 ==")
rules = apps.Rules()
rules.add({"apps": [{"app": "甲", "category": "视频", "suffix": ["known.test"]}]})
ev = lambda name, kind="dns": {"ts": 1.0, "station": DEV, "kind": kind, "name": name, "frame": 1}      # noqa: E731
with capture_logs() as c:
    got = apps.log_coverage(rules, [ev("n%d.test" % i) for i in range(12)])
check(got == (0, 12) and has(c, "12 个事件（mdns 除外）里 0 个（0%）归到了应用，12 个没有规则（12 个不同的名字）", "INFO") and has(c, "超过一半的事件（12/12）没有规则认出来", "WARNING") and has(c, "见 apps.unmatched", "WARNING"), "12 个事件全没规则：INFO 给数字，WARNING 给补规则的提示")
check(has(c, "没规则的名字前 10：n0.test×1", "DEBUG") and len([m for m in msgs(c, "DEBUG") if "前 10" in m][0].split("、")) == 10, "DEBUG：没规则的名字只列前 10 个")
with capture_logs() as c:
    got = apps.log_coverage(rules, [ev("a.known.test")] * 5 + [ev("n%d.test" % i) for i in range(7)])
check(got == (5, 12) and has(c, "超过一半的事件（7/12）没有规则认出来", "WARNING"), "7/12（58%）没规则：超过一半就提示（阈值不是 90%）")
with capture_logs() as c:
    got = apps.log_coverage(rules, [ev("n%d.test" % i) for i in range(5)])
check(got == (0, 5) and not msgs(c, "WARNING"), "事件少于 10 个：不提示（样本太少）")
with capture_logs() as c:
    got = apps.log_coverage(rules, [ev("a.known.test")] * 8 + [ev("zzz.test")] * 4 + [ev("svc.local", "mdns")])
check(got == (8, 12) and not msgs(c, "WARNING") and has(c, "8 个（67%）归到了应用", "INFO"), "多数认得：不提示；mdns 不计入")
with capture_logs() as c:
    r2 = apps.load()
check(has(c, "规则：2 个文件（自己的 0 个）", "INFO") and any(m.startswith("规则文件 ") for m in msgs(c, "DEBUG")) and len(r2.sources) == 2, "load：INFO 给文件数和规则数，DEBUG 逐个文件")

print("== 流量与结果 ==")
fl = lambda proto, rport, name, up_=100, down=900: dict(proto=proto, remote_port=rport, name=name, bytes_up=up_, bytes_down=down)      # noqa: E731
with capture_logs() as c:
    tot = traffic.log_summary([fl("tcp", 443, None), fl("tcp", 443, None), fl("udp", 443, None), fl("udp", 53, None), fl("udp", 53, None), fl("tcp", 80, "ok.test")])
check(tot == (6000, 5000), "log_summary 返回（总字节，没有名字的流的字节）")
check(has(c, "6 条流（tcp 3、udp 3），上行 600 B、下行 5.3 KiB", "INFO") and has(c, "没有名字的 5 条", "INFO") and has(c, "可能带名字的（TCP、UDP 443）4 条，没名字 3 条", "INFO") and has(c, "一半以上本该有名字的流没有名字（3/4）", "WARNING"), "流量小结：DNS 的 UDP 53 不算「本该有名字」，3/4 没名字才警告")
with capture_logs() as c:
    traffic.log_summary([fl("udp", 53, None)] * 20 + [fl("tcp", 443, "a.test")] * 3)
check(not msgs(c, "WARNING"), "一堆没有名字的 DNS 流不触发警告（它们本来就没有名字）")
with capture_logs() as c:
    traffic.log_summary([fl("tcp", 443, None), fl("tcp", 443, None)])
check(not msgs(c, "WARNING"), "本该有名字的流只有 2 条：样本太少，不警告")
rep = {"devices": [{"mac": DEV, "apps": [{"app": "甲"}, {"app": "乙"}], "events": 5}]}
with capture_logs() as c:
    report.log_result(rep, {"mode": "dot11", "frames": 100, "protected": 80, "decrypted": 70}, rules, [ev("a.known.test"), ev("b.test")], [fl("tcp", 443, "a.known.test", 1024, 2048)])
check(has(c, "结果：模式 dot11，帧 / 包 100 个，受保护 80 个解开 70 个；设备 1 台；事件 2 个；认出 2 个应用；上行 1.0 KiB、下行 2.0 KiB；没规则的事件占 50%", "INFO"), "结果一行：模式、帧数、解开数、设备数、事件数、应用数、流量、没规则的占比")
with capture_logs() as c:
    report.log_result({"devices": []}, {"mode": "plain", "frames": 3}, rules, [], [])
check(has(c, "结果：模式 plain，帧 / 包 3 个；设备 0 台；事件 0 个", "INFO") and has(c, "报告里没有设备", "WARNING") and not has(c, "受保护"), "明文模式的结果行不提受保护；没有设备时 WARNING")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
