#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""整条链从头到尾：合成一个 CCMP 加密的 802.11 抓包（独立加密方 tests/aead_build.py），里面有 DNS 查询与应答、TCP 握手 + 拆成两段的 TLS ClientHello、
明文 HTTP 请求、QUIC Initial；只给一把 TK（密钥表的 "tk" 项），用 pipeline.decrypt_capture -> activity.build 读出事件，
和 tshark 用同一把 TK 解密后读到的域名（dns.qry.name / tls.handshake.extensions_server_name / http.host）对照。
样例抓包里没有 TLS / QUIC 流，这是它们经过 802.11 解密后被认出来的唯一端到端对照。"""
import logging
import struct
import os
import subprocess
import sys
import tempfile

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aead_build as ab  # noqa: E402
import decrypt_oracle as d  # noqa: E402
import quic_build as qb  # noqa: E402
import tls_build as tb  # noqa: E402
from wifi80211 import activity  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import pipeline as pl  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


TK = bytes.fromhex("0e4dd207a9cefdf129eb9e17547080ec")
AP, STA, GW = bytes.fromhex("1a1b1c1d1e1f"), bytes.fromhex("2a2b2c2d2e2f"), bytes.fromhex("3a3b3c3d3e3f")
LAN, SRV = "192.168.7.20", "203.0.113.80"
SNAP = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"
pn = [0]
out = []


def send(ts, pkt, up=True):
    """一个 IP 包 -> 加密的 802.11 数据帧。上行：a1 = AP、a2 = 设备、a3 = 网关；下行：a1 = 设备、a2 = AP、a3 = 网关。"""
    pn[0] += 1
    if up:
        ab.A2, ab.A3, a1, kw = STA, GW, AP, dict(to_ds=1, from_ds=0)
    else:
        ab.A2, ab.A3, a1, kw = AP, GW, STA, dict(to_ds=0, from_ds=1)
    out.append((ts, ab.build("CCMP-128", TK, pn[0], SNAP + bytes(pkt), a1=a1, qos=0, **kw)))


t = 1700000000.0
send(t, IP(src=LAN, dst="192.168.7.1") / UDP(sport=50123, dport=53) / DNS(id=7, qd=DNSQR(qname="secure.example.org")))
send(t + .01, IP(src="192.168.7.1", dst=LAN) / UDP(sport=53, dport=50123) / DNS(id=7, qr=1, qd=DNSQR(qname="secure.example.org"), an=DNSRR(rrname="secure.example.org", type="A", rdata=SRV)), up=False)
send(t + .02, IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=100, flags="S"))
send(t + .03, IP(src=SRV, dst=LAN) / TCP(sport=443, dport=41000, seq=900, ack=101, flags="SA"), up=False)
ch = tb.records(tb.hello([tb.sni_ext("secure.example.org"), tb.alpn_ext("h2")]))
send(t + .04, IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=101, ack=901, flags="PA") / Raw(ch[:40]))
send(t + .05, IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=141, ack=901, flags="PA") / Raw(ch[40:]))
send(t + 1, IP(src=LAN, dst="198.51.100.9") / TCP(sport=41001, dport=80, seq=500, flags="S"))
send(t + 1.01, IP(src="198.51.100.9", dst=LAN) / TCP(sport=80, dport=41001, seq=700, ack=501, flags="SA"), up=False)
send(t + 1.02, IP(src=LAN, dst="198.51.100.9") / TCP(sport=41001, dport=80, seq=501, ack=701, flags="PA") / Raw(b"GET /index.html HTTP/1.1\r\nHost: Plain.Example.net:80\r\nUser-Agent: t\r\n\r\n"))
dcid = bytes.fromhex("8394c8f03e515708")
send(t + 2, IP(src=LAN, dst="203.0.113.99") / UDP(sport=52000, dport=443) / Raw(qb.build(dcid, b"\x01\x02", qb.crypto_frame(0, qb.client_hello("quic.example.com")))))

path = os.path.join(tempfile.mkdtemp(), "e2e.pcap")
with open(path, "wb") as f:                                              # 经典 pcap，链路类型 105 = 裸 802.11（没有 radiotap）
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105))
    for ts, dot11 in out:
        f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(dot11), len(dot11)) + dot11)
keys = [("tk", TK.hex())]

frames = list(fr.iter_frames(path))
res = pl.decrypt_capture(frames, keys)
check(len(frames) == len(out) == 10 and len(res) == 10 and {v["how"] for v in res.values()} == {"user_tk"}, "10 个加密帧全部用用户给的 TK 解开（how 都是 user_tk）")
ev = activity.build(frames, res)
ours = sorted((e["kind"], e["name"]) for e in ev)
check({e["station"] for e in ev} == {":".join("%02x" % b for b in STA)}, "所有事件都归到同一台设备（上行取源地址，下行取目的地址）")

usable, _ = d.tshark_usable(keys)
with d.key_env(usable) as env:
    cmd = ["tshark", "-r", path] + d.TSHARK_DECRYPT + ["-T", "fields", "-E", "occurrence=f", "-e", "frame.number", "-e", "tcp.dstport", "-e", "udp.dstport", "-e", "dns.flags.response",
                                                       "-e", "dns.qry.name", "-e", "tls.handshake.extensions_server_name", "-e", "http.host"]
    rows = [l.split("\t") + [""] * 7 for l in subprocess.run(cmd, capture_output=True, text=True, env=env).stdout.split("\n") if l]
theirs = []
for r in rows:
    _n, tcp, udp, resp, dns, sni, host = r[:7]
    if dns and resp == "False":
        theirs.append(("dns", dns))
    elif sni:
        theirs.append(("quic" if udp == "443" else "tls", sni))
    elif host:
        theirs.append(("http", host))
theirs.sort()
want = sorted([("dns", "secure.example.org"), ("tls", "secure.example.org"), ("http", "plain.example.net"), ("quic", "quic.example.com")])
check(ours == want, "我们读出的 4 个事件：DNS 查询、拆成两段的 TLS SNI、HTTP Host、QUIC SNI")
norm = lambda l: [(k, n.lower().split(":")[0]) for k, n in l]          # noqa: E731    tshark 的 http.host 保留原样（含大小写和端口），我们转小写去端口
check(norm(theirs) == ours, "tshark 用同一把 TK 解密后读到的域名与我们逐项相同（%d 项）" % len(ours))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
