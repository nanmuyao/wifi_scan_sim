#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QUIC Initial 对 tshark：tests/quic_build.py 独立造出各种客户端 Initial（不同 SNI、令牌、v2、ClientHello 拆在几个包里、合并的数据报、没有 SNI），
写成普通的 Ethernet/IPv4/UDP 抓包；tshark 4.4 自己会解 Initial。逐包比版本 / DCID / SCID / 包号 / CRYPTO 偏移，逐连接比 SNI，
并且我们取出的 ClientHello 必须与构造时的字节完全相同。"""
import logging
import os
import struct
import subprocess
import sys
import tempfile

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, UDP, Ether, Raw, conf, wrpcap  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import quic_build as qb  # noqa: E402
from wifi80211 import quic  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def sni_of(hello):
    """ClientHello 里的 server_name（本测试自己的小解析，只为和 tshark 比）。"""
    p = 4 + 2 + 32
    p += 1 + hello[p]
    p += 2 + struct.unpack(">H", hello[p:p + 2])[0]
    p += 1 + hello[p]
    end = p + 2 + struct.unpack(">H", hello[p:p + 2])[0]
    p += 2
    while p + 4 <= end:
        t, n = struct.unpack(">HH", hello[p:p + 4])
        if t == 0:
            ln = struct.unpack(">H", hello[p + 7:p + 9])[0]
            return hello[p + 9:p + 9 + ln].decode()
        p += 4 + n
    return None


D = lambda n: bytes([n]) * 8        # noqa: E731
CASES = []                          # (名字, [数据报...], 期望的 ClientHello 或 None)
h = qb.client_hello("www.example.com")
CASES.append(("单包", [qb.build(D(1), b"", qb.crypto_frame(0, h), pn=0)], h))
h = qb.client_hello("cdn.video.example.net")
CASES.append(("带令牌和 SCID、2 字节包号", [qb.build(D(2), b"\xaa\xbb\xcc\xdd", qb.crypto_frame(0, h), pn=300, pn_len=2, token=b"retry-token")], h))
h = qb.client_hello("split.example.org", extra=1400)
CASES.append(("ClientHello 拆在两个包里", [qb.build(D(3), b"\x01", qb.crypto_frame(0, h[:900]), pn=0), qb.build(D(3), b"\x01", qb.crypto_frame(900, h[900:]), pn=1)], h))
h = qb.client_hello("three.example.org", extra=2600)
CASES.append(("拆在三个包里，到达顺序是 2、1、3", [qb.build(D(4), b"", qb.crypto_frame(1000, h[1000:2000]), pn=1), qb.build(D(4), b"", qb.crypto_frame(0, h[:1000]), pn=0),
                                          qb.build(D(4), b"", qb.crypto_frame(2000, h[2000:]), pn=2)], h))
h = qb.client_hello("coalesced.example.org")
CASES.append(("两个 Initial 合并进一个数据报", [qb.build(D(5), b"", qb.crypto_frame(0, h[:60]), pn=0, pad_to=0) + qb.build(D(5), b"", qb.crypto_frame(60, h[60:]), pn=1)], h))
h = qb.client_hello("v2.example.org")
CASES.append(("QUIC v2", [qb.build(D(6), b"", qb.crypto_frame(0, h), pn=0, version=0x6b3343cf)], h))
h = qb.client_hello(None)
CASES.append(("没有 SNI", [qb.build(D(7), b"", qb.crypto_frame(0, h), pn=0)], h))
h = qb.client_hello("ack.example.org")
CASES.append(("ACK 帧在 CRYPTO 之前", [qb.build(D(8), b"", b"\x02\x05\x00\x00\x03" + qb.crypto_frame(0, h), pn=4)], h))

pkts, owner = [], []
for ci, (name, dgs, _) in enumerate(CASES):
    for dg in dgs:
        pkts.append(Ether() / IP(src="192.0.2.%d" % (ci + 1), dst="198.51.100.1") / UDP(sport=50000 + ci, dport=443) / Raw(dg))
        owner.append(ci)
path = os.path.join(tempfile.mkdtemp(), "quic.pcap")
wrpcap(path, pkts)

FIELDS = ["quic.version", "quic.dcid", "quic.scid", "quic.packet_number", "quic.crypto.offset", "tls.handshake.extensions_server_name"]
cmd = ["tshark", "-r", path, "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|", "-e", "frame.number"] + sum((["-e", f] for f in FIELDS), [])
out = subprocess.run(cmd, capture_output=True, text=True).stdout
rows = {}
for line in out.split("\n"):
    if line:
        c = (line.split("\t") + [""] * (len(FIELDS) + 1))[:len(FIELDS) + 1]
        rows[int(c[0])] = dict(zip(FIELDS, c[1:]))

print("== 逐包 ==")
n = 0
for i, dg in enumerate(pkts):
    t = rows.get(i + 1, {})
    mine = quic.parse_datagram(bytes(dg[Raw].load))
    # 合并的数据报里 tshark 的字段是用 | 连起来的列表
    got = {"quic.version": ["0x%08x" % m["version"] for m in mine], "quic.dcid": [m["dcid"].hex() for m in mine], "quic.scid": [m["scid"].hex() for m in mine],
           "quic.packet_number": [str(m["pn"]) for m in mine], "quic.crypto.offset": [str(o) for m in mine for o, _ in m["crypto"]]}
    ok = len(mine) > 0 and all(t.get(k, "") == "|".join(x for x in v if x) for k, v in got.items())          # tshark 把空的 SCID 略过
    n += ok
    if not ok:
        print("   第 %d 个包不一致：tshark %s，我们 %s" % (i + 1, t, got))
check(n == len(pkts) and len(pkts) == 11, "%d 个数据报里版本 / DCID / SCID / 包号 / CRYPTO 偏移和 tshark 逐字段一致" % n)

print("== 逐连接 ==")
res = quic.collect([bytes(p[Raw].load) for p in pkts])
for ci, (name, dgs, want) in enumerate(CASES):
    c = res.get(D(ci + 1))
    tsni = sorted({r["tls.handshake.extensions_server_name"] for i, r in rows.items() if owner[i - 1] == ci and r["tls.handshake.extensions_server_name"]})
    ours = sni_of(c["client_hello"]) if c and c["client_hello"] else None
    check(c is not None and c["client_hello"] == want and (tsni == [ours] if ours else tsni == []), "%s：ClientHello 字节相同；SNI 我们 %r，tshark %s" % (name, ours, tsni))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
