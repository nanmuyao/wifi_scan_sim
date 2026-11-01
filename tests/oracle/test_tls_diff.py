#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS ClientHello 对照 tshark：把 20 多种形状的 ClientHello（SNI 长短、无 SNI、ALPN、supported_versions、ECH、拆成 2 / 3 个记录、
拆在两个 TCP 段里、老式没有扩展、RFC 8448 的真实字节）各放进一条明文 TCP 连接写成 pcap，用 tshark 解，和 wifi80211.tls 逐字段比：
SNI、ALPN、supported_versions、legacy 版本、记录版本、握手类型、密码套件个数、扩展类型列表。"""
import logging
import os
import subprocess
import sys
import tempfile

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, Ether, Raw, conf, wrpcap  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
from wifi80211 import tls  # noqa: E402
import tls_build as b  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


RFC8448 = bytes.fromhex(
    "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece700000613011303"
    "1302010000910000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104"
    "00230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003"
    "020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c000240"
    "01")
FULL = [b.sni_ext("www.example.com"), b.alpn_ext("h2", "http/1.1"), b.versions_ext(0x0304, 0x0303), b.ext(10, b"\x00\x04\x00\x1d\x00\x17")]
H_FULL = b.hello(FULL)
CASES = [      # (名字, 字节流, TCP 段的切点)
    ("rfc8448", RFC8448, []),
    ("full", b.records(H_FULL), []),
    ("sni1", b.records(b.hello([b.sni_ext("a")])), []),
    ("sni-long", b.records(b.hello([b.sni_ext(("a" * 60 + ".") * 4 + "example.org")])), []),
    ("sni-two", b.records(b.hello([b.sni_ext("a.test", "b.test")])), []),
    ("no-sni", b.records(b.hello([b.alpn_ext("h2")])), []),
    ("alpn-h2", b.records(b.hello([b.sni_ext("x.test"), b.alpn_ext("h2")])), []),
    ("alpn-http1", b.records(b.hello([b.sni_ext("x.test"), b.alpn_ext("http/1.1")])), []),
    ("tls12-only", b.records(b.hello([b.sni_ext("x.test"), b.versions_ext(0x0303, 0x0302)])), []),
    ("ech", b.records(b.hello([b.sni_ext("public.test"), b.ext(0xfe0d, b"\x00" * 20)])), []),
    ("old-no-ext", b.records(b.hello(version=0x0301, ciphers=[0x002f, 0x0035])), []),
    ("ciphers-40", b.records(b.hello([b.sni_ext("x.test")], ciphers=range(0x1301, 0x1301 + 40))), []),
    ("session-32", b.records(b.hello([b.sni_ext("x.test")], session=b"s" * 32)), []),
    ("rec-version-0303", b.records(H_FULL, version=0x0303), []),
    ("split-2-records", b.records(H_FULL, [20]), []),
    ("split-3-records", b.records(H_FULL, [3, 70]), []),
    ("split-in-sni", b.records(H_FULL, [H_FULL.index(b"www.example.com") + 5]), []),
    ("split-tcp-2", b.records(H_FULL), [40]),
    ("split-tcp-3", b.records(H_FULL, [30]), [10, 60]),
    ("rfc8448-tcp-2", RFC8448, [100]),
]
CLIENT = ("192.0.2.10", "198.51.100.20")
FIELDS = ["tls.handshake.type", "tls.record.version", "tls.handshake.version", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str",
          "tls.handshake.extensions.supported_version", "tls.handshake.cipher_suites_length", "tls.handshake.extension.type"]


def make_pcap(path):
    pkts = []
    for i, (name, stream, cuts) in enumerate(CASES):
        sport, seq = 40000 + i, 1000
        parts = [stream[a:c] for a, c in zip([0] + cuts, cuts + [len(stream)])]
        base = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=CLIENT[0], dst=CLIENT[1])
        pkts.append(base / TCP(sport=sport, dport=443, flags="S", seq=seq - 1))
        for part in parts:
            pkts.append(base / TCP(sport=sport, dport=443, flags="PA", seq=seq, ack=1) / Raw(part))
            seq += len(part)
    wrpcap(path, pkts)


def tshark(path):
    cmd = ["tshark", "-r", path, "-Y", "tls.handshake.type == 1", "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|", "-e", "tcp.srcport"] + [x for f in FIELDS for x in ("-e", f)]
    rows = {}
    for line in subprocess.run(cmd, capture_output=True, text=True).stdout.split("\n"):
        if line:
            c = (line.split("\t") + [""] * (len(FIELDS) + 1))[:len(FIELDS) + 1]
            rows[int(c[0])] = dict(zip(FIELDS, c[1:]))
    return rows


def split(s):
    return [x for x in s.split("|") if x]


def expect(r):
    """我们读出的 -> tshark 同一字段的值。"""
    return {"tls.handshake.type": ["1"], "tls.record.version": ["0x%04x" % r["record_version"]], "tls.handshake.version": ["0x%04x" % r["version"]],
            "tls.handshake.extensions_server_name": r["sni"], "tls.handshake.extensions_alpn_str": r["alpn"],
            "tls.handshake.extensions.supported_version": ["0x%04x" % v for v in r["supported_versions"]],
            "tls.handshake.cipher_suites_length": [str(2 * r["cipher_suites"])], "tls.handshake.extension.type": [str(t) for t in r["extensions"]]}


with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "tls.pcap")
    make_pcap(path)
    ts = tshark(path)
ours_n = 0
for i, (name, stream, cuts) in enumerate(CASES):
    r = tls.parse_client_hello(stream)
    t = ts.get(40000 + i)
    if r is None or t is None:
        check(False, "%s：我们 %s，tshark %s" % (name, "读出" if r else "None", "认出" if t else "没有"))
        continue
    ours_n += 1
    e = expect(r)
    t = dict(t, **{"tls.record.version": "|".join(split(t["tls.record.version"])[:1])})      # tshark 每个记录列一个版本，我们取第一个记录的
    diff = [k for k in FIELDS if e[k] != split(t[k]) and not (k == "tls.handshake.extension.type" and not r["extensions"] and not split(t[k]))]
    check(not diff, "%s：和 tshark 逐字段一致%s" % (name, "" if not diff else "，不一致 %s：我们 %s，tshark %s" % (diff[0], e[diff[0]], t[diff[0]])))
check(ours_n == len(CASES) == 20 and len(ts) == 20, "20 个用例，tshark 认出 %d 个 ClientHello，我们读出 %d 个" % (len(ts), ours_n))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
