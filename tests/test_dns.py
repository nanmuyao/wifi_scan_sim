#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dns80211：域名（含压缩指针）、提问、应答记录。用 scapy 当独立的报文构造器；真实抓包由 tests/oracle/test_dns_diff.py 对 tshark。"""
import logging
import os
import struct
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, DNSQR, DNSRR, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wifi80211 import dns  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


HDR = lambda qd=0, an=0, flags=0: struct.pack(">HHHHHH", 0xBEEF, flags, qd, an, 0, 0)       # noqa: E731
Q = lambda name, t=1: b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0" + struct.pack(">HH", t, 1)       # noqa: E731

print("== 提问 ==")
m = dns.parse(bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="www.Example.com", qtype="AAAA"))))
check(m["id"] == 0x1234 and not m["response"] and m["opcode"] == 0 and m["rcode"] == 0, "头：id、QR=0、opcode、rcode")
check(m["questions"] == [{"name": "www.Example.com", "type": 28, "class": 1, "top_bit": 0}] and not m["answers"], "提问：名字保留大小写、类型 AAAA、类 IN")
check(dns.parse(bytes(DNS(qd=DNSQR(qname=".", qtype="NS"))))["questions"][0]["name"] == "", "根域名是空串")

u = "Karen\u2019s iMac".encode("utf-8")
check(dns.parse(HDR(1) + bytes([len(u)]) + u + b"\x04_ipp\0" + struct.pack(">HH", 1, 1))["questions"][0]["name"] == "Karen\u2019s iMac._ipp", "UTF-8 标签（mDNS 服务名）按 UTF-8 解")
check(dns.parse(HDR(1) + b"\x02\xff\xfe\0" + struct.pack(">HH", 1, 1))["questions"][0]["name"] == "\xff\xfe", "不是合法 UTF-8 的标签：按 latin-1 逐字节保留")

print("== 应答 ==")
a = bytes(DNS(id=7, qr=1, aa=1, rcode=3, ancount=3, qd=DNSQR(qname="a.example.org"), an=DNSRR(rrname="a.example.org", type="CNAME", ttl=300, rdata="b.example.org") /
                DNSRR(rrname="b.example.org", type="A", ttl=60, rdata="192.0.2.9") / DNSRR(rrname="b.example.org", type="AAAA", ttl=61, rdata="2001:db8::1")))
m = dns.parse(a)
check(m["response"] and m["rcode"] == 3 and [r["type"] for r in m["answers"]] == [5, 1, 28], "QR=1、rcode=3（NXDOMAIN）、应答类型依次是 CNAME / A / AAAA")
check(m["answers"][0]["data"] == "b.example.org" and m["answers"][1]["data"] == "192.0.2.9" and m["answers"][2]["data"] == "2001:db8:0:0:0:0:0:1", "CNAME 解出名字；A 点分；AAAA 不缩写")
check([r["ttl"] for r in m["answers"]] == [300, 60, 61] and m["answers"][1]["name"] == "b.example.org", "ttl 和应答的所有者名字")
txt = dns.parse(HDR(0, 1) + Q("x.y", 16)[:-4] + struct.pack(">HHIH", 16, 1, 5, 4) + b"\x03abc")
check(txt["answers"][0]["data"] == b"\x03abc", "不认识展开方式的类型（TXT）：data 是原始字节")
check(dns.parse(HDR(0, 1) + Q("x.y", 1)[:-4] + struct.pack(">HHIH", 1, 1, 5, 3) + b"\x01\x02\x03")["answers"][0]["data"] == b"\x01\x02\x03", "A 记录长度不是 4：不当地址，保留原始字节")
mdns = dns.parse(HDR(1) + Q("_hap._tcp.local", 12)[:-2] + struct.pack(">H", 0x8001))
check(mdns["questions"][0]["class"] == 1 and mdns["questions"][0]["top_bit"] == 1, "mDNS 的类高位（单播响应 / 缓存刷新）拆出来，类仍是 1")

print("== 压缩指针与坏报文 ==")
m = dns.parse(HDR(1, 1) + Q("a.b.c") + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + bytes([1, 2, 3, 4]))
check(m["answers"][0]["name"] == "a.b.c" and m["answers"][0]["data"] == "1.2.3.4", "指针 0xC00C 指回提问的名字")
m = dns.parse(HDR(1, 1) + Q("a.b.c") + b"\x01z\xc0\x0e" + struct.pack(">HHIH", 1, 1, 0, 4) + bytes([1, 2, 3, 4]))
check(m["answers"][0]["name"] == "z.b.c", "标签 + 指针（z 后接 b.c）")
check(dns.parse(HDR(1) + b"\xc0\x0c" + struct.pack(">HH", 1, 1)) is None, "指针指向自己：None（不死循环）")
check(dns.parse(HDR(1) + b"\xc0\x20" + b"\0" * 40) is None, "指针指向后面：None")
check(dns.parse(HDR(1) + b"\x01a\xc0\x0c" + struct.pack(">HH", 1, 1)) is None, "指针回到自己前面的标签并成环：None")
check(dns.parse(HDR(1) + b"\x40abc\0" + struct.pack(">HH", 1, 1)) is None, "保留的标签类型 0x40：None")
check(dns.parse(HDR(1) + b"\x40" + b"a" * 64 + b"\0" + struct.pack(">HH", 1, 1)) is None, "标签长度超过 63：None")
check(dns.parse(HDR(1) + b"".join(b"\x3f" + b"a" * 63 for _ in range(5)) + b"\0" + struct.pack(">HH", 1, 1)) is None, "名字总长超过 255：None")
check(dns.parse(b"\0" * 11) is None and dns.parse(HDR(1) + Q("a.b")[:-2]) is None and dns.parse(HDR(2) + Q("a.b")) is None, "头不足 12 / 提问被截断 / 提问个数大于实际：None")
t = dns.parse(HDR(1, 2) + Q("a.b") + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + bytes([1, 2, 3, 4]) + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 9) + b"\0")
check(t["truncated"] and len(t["answers"]) == 1, "第二条应答被截断：保留第一条并标 truncated")
check(dns.type_name(1) == "A" and dns.type_name(65) == "HTTPS" and dns.type_name(999) == "TYPE999", "类型名")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
