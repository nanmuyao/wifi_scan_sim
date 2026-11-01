#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tls80211：从 TCP 流的开头读 ClientHello（SNI、ALPN、版本、ECH）。
RFC 8448 第 3 节公布的真实 TLS 1.3 ClientHello 当向量；其余用 tests/tls_build.py 的独立构造器；真实字节流对 tshark 由 tests/oracle/test_tls_diff.py 做。"""
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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

print("== RFC 8448 第 3 节的真实 ClientHello ==")
r = tls.parse_client_hello(RFC8448)
check(r["sni"] == ["server"] and r["tls13"] and r["supported_versions"] == [0x0304], "SNI 是 server；supported_versions 里有 TLS 1.3")
check(r["record_version"] == 0x0301 and r["version"] == 0x0303 and r["cipher_suites"] == 3, "记录版本 0x0301、legacy_version 0x0303、3 个密码套件")
check(r["extensions"] == [0, 0xff01, 10, 35, 51, 43, 13, 45, 28] and r["alpn"] == [] and not r["ech"] and not r["esni"] and not r["truncated"], "扩展类型依次、没有 ALPN、没有 ECH")

print("== 各种形状 ==")
h = b.hello([b.sni_ext("www.example.com"), b.alpn_ext("h2", "http/1.1"), b.versions_ext(0x0304, 0x0303)])
r = tls.parse_client_hello(b.records(h))
check(r["sni"] == ["www.example.com"] and r["alpn"] == ["h2", "http/1.1"] and r["supported_versions"] == [0x0304, 0x0303] and r["tls13"], "SNI、ALPN 两个协议、supported_versions 两个版本")
check(tls.parse_client_hello(b.records(b.hello([b.versions_ext(0x0303, 0x0302)])))["tls13"] is False, "supported_versions 里没有 0x0304：不是 TLS 1.3")
check(tls.parse_client_hello(b.records(b.hello([b.alpn_ext("h2")])))["sni"] == [], "没有 SNI：空表")
check(tls.parse_client_hello(b.records(b.hello([b.sni_ext("a.test", "b.test")])))["sni"] == ["a.test", "b.test"], "SNI 列表里有两个 host_name：都读出")
long_name = ("a" * 63 + ".") * 3 + "example.org"
check(tls.parse_client_hello(b.records(b.hello([b.sni_ext(long_name)])))["sni"] == [long_name], "长域名（%d 字节）" % len(long_name))
check(tls.parse_client_hello(b.records(b.hello([b.sni_ext("x.test")], ciphers=range(0x1301, 0x1301 + 40))))["cipher_suites"] == 40, "40 个密码套件")
check(tls.parse_client_hello(b.records(b.hello([b.sni_ext("x.test")], session=b"s" * 32)))["sni"] == ["x.test"], "有 32 字节 session_id")
check(tls.parse_client_hello(b.records(b.hello([b.sni_ext("x.test")], compression=b"\x00\x01")))["sni"] == ["x.test"], "压缩方法有两个")
e = tls.parse_client_hello(b.records(b.hello([b.sni_ext("x.test"), b.ext(0xfe0d, b"\x00" * 12)])))
check(e["ech"] and not e["esni"] and e["extensions"] == [0, 0xfe0d], "ECH 扩展（0xfe0d）存在：ech 为真")
check(tls.parse_client_hello(b.records(b.hello([b.ext(0xffce, b"\x00\x01")])))["esni"], "旧的 ESNI 扩展（0xffce）：esni 为真")
check(tls.parse_client_hello(b.records(b.hello([b.sni_ext("x.test")]), version=0x0303))["record_version"] == 0x0303, "记录版本取第一个记录的")
old = tls.parse_client_hello(b.records(b.hello(version=0x0301, ciphers=[0x002f])))
check(old is not None and old["sni"] == [] and old["extensions"] == [] and not old["truncated"], "没有扩展区的老式 ClientHello 也能读")
check(tls.parse_client_hello(b.records(b.hello([b.sni_ext("例.test")])))["sni"] == ["例.test"], "UTF-8 的 host_name 按 UTF-8 解")

print("== 握手消息拆在多个记录里 ==")
h = b.hello([b.sni_ext("split.example.net"), b.alpn_ext("h2"), b.versions_ext(0x0304)])
whole = tls.parse_client_hello(b.records(h))
for cuts in ([2], [4], [5], [30], [60, 90], [1, 2, 3], [len(h) - 1]):
    check(tls.parse_client_hello(b.records(h, cuts)) == whole, "切在 %s：结果和不拆时相同" % cuts)
check(tls.parse_client_hello(b.records(h, [10]) + b"\x17\x03\x03\x00\x01x") == whole, "后面跟着应用数据记录：不受影响")
check(tls.parse_client_hello(b.records(h) + h) == whole, "后面还有别的字节：只看第一条 ClientHello")

print("== 数据在中途结束 ==")
rec = b.records(b.hello([b.sni_ext("cut.example.net"), b.alpn_ext("h2"), b.versions_ext(0x0304)]))
sni_end = rec.index(b"cut.example.net") + len("cut.example.net")
check(tls.parse_client_hello(rec[:sni_end - 1]) is None, "SNI 还没读完就结束：None")
t = tls.parse_client_hello(rec[:sni_end])
check(t is not None and t["sni"] == ["cut.example.net"] and t["truncated"] and t["alpn"] == [], "刚好读完 SNI 就结束：返回，truncated，后面的扩展没有")
t = tls.parse_client_hello(rec[:-3])
check(t["truncated"] and t["sni"] == ["cut.example.net"] and t["alpn"] == ["h2"] and t["supported_versions"] == [], "最后一个扩展被截断：前面的保留，截断的那个不要")
check(tls.parse_client_hello(rec[:-3][:5] + rec[:-3][5:]) == t and tls.parse_client_hello(rec)["truncated"] is False, "完整的 truncated 为假")
check(all(tls.parse_client_hello(rec[:n]) is None or tls.parse_client_hello(rec[:n])["sni"] for n in range(len(rec))), "任意位置截断：要么 None，要么已经有 SNI")
check(tls.parse_client_hello(rec[:5]) is None and tls.parse_client_hello(rec[:8]) is None and tls.parse_client_hello(b"") is None, "只有记录头 / 握手头 / 空：None")

print("== 不是 ClientHello 或结构不对 ==")
check(tls.parse_client_hello(b"\x17\x03\x03\x00\x05hello") is None and tls.parse_client_hello(b"GET / HTTP/1.1\r\n\r\n") is None, "应用数据记录 / HTTP 明文：None")
check(tls.parse_client_hello(b.records(b"\x02" + h[1:])) is None, "握手类型是 ServerHello(2)：None")
check(tls.parse_client_hello(b"\x16\x02\x01\x00\x10" + h[:16]) is None and tls.parse_client_hello(b"\x16\x03\x01\x00\x10" + b"\x00" * 16) is None, "记录主版本不是 3 / 握手类型是 0：None")
bad = bytearray(h)
bad[4 + 2 + 32] = 200
check(tls.parse_client_hello(b.records(bytes(bad))) is None, "session_id 长度超过消息：None")
check(tls.parse_client_hello(b.records(b.hello([b.sni_ext("x.test")], raw_ciphers=b"\x13\x01\xc0"))) is None, "密码套件字节数是奇数：None")
check(tls.parse_client_hello(b.records(b.hello(raw_extensions=b"\x00\x20" + b.sni_ext("x.test")))) is None, "扩展区声明的长度和实际不符：None")
check(tls.parse_client_hello(b.records(b.hello([b.ext(0, b"\x00\x09\x00\x00\x10abc")]))) is None, "SNI 的列表长度超过扩展：None")
check(tls.parse_client_hello(b.records(b.hello([b.ext(0, b"\x00\x03\x00\x00\x00")])))["sni"] == [""], "SNI 条目是空名字：读出空串，不报错")
check(tls.parse_client_hello(b.records(b.hello([b.ext(16, b"\x00\x04\x09ab")]))) is None, "ALPN 条目长度超过列表：None")
check(tls.parse_client_hello(b.records(b.hello([b.ext(43, b"\x03\x03\x04\x03")]))) is None and tls.parse_client_hello(b.records(b.hello([b.ext(43, b"\x04\x03\x04")]))) is None, "supported_versions 长度是奇数 / 和扩展长度不符：None")
r = tls.parse_client_hello(b.records(b.hello([b.sni_ext("x.test")]) + b"\x00"))
check(r is not None and r["sni"] == ["x.test"] and not r["truncated"], "同一个记录里握手消息之后多出的字节：只看这条消息，不算截断")
check(tls.parse_client_hello(b.records(h, version=0x0201)) is None and tls.parse_client_hello(b"\x17\x03\x01" + b.records(h)[3:]) is None, "记录主版本不是 3 / 记录类型是应用数据，内容却是合法的 ClientHello：None")
check(tls.parse_client_hello(b.records(b.hello([b.ext(0, b"\x00\x0c\x01\x00\x03abc\x00\x00\x03xyz")]))) ["sni"] == ["xyz"], "SNI 里 name_type 不是 0 的条目不算 host_name")
check(tls.parse_client_hello(b.records(b.hello([b.ext(43, b"\x02\x03\x04\x03\x03")]))) is None, "supported_versions 的长度字节比扩展里实际的小（偶数）：None")
check(tls.parse_client_hello(b.records(b.hello(raw_extensions=b"\x00\x06\x00\x99\x00\xffab"))) is None, "完整的 ClientHello 里最后一个扩展声明的长度超出扩展区：None")
junk = b.records(b.hello([b.sni_ext("x.test")], claim_extra=6) + b"\x00\x99\x00\x00\x00")
r = tls.parse_client_hello(junk)
check(r is not None and r["truncated"] and r["extensions"] == [0], "握手头声明得更长、扩展区之后有多余字节：扩展只读到扩展区结束，算截断")
r = tls.parse_client_hello(b.records(b.hello([b.sni_ext("x.test"), b.ext(16, b"\x00\x09\x09ab")], claim_extra=5)))
check(r is not None and r["truncated"] and r["sni"] == ["x.test"] and r["alpn"] == [], "数据没到齐、后面某个扩展的内部长度坏了：已读到 SNI 就返回，坏的那个不要")
inner = bytearray(h)
inner[-1:] = b""
check(tls.parse_client_hello(b.records(bytes(inner))) is not None, "握手头声明的长度比实际长：当作截断处理（有 SNI 才返回）")

print("== 随机破坏：任何输入都不抛异常 ==")
rng = random.Random(8448)
bad_total = 0
for i in range(3000):
    d = bytearray(rec if i % 2 else RFC8448)
    for _ in range(rng.randint(1, 4)):
        d[rng.randrange(len(d))] = rng.randrange(256)
    d = bytes(d[:rng.randint(0, len(d))])
    try:
        tls.parse_client_hello(d)
    except Exception:       # noqa: BLE001
        bad_total += 1
check(bad_total == 0, "3000 个随机改字节 / 截断的输入：0 次异常")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
