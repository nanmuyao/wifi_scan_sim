#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""capture.py 的单元测试：用手工拼出来的字节覆盖 pcap / pcapng / gzip 的各种写法。"""
import gzip
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wifi80211 import capture  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


# ---------- 构造器 ----------
def pcap(pkts, e="<", nano=False, linktype=127):
    magic = {("<", False): b"\xd4\xc3\xb2\xa1", ("<", True): b"\x4d\x3c\xb2\xa1",
             (">", False): b"\xa1\xb2\xc3\xd4", (">", True): b"\xa1\xb2\x3c\x4d"}[(e, nano)]
    out = magic + struct.pack(e + "HHiIII", 2, 4, 0, 0, 65535, linktype)
    for sec, frac, data in pkts:
        out += struct.pack(e + "IIII", sec, frac, len(data), len(data)) + data
    return out


def pad4(b):
    return b + b"\x00" * (-len(b) % 4)


def block(btype, body, e="<"):
    body = pad4(body)
    return struct.pack(e + "II", btype, len(body) + 12) + body + struct.pack(e + "I", len(body) + 12)


def opt(code, value, e="<"):
    return struct.pack(e + "HH", code, len(value)) + pad4(value)


def shb(e="<"):
    bom = struct.pack(e + "I", 0x1A2B3C4D)
    return block(0x0A0D0D0A, bom + struct.pack(e + "HHq", 1, 0, -1), e)


def idb(linktype=127, tsresol=None, e="<", desc=None):
    body = struct.pack(e + "HHI", linktype, 0, 0)
    if desc is not None:
        body += opt(3, desc, e)                      # if_description，长度不是 4 的倍数时选项要补齐
    if tsresol is not None:
        body += opt(9, bytes([tsresol]), e) + struct.pack(e + "HH", 0, 0)
    return block(1, body, e)


def epb(data, ticks, iface=0, e="<"):
    body = struct.pack(e + "IIIII", iface, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data)) + data
    return block(6, body, e)


def dsb(stype, secret, e="<"):
    return block(0x0A, struct.pack(e + "II", stype, len(secret)) + secret, e)


PKT_A, PKT_B, PKT_C = b"A" * 10, b"B" * 7, b"C" * 4     # 7 字节：块里要补齐

print("== 经典 pcap ==")
c = capture.parse_capture(pcap([(100, 500000, PKT_A), (101, 0, PKT_B)]))
check(c.format == "pcap" and [p.data for p in c.packets] == [PKT_A, PKT_B], "小端微秒")
check(abs(c.packets[0].ts - 100.5) < 1e-9 and c.packets[0].linktype == 127, "时间戳 100.5，链路类型 127")
c = capture.parse_capture(pcap([(100, 500, PKT_A)], nano=True))
check(abs(c.packets[0].ts - 100.0000005) < 1e-9, "小端纳秒")
c = capture.parse_capture(pcap([(100, 500000, PKT_A)], e=">"))
check(abs(c.packets[0].ts - 100.5) < 1e-9, "大端微秒")
c = capture.parse_capture(pcap([(1, 0, PKT_A)], linktype=105 | 0x10000000))
check(c.packets[0].linktype == 105, "链路类型高位的标志位被去掉")
raw = pcap([(1, 0, PKT_A), (2, 0, PKT_B)])
c = capture.parse_capture(raw[:-3])
check(c.truncated and [p.data for p in c.packets] == [PKT_A], "最后一个包被截断：保留前面的，标记 truncated")

print("== pcapng ==")
raw = shb() + idb(127) + epb(PKT_A, 1_500_000) + epb(PKT_B, 2_000_000)
c = capture.parse_capture(raw)
check(c.format == "pcapng" and [p.data for p in c.packets] == [PKT_A, PKT_B], "基本：SHB + IDB + 2 个 EPB（数据不是 4 的倍数也能对上）")
check(abs(c.packets[0].ts - 1.5) < 1e-9, "默认微秒精度")
c = capture.parse_capture(shb() + idb(127, tsresol=9) + epb(PKT_A, 2_500_000_000))
check(abs(c.packets[0].ts - 2.5) < 1e-9, "if_tsresol=9（纳秒）")
c = capture.parse_capture(shb() + idb(127, tsresol=9, desc=b"abc") + epb(PKT_A, 2_500_000_000))
check(abs(c.packets[0].ts - 2.5) < 1e-9, "前一个选项长度 3（要补齐到 4）后面的 if_tsresol 仍读对")
c = capture.parse_capture(shb() + idb(127, tsresol=9) + epb(PKT_A, 5_000_000_000))
check(abs(c.packets[0].ts - 5.0) < 1e-9, "时间戳超过 2^32 个单位：高 32 位也要算")
c = capture.parse_capture(shb() + idb(127, tsresol=0x80 | 10) + epb(PKT_A, 3 * 1024))
check(abs(c.packets[0].ts - 3.0) < 1e-9, "if_tsresol 最高位=1：2 的幂（2^-10 秒）")
c = capture.parse_capture(shb(">") + idb(105, e=">") + epb(PKT_C, 1_000_000, e=">"))
check(c.packets[0].data == PKT_C and c.packets[0].linktype == 105 and abs(c.packets[0].ts - 1.0) < 1e-9, "大端")
c = capture.parse_capture(shb() + idb(127) + idb(1) + epb(PKT_A, 0, iface=1) + epb(PKT_B, 0, iface=0))
check([(p.linktype, p.iface) for p in c.packets] == [(1, 1), (127, 0)], "多个接口：每个包带自己接口的链路类型")
c = capture.parse_capture(shb() + idb(127) + dsb(0x57474b4c, b"secret-bytes!") + epb(PKT_A, 0) + block(0x40000BAD, b"custom") + epb(PKT_B, 0))
check(c.secrets == [(0x57474b4c, b"secret-bytes!")], "Decryption Secrets Block 读出类型和内容")
check(len(c.packets) == 2, "未知/自定义块被跳过，后面的包还在")
c = capture.parse_capture(shb("<") + idb(127) + epb(PKT_A, 0) + shb(">") + idb(105, e=">") + epb(PKT_B, 0, e=">"))
check([(p.data, p.linktype) for p in c.packets] == [(PKT_A, 127), (PKT_B, 105)], "第二个 section 换字节序、重新建接口表")
raw = shb() + idb(127) + epb(PKT_A, 0) + epb(PKT_B, 0)
c = capture.parse_capture(raw[:-5])
check(c.truncated and [p.data for p in c.packets] == [PKT_A], "最后一块被截断：保留前面的")
spb = block(3, struct.pack("<I", 4) + PKT_C)
c = capture.parse_capture(shb() + idb(127) + spb)
check(c.packets[0].data == PKT_C and c.packets[0].origlen == 4, "Simple Packet Block")
c = capture.parse_capture(shb() + idb(127) + block(3, struct.pack("<I", 100) + PKT_C))
check(c.packets[0].data == PKT_C and c.packets[0].caplen == 4 and c.packets[0].origlen == 100,
      "Simple Packet Block 原始长度 100、实际只存了 4 字节")

print("== 出错 ==")
for name, raw in (("不认识的格式", b"hello world, not a capture"),
                  ("pcapng 字节序标记错", b"\x0a\x0d\x0d\x0a" + struct.pack("<II", 28, 0xDEADBEEF) + b"\x00" * 20),
                  ("pcapng 块长度不是 4 的倍数", shb() + struct.pack("<II", 6, 13) + b"\x00" * 5),
                  ("EPB 引用不存在的接口", shb() + idb(127) + epb(PKT_A, 0, iface=3))):
    try:
        capture.parse_capture(raw)
        check(False, name + "：应当报错")
    except ValueError:
        check(True, name + "：ValueError")

print("== gzip ==")
with tempfile.TemporaryDirectory() as tmp:
    raw = shb() + idb(127) + epb(PKT_A, 1_000_000)
    p = os.path.join(tmp, "a.pcapng.gz")
    with open(p, "wb") as f:
        f.write(gzip.compress(raw))
    check([x.data for x in capture.read_capture(p).packets] == [PKT_A], "gzip 包着的 pcapng")
    p = os.path.join(tmp, "b.pcap")
    with open(p, "wb") as f:
        f.write(pcap([(1, 0, PKT_B)]))
    check([x.data for x in capture.read_capture(p).packets] == [PKT_B], "没压缩的 pcap")
    p = os.path.join(tmp, "c.pcap.gz")
    with open(p, "wb") as f:
        f.write(gzip.compress(pcap([(1, 0, PKT_A), (2, 0, PKT_B)]))[:-12])      # gzip 流被截断
    check(len(capture.read_capture(p).packets) >= 1, "gzip 流被截断：已解出的部分仍可读")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
