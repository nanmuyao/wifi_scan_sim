#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""quic80211：Initial 密钥（RFC 9001 附录 A.1）、整个客户端 Initial 包（附录 A.2）、帧、CRYPTO 重组、坏输入。
包由 tests/quic_build.py 独立构造（先用 A.2 证明构造器本身是对的）。真实流量由 tests/oracle/test_quic_diff.py 对 tshark。"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import quic_build as qb  # noqa: E402
from wifi80211 import quic  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


DCID = bytes.fromhex("8394c8f03e515708")
# RFC 9001 附录 A.2：ClientHello（CRYPTO 帧的内容，245 字节）；包头 c3 00000001 08 DCID 00 449e 00000002 里 pn = 2、长度 1162
HELLO = bytes.fromhex(
    "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d00170018"
    "00100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806"
    "002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff")

print("== 密钥（RFC 9001 A.1）==")
k, iv, hp = quic.initial_keys(DCID)
check(k.hex() == "1f369613dd76d5467730efcbe3b1a22d" and iv.hex() == "fa044b2f42a3fd3b46fb255c" and hp.hex() == "9f50449e04a0e810283a1e9933adedd2", "key / iv / hp 和 RFC 公布的一致")
check(quic.initial_keys(DCID, 0xdeadbeef) is None and (k, iv, hp) == qb.keys(DCID), "不认识的版本 None；和独立构造器推出的相同")
check(quic.initial_keys(DCID, 0x6b3343cf) == qb.keys(DCID, 0x6b3343cf) and quic.initial_keys(DCID, 0x6b3343cf) != (k, iv, hp), "QUIC v2：盐和标签都不同，推出的密钥不同")

print("== 整个包（RFC 9001 A.2）==")
pkt = qb.build(DCID, b"", qb.crypto_frame(0, HELLO), pn=2, pn_len=4, pad_to=1200)
check(len(pkt) == 1200 and pkt.hex().startswith("c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c"), "构造器造出的包头、头保护后的包号、开头的密文和 RFC 一致")
check(pkt.hex().endswith("e221af44860018ab0856972e194cd934"), "整个包 1200 字节，结尾的 GCM tag 和 RFC 一致（整段明文都对）")
r = quic.parse_initial(pkt)
check(r["version"] == 1 and r["dcid"] == DCID and r["scid"] == b"" and r["pn"] == 2 and r["token"] == b"" and r["rest"] == b"", "版本 / 连接 ID / 包号 / 令牌 / 没有后续的包")
check(r["crypto"] == [(0, HELLO)] and r["frames"] == ["crypto", "padding"] and not r["truncated"], "CRYPTO 帧的内容就是 ClientHello，后面是 PADDING")
check(quic.client_hello(quic.crypto_stream(r["crypto"])) == HELLO, "ClientHello 完整地取出来")

print("== 包的各种形状 ==")
HELLO2 = qb.client_hello("www.example.org")
fr = qb.crypto_frame(0, HELLO2)
a = quic.parse_initial(qb.build(b"\x01\x02\x03\x04\x05\x06\x07\x08", b"\xaa\xbb", fr, pn=0x12345, pn_len=3, token=b"tok", pad_to=0))
check(a["dcid"] == bytes(range(1, 9)) and a["scid"] == b"\xaa\xbb" and a["token"] == b"tok" and a["pn"] == 0x12345, "非空的 SCID / 令牌；3 字节包号还原")
check(quic.parse_initial(qb.build(b"\x09" * 4, b"", fr, pn=7, pn_len=1))["pn"] == 7 and quic.parse_initial(qb.build(b"\x09" * 20, b"\x08" * 20, fr, pn=9, pn_len=2))["pn"] == 9, "1 / 2 字节包号；20 字节的连接 ID")
v2 = quic.parse_initial(qb.build(DCID, b"", fr, version=0x6b3343cf))
check(v2 is not None and v2["version"] == 0x6b3343cf and v2["crypto"] == [(0, HELLO2)], "QUIC v2 的 Initial（类型位是 01，盐和标签不同）")
check(quic.parse_initial(qb.build(DCID, b"", fr, version=1)[:1] + qb.build(DCID, b"", fr, version=0x6b3343cf)[1:]) is None, "v2 的包套上 v1 的类型位：不是 v1 的 Initial，None")

f = qb.crypto_frame(0, HELLO2[:50])
ack = b"\x02\x05\x00\x01\x03\x01\x02"
ecn = b"\x03\x05\x00\x00\x03\x01\x02\x03"
r = quic.parse_initial(qb.build(DCID, b"", b"\x01" + ack + ecn + f + b"\x00\x00", pad_to=0))
check(r["frames"] == ["ping", "ack", "ack", "crypto", "padding"] and r["crypto"] == [(0, HELLO2[:50])] and not r["truncated"], "PING、ACK（带额外区间）、带 ECN 计数的 ACK、CRYPTO、PADDING 依次解出，CRYPTO 内容不受前面帧的长度影响")
r = quic.parse_initial(qb.build(DCID, b"", f + b"\x1e\x00" + qb.crypto_frame(50, HELLO2[50:]), pad_to=0))
check(r["truncated"] and r["crypto"] == [(0, HELLO2[:50])], "Initial 里不该有的帧（0x1e HANDSHAKE_DONE）：停下来标 truncated，前面的 CRYPTO 保留")
r = quic.parse_initial(qb.build(DCID, b"", f[:-1], pad_to=0))
check(r["truncated"] and r["crypto"] == [], "CRYPTO 帧的长度超出包：truncated，不收这一帧")
check(quic.parse_frames(b"\x02\x05")["truncated"] and quic.parse_frames(b"\x06\x00")["truncated"], "ACK / CRYPTO 在字段中间被截断：truncated")

print("== 合并的包、多个包拼 ClientHello ==")
big = qb.client_hello("a.very.long.example.com", extra=1500)
p1 = qb.build(DCID, b"", qb.crypto_frame(0, big[:700]), pn=0)
p2 = qb.build(DCID, b"", qb.crypto_frame(700, big[700:1400]), pn=1)
p3 = qb.build(DCID, b"", qb.crypto_frame(1400, big[1400:]), pn=2)
check(quic.client_hello(big[:700]) is None and quic.client_hello(big) == big and quic.client_hello(b"\x02" + big[1:]) is None and quic.client_hello(b"") is None, "ClientHello 不完整 / 类型不对 / 空：None")
got = quic.collect([p1, p2, p3])
check(list(got) == [DCID] and got[DCID]["client_hello"] == big and got[DCID]["packets"] == 3 and got[DCID]["version"] == 1, "3 个包的 CRYPTO 按偏移拼成完整的 ClientHello")
check(quic.collect([p3, p1, p2])[DCID]["client_hello"] == big, "乱序到达一样")
got = quic.collect([p1, p3])
check(got[DCID]["client_hello"] is None and got[DCID]["stream"] == big[:700], "缺中间一段：流停在缺口前，ClientHello 不完整")
check(quic.collect([p1, p1, p2, p3])[DCID]["client_hello"] == big, "重传的包（相同偏移）不影响")
ov = quic.crypto_stream([(0, b"abcdef"), (3, b"defghi"), (2, b"cde")])
check(ov == b"abcdefghi" and quic.crypto_stream([(5, b"x")]) == b"" and quic.crypto_stream([]) == b"", "重叠的片段只取新的部分；不从 0 开始 / 空 -> 空")
d2 = qb.build(b"\x07" * 8, b"", qb.crypto_frame(0, HELLO2), pad_to=0)
co = quic.parse_datagram(p1 + d2)
check(len(co) == 2 and co[0]["dcid"] == DCID and co[1]["dcid"] == b"\x07" * 8 and co[1]["rest"] == b"", "一个数据报里合并了两个 Initial：都解出，按各自的连接 ID")
co = quic.parse_datagram(p1 + b"\x40\x01\x02\x03")
check(len(co) == 1 and co[0]["rest"] == b"\x40\x01\x02\x03", "后面合并的不是 Initial（短包头）：只收前面的，rest 原样保留")
two = quic.collect([p1 + d2])
check(sorted(two) == sorted([DCID, b"\x07" * 8]), "collect 对合并的数据报分别记账")

print("== 不是 Initial / 坏输入 ==")
good = qb.build(DCID, b"", fr)
bad = bytearray(good)
bad[600] ^= 1
check(quic.parse_initial(bytes(bad)) is None, "密文改一位：认证失败，None")
bad = bytearray(good)
bad[-1] ^= 1
check(quic.parse_initial(bytes(bad)) is None, "tag 改一位：None")
bad = bytearray(good)
bad[10] ^= 1
check(quic.parse_initial(bytes(bad)) is None, "连接 ID 改一位：密钥变了，None")
bad = bytearray(good)
bad[0] ^= 0x10
check(quic.parse_initial(bytes(bad)) is None, "类型位变成 Handshake / 0-RTT：不是 Initial，None")
bad = bytearray(good)
bad[0] &= 0xBF
check(quic.parse_initial(bytes(bad)) is None, "固定位清零：None")
check(quic.parse_initial(good[:1] + b"\x00\x00\x00\x00" + good[5:]) is None and quic.parse_initial(good[:1] + b"\xff\x00\x00\x1d" + good[5:]) is None, "版本协商（0）/ 草案版本：不认识，None")
check(quic.parse_initial(b"\x40" + good[1:]) is None and quic.parse_initial(b"") is None and quic.parse_initial(None) is None, "短包头 / 空 / None：None")
check(quic.parse_initial(good[:40]) is None and quic.parse_initial(good[:-1]) is None, "被截断的包：None")
cid = bytearray(good)
cid[5] = 21
check(quic.parse_initial(bytes(cid)) is None, "连接 ID 长度 21（上限 20）：None")
cid = bytearray(good)
cid[14] = 21
check(quic.parse_initial(bytes(cid)) is None, "SCID 长度 21：None")
ok = True
for i in range(len(good)):                                                        # 每个长度的前缀、每个字节取反都不抛异常
    for g in (good[:i], good[:i] + bytes([good[i] ^ 0xFF]) + good[i + 1:] if i < len(good) else good):
        try:
            quic.parse_initial(g)
            quic.parse_datagram(g)
        except Exception:
            ok = False
check(ok, "把包截成每一种长度、每个字节取反：都不抛异常")
check(quic.varint(b"\x25", 0) == (37, 1) and quic.varint(b"\x7b\xbd", 0) == (15293, 2) and quic.varint(b"\x9d\x7f\x3e\x7d", 0) == (494878333, 4)
      and quic.varint(b"\xc2\x19\x7c\x5e\xff\x14\xe8\x8c", 0) == (151288809941952652, 8), "可变长整数：RFC 9000 附录 A.1 的四个例子（37、15293、494878333、151288809941952652）")

print("== 认证通过、但头不合规 ==")
ok_pkt = qb.build(DCID, b"", fr)
check(quic.parse_initial(qb.build(DCID, b"", fr, first_xor=0x40)) is None and quic.parse_initial(qb.build(DCID, b"", fr, first_xor=0x80)) is None, "固定位 / 长包头位被翻过（头也参与认证，所以 GCM 能通过）：仍然 None")
check(quic.parse_initial(qb.build(DCID, b"", fr, first_xor=0x20)) is None and quic.parse_initial(qb.build(DCID, b"", fr, first_xor=0x10)) is None, "包类型是 Handshake / 0-RTT（用 Initial 的密钥加密也不算）：None")
check(quic.parse_initial(qb.build(b"\x01" * 21, b"", fr)) is None and quic.parse_initial(qb.build(DCID, b"\x01" * 21, fr)) is None, "DCID / SCID 21 字节（上限 20）：None")
check(quic.parse_initial(qb.build(b"\x01" * 20, b"\x02" * 20, fr)) is not None, "20 字节的 DCID / SCID 是允许的")
e = quic.parse_initial(qb.build(DCID, b"", b"", pad_to=0, pn_len=4))
check(e is not None and e["frames"] == [] and e["crypto"] == [], "载荷为空的最短合法包（包号 4 字节 + 16 字节 tag = 20）：解得出，没有帧")
check(quic.client_hello(big[:-1]) is None and quic.client_hello(big + b"xx") == big, "ClientHello 少最后一个字节：None；多出来的字节不算它的")
try:
    quic.varint(b"\x80\x00", 0)
    short = False
except IndexError:
    short = True
check(short, "可变长整数的字节数不够：抛 IndexError（不是悄悄按短数据算出别的值）")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
