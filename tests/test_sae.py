#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sae80211：SAE 认证帧结构、曲线检查。曲线常量与 pycryptodome 交叉核对，合法点用 pycryptodome 生成（标量 × 生成元），真实抓包见 tests/oracle/test_sae_diff.py。"""
import os
import struct
import sys

from Crypto.PublicKey import ECC

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import ie  # noqa: E402
import sae80211 as sae  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


CURVE = {19: "NIST P-256", 20: "NIST P-384", 21: "NIST P-521"}
print("== 曲线常量（对照 pycryptodome 的 NIST 曲线表）==")
for grp, nm in CURVE.items():
    c = ECC._curves[nm]
    name, p, b, n, size, hname = sae.GROUPS[grp]
    check((p, b, n) == (int(c.p), int(c.b), int(c.order)) and size == (int(c.p).bit_length() + 7) // 8, "组 %d（%s）：p、b、阶 n、坐标字节数" % (grp, name))
    pt = c.G
    check(sae.on_curve(grp, int(pt.x), int(pt.y)) is True and sae.x_on_curve(grp, int(pt.x)) is True, "组 %d：生成元在曲线上" % grp)

print("== 点的检查 ==")


def point(grp, k):
    c = ECC._curves[CURVE[grp]]
    pt = c.G * k
    return int(pt.x), int(pt.y)


for grp in CURVE:
    x, y = point(grp, 123456789 + grp)
    p = sae.GROUPS[grp][1]
    check(sae.on_curve(grp, x, y) is True, "组 %d：k·G 在曲线上" % grp)
    check(sae.on_curve(grp, x, (y + 1) % p) is False and sae.on_curve(grp, (x + 1) % p, y) is False, "组 %d：改动 y 或 x 之后不在曲线上" % grp)
    check(sae.on_curve(grp, x + p, y) is False and sae.on_curve(grp, x, y + p) is False, "组 %d：坐标 >= p 不接受（同余也不行）" % grp)
    check(sae.x_on_curve(grp, x) is True and sae.x_on_curve(grp, p) is False and sae.x_on_curve(grp, -1) is False, "组 %d：x 有对应点；x >= p 或为负不接受" % grp)
    bad = next(v for v in range(2, 200) if not sae.x_on_curve(grp, v))
    check(sae.on_curve(grp, bad, 0) is False and sae.x_on_curve(grp, bad) is False, "组 %d：找到一个没有对应点的 x（%d）：x_on_curve 为假" % (grp, bad))
    n = sae.GROUPS[grp][3]
    check((sae.scalar_valid(grp, 1), sae.scalar_valid(grp, n - 1), sae.scalar_valid(grp, 0), sae.scalar_valid(grp, n), sae.scalar_valid(grp, n + 1)) == (True, True, False, False, False), "组 %d：标量范围 [1, n-1]" % grp)
check(sae.on_curve(25, 1, 1) is None and sae.x_on_curve(25, 1) is None and sae.scalar_valid(25, 1) is None, "不认识的组：None（既不说合法也不说不合法）")
check(sae.x_on_curve(19, int(ECC._curves["NIST P-256"].G.x)) is True, "x_on_curve 对 y^2 恰好为 0 之外的情形：生成元")

print("== 认证帧解析 ==")
HDR = lambda seq, status: struct.pack("<HHH", 3, seq, status)         # noqa: E731


def commit(grp, k=7, status=0, extra=b"", scalar=None, token=b""):
    x, y = point(grp, k)
    size = sae.GROUPS[grp][4]
    s = (k + 5).to_bytes(size, "big") if scalar is None else scalar
    return HDR(1, status) + struct.pack("<H", grp) + token + s + x.to_bytes(size, "big") + y.to_bytes(size, "big") + extra, s, x.to_bytes(size, "big") + y.to_bytes(size, "big")


for grp in CURVE:
    body, s, el = commit(grp)
    r = sae.parse_auth(body)
    check((r["type"], r["status"], r["group"], r["scalar"], r["element"], r["extra"], r["token"]) == ("commit", 0, grp, s, el, b"", None), "组 %d commit：状态、组、标量、元素的位置和长度" % grp)
    check(r["scalar_ok"] is True and r["on_curve"] is True, "组 %d commit：合法" % grp)
    body, s, el = commit(grp, status=126, extra=b"\xff\x03\x5c\x13\x00")
    r = sae.parse_auth(body)
    check(r["status"] == 126 and r["scalar"] == s and r["element"] == el and r["extra"] == b"\xff\x03\x5c\x13\x00", "组 %d H2E commit（状态 126）：后面的元素放 extra" % grp)
    size = sae.GROUPS[grp][4]
    r = sae.parse_auth(commit(grp, scalar=bytes(size))[0])
    check(r["scalar_ok"] is False and r["on_curve"] is True, "组 %d：标量为 0：scalar_ok 为假" % grp)
    r = sae.parse_auth(commit(grp, scalar=sae.GROUPS[grp][3].to_bytes(size, "big"))[0])
    check(r["scalar_ok"] is False, "组 %d：标量 = n：不合法" % grp)
    body, s, el = commit(grp)
    tampered = body[:-1] + bytes([body[-1] ^ 1])
    check(sae.parse_auth(tampered)["on_curve"] is False, "组 %d：元素 y 末字节变了：不在曲线上" % grp)
    check(sae.parse_auth(body[:-1]) == dict(sae.parse_auth(body[:-1])) and sae.parse_auth(body[:-1])["scalar"] is None and sae.parse_auth(body[:-1])["on_curve"] is None, "组 %d：数据不够长：不切标量 / 元素，放 extra" % grp)

r = sae.parse_auth(HDR(1, 76) + struct.pack("<H", 19) + b"TOKEN123")
check((r["status"], r["group"], r["token"], r["scalar"]) == (76, 19, b"TOKEN123", None), "状态 76：要求反阻塞令牌：组 + 令牌")
r = sae.parse_auth(HDR(1, 77) + struct.pack("<H", 22) + b"zz")
check((r["status"], r["group"], r["scalar"], r["extra"]) == (77, 22, None, b"zz"), "状态 77 / 不认识的组：没有标量和元素，余下放 extra")
body19 = commit(19)[0]
r = sae.parse_auth(body19[:4] + struct.pack("<H", 77) + body19[6:])
check(r["status"] == 77 and r["group"] == 19 and r["scalar"] is None and r["on_curve"] is None and len(r["extra"]) == 96, "状态 77 但组认识、字节也够：不按 commit 切（失败响应里没有标量和元素）")
r = sae.parse_auth(HDR(1, 0) + struct.pack("<H", 22) + bytes(100))
check(r["scalar"] is None and r["on_curve"] is None and len(r["extra"]) == 100, "成功状态但组不认识：不乱切")
r = sae.parse_auth(HDR(1, 0))
check(r["group"] is None and r["scalar"] is None, "commit 缺组字段：不崩溃")
check(sae.parse_auth(HDR(1, 0)[:5]) is None and sae.parse_auth(b"") is None, "短于 6 字节：None")
check(sae.parse_auth(struct.pack("<HHH", 0, 1, 0) + bytes(80)) is None, "不是 SAE（算法 0）：None")
check(sae.parse_auth(struct.pack("<HHH", 3, 3, 0) + bytes(80)) is None and sae.parse_auth(struct.pack("<HHH", 3, 0, 0) + bytes(80)) is None, "序号不是 1 / 2：None")

print("== confirm ==")
for grp, hl in ((19, 32), (20, 48), (21, 64)):
    conf = bytes(range(hl))
    r = sae.parse_auth(HDR(2, 0) + struct.pack("<H", 5) + conf + b"tail", grp)
    check((r["type"], r["send_confirm"], r["confirm"], r["extra"]) == ("confirm", 5, conf, b"tail"), "组 %d confirm：send-confirm 2 字节、哈希 %d 字节，余下放 extra" % (grp, hl))
    check(sae.parse_auth(HDR(2, 0) + struct.pack("<H", 5) + conf[:-1], grp) is None, "组 %d confirm：比哈希短一字节：None" % grp)
r = sae.parse_auth(HDR(2, 0) + struct.pack("<H", 0xFFFF) + bytes(32))
check(r["send_confirm"] == 0xFFFF and r["confirm"] == bytes(32) and r["extra"] == b"", "没给组：整段当 confirm；send-confirm 0xFFFF 原样")
check(sae.parse_auth(HDR(2, 0) + b"\x01") is None, "confirm 缺 send-confirm：None")

print("== OWE 的 DH 参数元素 ==")
d = ie.decode_owe_dh(struct.pack("<H", 19) + bytes(range(32)))
check(d == {"group": 19, "public": bytes(range(32))}, "组（小端）和公钥")
check(ie.decode_owe_dh(b"\x13") is None and ie.decode_owe_dh(b"")  is None and ie.decode_owe_dh(b"\x14\x00") == {"group": 20, "public": b""}, "不足 2 字节：None；只有组：公钥为空")
els, _ = ie.walk(bytes([255, 1 + 2 + 32, 32]) + struct.pack("<H", 19) + bytes(32))
check(ie.decode_all(els)["owe_dh"]["group"] == 19, "decode_all 认扩展元素 32")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
