#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""decrypt80211 的 CCMP / GCMP：用 pycryptodome 当独立加密方（AAD 在这里手写一遍，不借用被测代码），
覆盖真实样例里没有的帧形态（非 QoS、四地址、带 HT 控制、各种会被屏蔽的位）。真实帧的对照在 tests/oracle/test_decrypt_diff.py。"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import decrypt80211 as dec  # noqa: E402
import wifi_frame_parser as w  # noqa: E402
from aead_build import A1, A2, A3, A4, build, frame  # noqa: E402,F401

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


PLAIN = b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + bytes(range(40))
TK16, TK32 = bytes(range(16)), bytes(range(32))
CASES = [
    ("CCMP-128", TK16, "非 QoS 三地址", dict()),
    ("CCMP-128", TK16, "QoS（TID 5）", dict(qos=0x0005)),
    ("CCMP-128", TK16, "QoS 控制里 TID 以外的位被屏蔽（EOSP / 确认策略 / A-MSDU）", dict(qos=0x00F5 | 0x0100)),
    ("CCMP-128", TK16, "重试 / 省电 / 更多数据位被屏蔽", dict(qos=0x0003, flags=0x38)),
    ("CCMP-128", TK16, "序号被屏蔽、分片号保留", dict(qos=0x0000, seq=0x0FFF, frag=3)),
    ("CCMP-128", TK16, "四地址 QoS", dict(qos=0x0002, four=True)),
    ("CCMP-128", TK16, "带 HT 控制（顺序位）", dict(qos=0x0001, htc=True)),
    ("CCMP-128", TK16, "子类型 10（QoS 数据 + CF-Poll 类，子类型低位被屏蔽）", dict(qos=0x0000, subtype=10)),
    ("CCMP-128", TK16, "密钥序号 1", dict(qos=0x0000, key_id=1)),
    ("CCMP-256", TK32, "CCMP-256（MIC 16 字节）", dict(qos=0x0006)),
    ("GCMP-128", TK16, "GCMP-128", dict(qos=0x0000)),
    ("GCMP-256", TK32, "GCMP-256 四地址", dict(qos=0x0007, four=True)),
]
PN = 0x0000A1B2C3D4E5F6 & 0xFFFFFFFFFFFF
for cipher, tk, what, kw in CASES:
    print("== %s：%s ==" % (cipher, what))
    f = frame(build(cipher, tk, PN, PLAIN, **kw))
    pt, ok, pn = dec.decrypt_aead(tk, cipher, f)
    check(ok and pt == PLAIN and pn == PN, "MIC 通过、明文还原、PN = %#x" % PN)
    check(not dec.decrypt_aead(bytes(len(tk)), cipher, f)[1], "错的密钥 MIC 不通过")

print("== 会改变 AAD / nonce 的位必须让 MIC 失败 ==")
base = build("CCMP-128", TK16, PN, PLAIN, qos=0x0005)
hl = w.parse_mac_header(base)["header_len"]


def mutated(off, xor):
    b = bytearray(base)
    b[off] ^= xor
    return frame(bytes(b))


check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(4, 0x01))[1], "地址 1 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(10, 0x01))[1], "地址 2 变了（nonce 和 AAD）")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(16, 0x01))[1], "地址 3 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(22, 0x01))[1], "分片号变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(24, 0x01))[1], "QoS 的 TID 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(1, 0x04))[1], "更多分片位变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(1, 0x02))[1], "FromDS 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(hl, 0x01))[1], "PN0 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(hl + 7, 0x01))[1], "PN5 变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(len(base) - 1, 0x01))[1], "MIC 末字节变了")
check(not dec.decrypt_aead(TK16, "CCMP-128", mutated(hl + 9, 0x01))[1], "密文变了")

print("== 受保护的单播管理帧（PMF）==")
MPL = bytes([7, 0])                       # 解除认证的原因码
for cipher, tk, sub in (("CCMP-128", TK16, 12), ("CCMP-128", TK16, 10), ("CCMP-256", TK32, 12), ("GCMP-128", TK16, 13), ("GCMP-256", TK32, 12)):
    f = frame(build(cipher, tk, PN, MPL, mgmt=True, subtype=sub, a1=A1))
    pt, ok, pn = dec.decrypt_aead(tk, cipher, f)
    check(ok and pt == MPL and pn == PN and f.h["type"] == 0, "%s 管理帧子类型 %d：MIC 通过、明文还原" % (cipher, sub))
base_m = build("CCMP-128", TK16, PN, MPL, mgmt=True)
def mut_m(off, xor):
    b = bytearray(base_m)
    b[off] ^= xor
    return frame(bytes(b))
check(not dec.decrypt_aead(TK16, "CCMP-128", mut_m(0, 0x10))[1], "管理帧的子类型位变了：AAD 里整个保留，MIC 失败（数据帧才屏蔽 b4-b6）")
check(dec.decrypt_aead(TK16, "CCMP-128", mut_m(1, 0x08 | 0x10 | 0x20))[1], "重试 / 省电 / 更多数据位被屏蔽，MIC 仍通过")
check(not dec.decrypt_aead(TK16, "CCMP-128", mut_m(10, 0x01))[1], "地址 2 变了")
check(dec.decrypt_frame([], frame(base_m)) is None, "decrypt_frame 没有握手：None")

print("== WEP（独立加密：ARC4 + zlib.crc32）==")
import struct as _st  # noqa: E402
import zlib  # noqa: E402
from Crypto.Cipher import ARC4  # noqa: E402

WK5, WK13 = bytes.fromhex("1234567890"), bytes(range(1, 14))


def wep_frame(key, data, typ=2, iv=b"\x01\x02\x03", key_id=0, ext=False):
    enc = ARC4.new(iv + key).encrypt(data + _st.pack("<I", zlib.crc32(data)))
    body = iv + bytes([key_id << 6 | (0x20 if ext else 0)]) + enc
    fc0 = 0x08 if typ == 2 else 0xB0                  # 数据帧 / 认证帧（管理，子类型 11）
    d = bytes([fc0, 0x41 if typ == 2 else 0x40, 0, 0]) + A1 + A2 + A3 + b"\x00\x10" + body
    return frame(d)


wf = wep_frame(WK5, PLAIN)
check(dec.decrypt_wep([WK5], wf) == (PLAIN, WK5), "数据帧：ARC4(IV ‖ 密钥)，ICV 通过")
check(dec.decrypt_wep([WK13, WK5], wf) == (PLAIN, WK5), "密钥表里有多把：ICV 通过的那把")
check(dec.decrypt_wep([WK13], wf) is None and dec.decrypt_wep([], wf) is None, "密钥不对 / 没有密钥：None")
auth = wep_frame(WK13, b"\x01\x00\x03\x00" + bytes(20), typ=0, key_id=2)
check(dec.decrypt_wep([WK13], auth) is not None and auth.h["type"] == 0, "共享密钥认证第 3 帧（管理帧）也是 WEP，密钥序号 2 照样解")
check(dec.decrypt_wep([WK5], wep_frame(WK5, PLAIN, ext=True)) is None, "ExtIV 位置位的是 TKIP / CCMP，不是 WEP：None")
check(dec.decrypt_wep([WK5], frame(wf.dot11[:1] + bytes([wf.dot11[1] & ~0x40]) + wf.dot11[2:])) is None, "受保护位没置：None")
check(dec.wep_keys([("wep", "1234567890"), ("wep", "zz"), ("wep", "0102"), ("wpa-psk", "1234567890"), ("wep", "00" * 13), ("wep", "00" * 16)]) == [WK5, bytes(13), bytes(16)],
      "wep_keys：只收十六进制、5 / 13 / 16 字节的")

print("== TKIP：Michael 的密钥方向、DA / SA、优先级、分片 ==")
import struct  # noqa: E402
import crypto80211 as c  # noqa: E402
import frames80211 as fr  # noqa: E402

TKT = bytes(range(32))
MK_AP, MK_STA = TKT[16:24], TKT[24:32]
BSS, STA_, DST, SRC = bytes([2, 0, 0, 0, 0, 1]), bytes([2, 0, 0, 0, 0, 2]), bytes([2, 0, 0, 0, 0, 3]), bytes([2, 0, 0, 0, 0, 4])
MSDU = b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + bytes(range(30))


def tkip_frame(*, to_ds, qos=None, frag=0, more_frag=False, key=TKT, mic_key=None, mic_input=None, tsc=0x0000_1234_5678):
    """独立构造：TKIP 帧。ToDS：A1 = BSSID、A2 = SA、A3 = DA；FromDS：A1 = DA、A2 = BSSID、A3 = SA。"""
    if to_ds:
        a1, a2, a3, da, sa = BSS, STA_, DST, DST, STA_
    else:
        a1, a2, a3, da, sa = DST, BSS, SRC, DST, SRC
    mk = mic_key or (MK_STA if to_ds else MK_AP)
    prio = (qos or 0) & 0x0F
    mic = c.michael(mk, mic_input if mic_input is not None else da + sa + bytes([prio, 0, 0, 0]) + MSDU)
    fc0 = 0x08 | (8 << 4 if qos is not None else 0)
    fc1 = (0x01 if to_ds else 0x02) | 0x40 | (0x04 if more_frag else 0)
    hdr = bytes([fc0, fc1, 0, 0]) + a1 + a2 + a3 + struct.pack("<H", 0x0100 << 4 & 0xFFF0 | frag)
    if qos is not None:
        hdr += struct.pack("<H", qos)
    d = hdr + c.tkip_encrypt(key[:16], a2, tsc, 0, MSDU + mic)
    return fr.Frame(1, 0.0, d, w.parse_mac_header(d), d[len(hdr):], None)


for to_ds in (True, False):
    f = tkip_frame(to_ds=to_ds, qos=0x0003)
    msdu, icv, mic, tsc = dec.decrypt_tkip(TKT, f)
    check(msdu == MSDU and icv and mic is True and tsc == 0x12345678, "%s：MSDU 还原、ICV 和 Michael 通过、TSC" % ("ToDS（STA 发出）用 tk[24:32]" if to_ds else "FromDS（AP 发出）用 tk[16:24]"))
    check(dec.decrypt_any("TKIP", TKT, f) == (MSDU, True), "decrypt_any 把 TKIP 当整体判断")
    check(dec.decrypt_tkip(TKT, tkip_frame(to_ds=to_ds, qos=0x0003, mic_key=MK_AP if to_ds else MK_STA))[2] is False, "Michael 密钥方向反了：失败")
check(dec.decrypt_tkip(TKT, tkip_frame(to_ds=True, qos=0x0005))[2] is True and dec.decrypt_tkip(TKT, tkip_frame(to_ds=True))[2] is True, "优先级取 QoS 的 TID；非 QoS 为 0")
bad_prio = tkip_frame(to_ds=True, qos=0x0005, mic_input=DST + STA_ + bytes([0, 0, 0, 0]) + MSDU)
check(dec.decrypt_tkip(TKT, bad_prio)[2] is False, "Michael 输入里的优先级不是 TID：失败")
swapped = tkip_frame(to_ds=False, qos=0x0000, mic_input=SRC + DST + bytes(4) + MSDU)
check(dec.decrypt_tkip(TKT, swapped)[2] is False, "DA 和 SA 颠倒：失败")
frag = tkip_frame(to_ds=True, qos=0x0000, more_frag=True, mic_key=bytes(8))
check(dec.decrypt_tkip(TKT, frag)[2] is None and dec.decrypt_any("TKIP", TKT, frag)[1], "分片帧：Michael 要重组后才能校验，返回 None，整体只看 ICV")
check(dec.decrypt_tkip(TKT, tkip_frame(to_ds=True, qos=0x0000, frag=2, mic_key=bytes(8)))[2] is None, "分片号非 0 的帧同样不校验 Michael")
ok_f = tkip_frame(to_ds=True, qos=0x0000)
wrong = dec.decrypt_tkip(bytes(range(1, 33)), ok_f)
check(not wrong[1] and dec.decrypt_any("TKIP", bytes(range(1, 33)), ok_f)[1] is False, "错的 TEK：ICV 不通过")
check(dec.decrypt_any("TKIP", TKT[:16] + bytes(16), ok_f)[1] is False, "TEK 对但 Michael 密钥错：整体失败")
for bad_len in (16, 31, 33):
    try:
        dec.decrypt_any("TKIP", bytes(bad_len), ok_f)
        check(False, "TKIP 密钥 %d 字节应当报错" % bad_len)
    except ValueError:
        check(True, "TKIP 密钥 %d 字节：ValueError" % bad_len)
try:
    dec.decrypt_any("TKIP", TKT, fr.Frame(1, 0.0, ok_f.dot11[:30] + bytes(10), ok_f.h, bytes(10), None))
    check(False, "帧体太短应当报错")
except ValueError:
    check(True, "帧体太短：ValueError")

print("== pn_of ==")
check(dec.pn_of(bytes([1, 2, 0, 0x20, 3, 4, 5, 6])) == (0x060504030201, 0, True), "PN0 PN1 在前、PN2-PN5 在后，ExtIV 位")
check(dec.pn_of(bytes([0, 0, 0, 0xE0, 0, 0, 0, 0]))[1] == 3, "密钥序号取最高 2 位")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
