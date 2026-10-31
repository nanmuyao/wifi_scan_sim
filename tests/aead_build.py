# -*- coding: utf-8 -*-
"""测试用的 CCMP / GCMP 帧构造：用 pycryptodome 当独立加密方，AAD 在这里按标准手写（不借用被测代码）。"""
import os
import struct
import sys

from Crypto.Cipher import AES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import decrypt80211 as dec  # noqa: E402
import frames80211 as fr  # noqa: E402
import wifi_frame_parser as w  # noqa: E402

A1, A2, A3, A4 = (bytes([i] * 6) for i in (0x11, 0x22, 0x33, 0x44))
MAC = lambda b: ":".join("%02x" % x for x in b)  # noqa: E731


def build(cipher, tk, pn, plain, *, a1=None, qos=None, to_ds=1, from_ds=0, four=False, htc=False, flags=0, seq=0x0123, frag=0, key_id=0, subtype=None, mgmt=False, mld=None):
    """返回完整 802.11 帧。flags：重试 0x08 / 省电 0x10 / 更多数据 0x20（这些位 AAD 里是 0，加密时不算）。
    AAD 按标准手写：帧控制第 2 字节只留 ToDS / FromDS / 更多分片 / 受保护（0x47），第 1 字节只留 0x8F。"""
    a1 = a1 or A1
    if mgmt:
        # 管理帧（如 PMF 的解除认证）：类型 0；帧控制第 1 字节整个进 AAD；CCMP nonce 的标志是 0x10；没有 QoS / 第四地址
        fc0 = (12 if subtype is None else subtype) << 4
        hdr = bytes([fc0, 0x40 | flags]) + struct.pack("<H", 0) + a1 + A2 + A3 + struct.pack("<H", seq << 4 | frag)
        aad = bytes([fc0, 0x40]) + a1 + A2 + A3 + struct.pack("<H", frag)
        ph = bytes([pn & 0xFF, (pn >> 8) & 0xFF, 0, 0x20 | key_id << 6]) + (pn >> 16).to_bytes(4, "little")
        if cipher.startswith("CCMP"):
            c = AES.new(tk, AES.MODE_CCM, nonce=bytes([0x10]) + A2 + pn.to_bytes(6, "big"), mac_len=dec.MIC_LEN[cipher], msg_len=len(plain))
        else:
            c = AES.new(tk, AES.MODE_GCM, nonce=A2 + pn.to_bytes(6, "big"), mac_len=16)
        c.update(aad)
        ct, tag = c.encrypt_and_digest(plain)
        return hdr + ph + ct + tag
    if subtype is None:
        subtype = 8 if qos is not None else 0
    fc0 = 0x08 | subtype << 4
    ds = to_ds | from_ds << 1
    fc1 = ds | 0x40 | flags | (0x80 if htc else 0)
    hdr = bytes([fc0, fc1]) + struct.pack("<H", 0) + a1 + A2 + A3 + struct.pack("<H", seq << 4 | frag)
    L = (lambda a: mld.get(a, a)) if mld else (lambda a: a)         # mld：{链路地址: MLD 地址}：AAD 和 nonce 里用 MLD 地址，帧头里仍是链路地址
    aad = bytes([fc0 & 0x8F, (ds | 0x40)]) + L(a1) + L(A2) + L(A3) + struct.pack("<H", frag)
    if four:
        hdr = bytes([fc0, fc1 | 0x03]) + hdr[2:] + A4
        aad = bytes([fc0 & 0x8F, 0x03 | 0x40]) + L(a1) + L(A2) + L(A3) + struct.pack("<H", frag) + L(A4)
    if qos is not None:
        hdr += struct.pack("<H", qos)
        aad += struct.pack("<H", qos & 0x000F)
    if htc:
        hdr += b"\x01\x02\x03\x04"
    ph = bytes([pn & 0xFF, (pn >> 8) & 0xFF, 0, 0x20 | key_id << 6]) + (pn >> 16).to_bytes(4, "little")
    if cipher.startswith("CCMP"):
        tid = (qos or 0) & 0x0F
        nonce = bytes([tid]) + L(A2) + pn.to_bytes(6, "big")
        c = AES.new(tk, AES.MODE_CCM, nonce=nonce, mac_len=dec.MIC_LEN[cipher], msg_len=len(plain))
    else:
        c = AES.new(tk, AES.MODE_GCM, nonce=L(A2) + pn.to_bytes(6, "big"), mac_len=16)
    c.update(aad)
    ct, tag = c.encrypt_and_digest(plain)
    return hdr + ph + ct + tag


def frame(dot11):
    h = w.parse_mac_header(dot11)
    return fr.Frame(1, 0.0, dot11, h, dot11[h["header_len"]:], None)


