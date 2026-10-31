# -*- coding: utf-8 -*-
"""
802.11 数据帧解密（先做 CCMP / GCMP 的单播数据帧；TKIP、WEP、组播、管理帧后续逐个加）。纯标准库。

CCMP / GCMP 帧体 = 8 字节头 ‖ 密文 ‖ MIC（CCMP-128 8 字节，CCMP-256 与 GCMP 16 字节）
  头：PN0 PN1 保留 (ExtIV | 密钥序号<<6) PN2 PN3 PN4 PN5
  nonce（CCMP，13 字节）：优先级(1) ‖ A2(6) ‖ PN(6，高位在前)；GCMP 的 IV（12 字节）：A2 ‖ PN（高位在前）
  AAD：帧控制（子类型高 3 位、重试、省电、更多数据清零；受保护位保留）‖ A1 ‖ A2 ‖ A3 ‖ 序号控制（只留分片号）‖ [A4] ‖ [QoS 控制，只留 TID]
"""
import struct

import crypto80211 as c

MIC_LEN = {"CCMP-128": 8, "CCMP-256": 16, "GCMP-128": 16, "GCMP-256": 16}


def _mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def pn_of(body):
    """CCMP / GCMP 头里的 48 位 PN，以及密钥序号、ExtIV 位。"""
    pn = body[0] | body[1] << 8 | body[4] << 16 | body[5] << 24 | body[6] << 32 | body[7] << 40
    return pn, body[3] >> 6, bool(body[3] & 0x20)


def aad_of(dot11, h):
    """从完整的 802.11 帧算 AAD（见模块说明）。"""
    fc = bytearray(dot11[:2])
    fc[0] &= 0x8F                      # 子类型的 b4-b6
    fc[1] &= ~(0x08 | 0x10 | 0x20) & 0xFF   # 重试、省电、更多数据
    if h["qos"] is not None:
        fc[1] &= ~0x80 & 0xFF          # 顺序位（QoS 数据帧里表示带 HT 控制）
    sc = struct.pack("<H", struct.unpack("<H", dot11[22:24])[0] & 0x000F)
    aad = bytes(fc) + dot11[4:22] + sc
    if h["addr4"] is not None:
        aad += dot11[24:30]
    if h["qos"] is not None:
        off = 30 if h["addr4"] is not None else 24
        aad += struct.pack("<H", struct.unpack("<H", dot11[off:off + 2])[0] & 0x000F)
    return aad


def decrypt_aead(tk, cipher, frame):
    """解一个 CCMP / GCMP 帧。返回 (明文, MIC 是否通过, PN)；明文从 LLC 开始。"""
    h, body = frame.h, frame.body
    mic = MIC_LEN[cipher]
    if len(body) < 8 + mic:
        raise ValueError("帧体太短")
    pn, _key_id, _ext = pn_of(body)
    a2 = _mac(h["addr2"])
    aad = aad_of(frame.dot11, h)
    if cipher.startswith("CCMP"):
        prio = h["qos"]["tid"] if h["qos"] is not None else 0
        nonce = bytes([prio]) + a2 + pn.to_bytes(6, "big")
        pt, ok = c.ccm_decrypt(tk, nonce, aad, body[8:], mic)
    else:
        pt, ok = c.gcm_decrypt(tk, a2 + pn.to_bytes(6, "big"), aad, body[8:], mic)
    return pt, ok, pn
