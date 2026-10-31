# -*- coding: utf-8 -*-
"""
EAPOL-Key 帧（四次握手和组密钥握手）的解析。纯标准库。

EAPOL 头 4 字节：版本、类型（3 = Key）、长度（大端，不含这 4 字节）。
Key 描述符：描述符类型(1：2 = RSN，254 = WPA1)、Key Info(2)、Key Length(2)、Replay Counter(8)、Key Nonce(32)、Key IV(16)、
Key RSC(8)、Key ID(8)、Key MIC(MIC 长度)、Key Data Length(2)、Key Data。**所有多字节字段都是大端。**

Key Info（大端 16 位）：bit0-2 描述符版本（1 = HMAC-MD5 + RC4，2 = HMAC-SHA1 + AES，3 = AES-CMAC + AES，0 = 由 AKM 决定），
bit3 密钥类型（1 = 成对），bit4-5 密钥序号，bit6 Install，bit7 Key Ack，bit8 Key MIC，bit9 Secure，bit10 Error，bit11 Request，
bit12 Key Data 已加密，bit13 SMK 消息。

MIC 长度取决于认证方式：16（多数），24（HMAC-SHA-384，Suite-B 192 等），32（HMAC-SHA-512）。不先知道 AKM 也能推出来：
长度字段 = 固定部分 + MIC 长度 + 2 + Key Data 长度，三种 MIC 长度里只有一种让 Key Data Length 字段与实际长度吻合。
"""
import struct

EAPOL_KEY = 3
FIXED = 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8            # 描述符类型 … Key ID（不含 MIC 和 Key Data Length）
MIC_LENGTHS = (16, 24, 32)

KI_VERSION, KI_PAIRWISE, KI_INSTALL, KI_ACK, KI_MIC, KI_SECURE = 0x0007, 0x0008, 0x0040, 0x0080, 0x0100, 0x0200
KI_ERROR, KI_REQUEST, KI_ENCRYPTED, KI_SMK = 0x0400, 0x0800, 0x1000, 0x2000


def key_info(v):
    return {"raw": v, "version": v & KI_VERSION, "pairwise": bool(v & KI_PAIRWISE), "index": v >> 4 & 3, "install": bool(v & KI_INSTALL),
            "ack": bool(v & KI_ACK), "mic": bool(v & KI_MIC), "secure": bool(v & KI_SECURE), "error": bool(v & KI_ERROR),
            "request": bool(v & KI_REQUEST), "encrypted": bool(v & KI_ENCRYPTED), "smk": bool(v & KI_SMK)}


def _mic_len_for(body_len, buf, off):
    """让 Key Data Length 与实际长度吻合的 MIC 长度；没有吻合的返回 None。"""
    for m in MIC_LENGTHS:
        p = off + FIXED + m
        if len(buf) >= p + 2 and p + 2 + struct.unpack(">H", buf[p:p + 2])[0] == body_len + off:
            return m
    return None


def parse(buf, mic_len=None):
    """解析 EAPOL 报文（含 4 字节 EAPOL 头）。不是 EAPOL-Key 返回 None；
    返回 dict，"truncated" 为 True 表示报文比声明的短（已解出的字段保留，Key Data 取到哪算哪）。
    mic_len 为 None 时由长度关系推出；推不出（报文残缺）按 16 解。"""
    if len(buf) < 4 or buf[1] != EAPOL_KEY:
        return None
    length = struct.unpack(">H", buf[2:4])[0]
    body = buf[4:4 + length]
    out = {"version": buf[0], "type": buf[1], "length": length, "truncated": len(buf) < 4 + length, "mic_len": None}
    if len(body) < FIXED:
        out["truncated"] = True
        return out
    if mic_len is None:
        mic_len = _mic_len_for(len(body), body, 0) or 16
    out["mic_len"] = mic_len
    out["descriptor"] = body[0]
    out["key_info"] = ki = key_info(struct.unpack(">H", body[1:3])[0])
    out["key_length"] = struct.unpack(">H", body[3:5])[0]
    out["replay_counter"] = struct.unpack(">Q", body[5:13])[0]
    out["nonce"], out["iv"], out["rsc"], out["key_id"] = body[13:45], body[45:61], body[61:69], body[69:77]
    p = FIXED + mic_len
    if len(body) < p + 2:
        out["truncated"] = True
        out["mic"], out["data_length"], out["data"] = body[FIXED:], 0, b""
        return out
    out["mic"] = body[FIXED:p]
    out["data_length"] = struct.unpack(">H", body[p:p + 2])[0]
    out["data"] = body[p + 2:p + 2 + out["data_length"]]
    if len(out["data"]) < out["data_length"]:
        out["truncated"] = True
    out["message"] = message_number(out)
    return out


def message_number(e):
    """握手消息号：成对握手 1-4；组密钥握手 "G1"（AP → STA）、"G2"（STA → AP）；认不出返回 None。
    依据 Key Info：M1 = Ack 无 MIC；M3 = Ack + MIC；M4 = 无 Ack、有 MIC、Secure；M2 = 无 Ack、有 MIC、非 Secure、带 SNonce。
    WPA1 的 M4 没有 Secure 位，和 M2 的位型一样，靠 Nonce 区分：M2 带 SNonce，M4 的 Nonce 全 0。"""
    ki = e["key_info"]
    if ki["pairwise"]:
        if ki["ack"] and not ki["mic"]:
            return 1
        if ki["ack"] and ki["mic"]:
            return 3
        if ki["mic"] and not ki["ack"]:
            if ki["secure"]:
                return 4
            return 2 if any(e["nonce"]) else 4
        return None
    if ki["ack"] and ki["mic"]:
        return "G1"
    if ki["mic"] and not ki["ack"]:
        return "G2"
    return None


def zero_mic(buf, mic_len):
    """把 EAPOL 报文里的 MIC 字段清零（算 / 验 MIC 时用）。"""
    off = 4 + FIXED
    return buf[:off] + bytes(mic_len) + buf[off + mic_len:]
