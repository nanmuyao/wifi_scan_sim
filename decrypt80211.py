# -*- coding: utf-8 -*-
"""
802.11 数据帧解密：CCMP / GCMP / TKIP（单播与组播；WEP、受保护的管理帧后续加）。纯标准库。

CCMP / GCMP 帧体 = 8 字节头 ‖ 密文 ‖ MIC（CCMP-128 8 字节，CCMP-256 与 GCMP 16 字节）
  头：PN0 PN1 保留 (ExtIV | 密钥序号<<6) PN2 PN3 PN4 PN5
  nonce（CCMP，13 字节）：标志(1：数据帧是 QoS 的 TID、管理帧是 0x10) ‖ A2(6) ‖ PN(6，高位在前)；GCMP 的 IV（12 字节）：A2 ‖ PN（高位在前）
  AAD：帧控制（数据帧的子类型 b4-b6、重试、省电、更多数据清零；受保护位保留；管理帧的子类型整个保留）‖ A1 ‖ A2 ‖ A3 ‖ 序号控制（只留分片号）‖ [A4] ‖ [QoS 控制，只留 TID]
"""
import struct

import crypto80211 as c
import kdf80211 as kdf

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
    if h["type"] == 2:
        fc[0] &= 0x8F                  # 数据帧：子类型的 b4-b6（管理帧的子类型整个保留）
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
        prio = 0x10 if h["type"] == 0 else (h["qos"]["tid"] if h["qos"] is not None else 0)     # 管理帧：nonce 标志的 bit 4
        nonce = bytes([prio]) + a2 + pn.to_bytes(6, "big")
        pt, ok = c.ccm_decrypt(tk, nonce, aad, body[8:], mic)
    else:
        pt, ok = c.gcm_decrypt(tk, a2 + pn.to_bytes(6, "big"), aad, body[8:], mic)
    return pt, ok, pn


def decrypt_tkip(tk, frame, michael_key=None):
    """解一个 TKIP 帧（密钥 32 字节：TEK 16 ‖ AP 发送的 Michael 密钥 8 ‖ STA 发送的 Michael 密钥 8）。
    返回 (MSDU, ICV 是否通过, Michael 是否通过 / 分片帧没法校验为 None, TSC)；MSDU 从 LLC 开始，已去掉 Michael MIC 和 ICV。
    Michael 的密钥由发送方决定：FromDS（AP 发出）用 tk[16:24]，否则 tk[24:32]；输入是 DA ‖ SA ‖ 优先级 ‖ 000 ‖ MSDU。"""
    h = frame.h
    if len(tk) != 32:
        raise ValueError("TKIP 密钥必须是 32 字节")
    data, tsc, icv_ok = c.tkip_decrypt(tk[:16], _mac(h["addr2"]), frame.body)
    if len(data) < 8:
        return data, icv_ok, False, tsc
    msdu, mic = data[:-8], data[-8:]
    if h["more_frag"] or h["frag_num"]:
        return msdu, icv_ok, None, tsc
    key = michael_key or (tk[16:24] if h["from_ds"] and not h["to_ds"] else tk[24:32])
    prio = h["qos"]["tid"] if h["qos"] is not None else 0
    m_ok = c.michael(key, c.tkip_michael_input(_mac(h["da"]), _mac(h["sa"]), prio, msdu)) == mic
    return msdu, icv_ok, m_ok, tsc


def decrypt_any(cipher, key, frame):
    """按套件解一个帧：返回 (明文, 完整性是否通过)。AEAD 看 MIC；TKIP 要 ICV 和 Michael 都过（分片帧只看 ICV）。"""
    if cipher == "TKIP":
        if len(frame.body) < 8 + 4 + 8:
            raise ValueError("帧体太短")
        msdu, icv_ok, m_ok, _tsc = decrypt_tkip(key, frame)
        return msdu, icv_ok and m_ok is not False
    pt, ok, _pn = decrypt_aead(key, cipher, frame)
    return pt, ok


SUPPORTED = tuple(MIC_LEN) + ("TKIP",)


def decrypt_frame(handshakes, frame):
    """在已推出的握手里找能解开这一帧的 PTK：同一对地址、M2 在这一帧之前的握手，从新到旧逐个试（重新握手之后到新密钥
    装上之前的帧、Extended Key ID 下新旧两把密钥同时有效，都要靠 MIC 来分辨）。返回 (握手, 明文) 或 None。
    CCMP / GCMP / TKIP 的单播数据帧，以及 CCMP / GCMP 保护的单播管理帧（PMF）。"""
    h = frame.h
    if h["type"] not in (0, 2) or not h["protected"]:
        return None
    pair = {h["addr1"], h["addr2"]}
    for hs in sorted((x for x in handshakes if {x.ap, x.sta} == pair and x.frames["m2"] < frame.n and x.cipher in SUPPORTED),
                     key=lambda x: -x.frames["m2"]):
        try:
            pt, ok = decrypt_any(hs.cipher, hs.tk, frame)
        except ValueError:
            continue
        if ok:
            return hs, pt
    return None


def wep_keys(keys):
    """从密钥表（decrypt_oracle.parse_keys 的格式）取出 WEP 密钥：十六进制串，5 / 13 / 16 字节。"""
    out = []
    for typ, val in keys:
        if typ == "wep":
            try:
                k = bytes.fromhex(val)
            except ValueError:
                continue
            if len(k) in (5, 13, 16):
                out.append(k)
    return out


def decrypt_wep(wep, frame):
    """WEP：数据帧，以及共享密钥认证的第 3 帧（管理帧，受保护位置位）。帧体 = IV(3) ‖ 密钥序号(1) ‖ 密文 ‖ ICV(4)，没有 ExtIV 位。
    逐个试 wep 里的密钥，ICV 通过的就是（WEP 密钥序号只告诉你第几把，不告诉你密钥值）。返回 (明文, 密钥) 或 None。"""
    h, body = frame.h, frame.body
    if not h["protected"] or len(body) < 8 or body[3] & 0x20:
        return None
    for k in wep:
        pt, _key_id, ok = c.wep_decrypt(k, body)
        if ok:
            return pt, k
    return None


# ---------------------------------------------------------------------------
# BIP：广播 / 组播管理帧的完整性（不加密，帧末尾带 Management MIC 元素）
# ---------------------------------------------------------------------------
# 组管理套件类型（00-0F-AC:n）-> (名字, IGTK 字节数, MIC 字节数)
BIP_SUITES = {6: ("BIP-CMAC-128", 16, 8), 11: ("BIP-GMAC-128", 16, 16), 12: ("BIP-GMAC-256", 32, 16), 13: ("BIP-CMAC-256", 32, 16)}
BIP_BY_NAME = {v[0]: v for v in BIP_SUITES.values()}
MME_ID = 76


def find_mme(body):
    """帧体末尾的 Management MIC 元素：[76, 长度, 密钥序号(2，小端), IPN(6), MIC]。返回 (密钥序号, IPN, MIC, MIC 在帧体里的偏移)，没有返回 None。
    长度 16 = MIC 8 字节，24 = MIC 16 字节（两者都从末尾往前认）。"""
    for mic_len in (8, 16):
        n = 8 + mic_len
        if len(body) >= 2 + n and body[-(2 + n)] == MME_ID and body[-(1 + n)] == n:
            p = len(body) - n
            return body[p] | body[p + 1] << 8, body[p + 2:p + 8], body[p + 8:], p + 8
    return None


def verify_bip(igtk, cipher, frame):
    """校验一个广播 / 组播管理帧的 MME。返回 (MIC 是否吻合, 密钥序号, IPN)，帧里没有 MME 返回 None。
    被保护的内容：AAD = 帧控制（重试 / 省电 / 更多数据清零）‖ A1 ‖ A2 ‖ A3，后面接帧体（MME 的 MIC 字段清零）。
    CMAC：AES-CMAC(IGTK, AAD ‖ 帧体)，取前 8 / 16 字节；GMAC：AES-GCM 无明文，IV = A2 ‖ IPN（高位在前），AAD 同上，tag 16 字节。"""
    found = find_mme(frame.body)
    if found is None:
        return None
    key_id, ipn, mic, off = found
    name, key_len, mic_len = BIP_BY_NAME[cipher]
    if len(igtk) != key_len or len(mic) != mic_len:
        return False, key_id, ipn
    body = frame.body[:off] + bytes(mic_len)
    fc = bytearray(frame.dot11[:2])
    fc[1] &= ~(0x08 | 0x10 | 0x20) & 0xFF
    aad = bytes(fc) + frame.dot11[4:22]
    if name.startswith("BIP-CMAC"):
        calc = kdf.aes_cmac(igtk, aad + body, mic_len)
    else:
        calc = c.gcm_encrypt(igtk, frame.dot11[10:16] + ipn[::-1], aad + body, b"", 16)
    return _eq(calc, mic), key_id, ipn


def _eq(a, b):
    return len(a) == len(b) and c._const_eq(a, b)
