# -*- coding: utf-8 -*-
"""
802.11 的数据面加密原语。AES 单块用 pycryptodome 的 ECB（唯一的第三方依赖），其余全部手写：

    CCM    CCMP-128（AES-128，MIC 8 字节）、CCMP-256（AES-256，MIC 16 字节）
    GCM    GCMP-128 / GCMP-256（MIC 16 字节），GHASH 手写
    RC4    WEP 和 TKIP 的流密码
    WEP    IV(3) + 密钥序号(1) + RC4(IV ‖ 密钥)(数据 ‖ ICV)，ICV = CRC-32 小端
    TKIP   密钥混合（第 1 阶段、第 2 阶段，得到 RC4 种子）和 Michael 消息完整性码

这里只有「算法」：给定密钥、nonce、AAD 就加密 / 解密。帧头怎么构造 nonce 和 AAD（哪些位屏蔽、4 地址、QoS）是另一回事，
放在解密流程里，用真实抓包对照 tshark 来验证。
"""
import struct
import zlib
from functools import lru_cache


# ---------------------------------------------------------------------------
# AES 单块
# ---------------------------------------------------------------------------
@lru_cache(maxsize=64)
def _ecb(key):
    """同一把密钥只建一次 AES 对象（建对象比加密一块还贵；ECB 加密不带状态，可以复用）。"""
    from Crypto.Cipher import AES
    return AES.new(key, AES.MODE_ECB)


def aes_block(key, block):
    """AES 单块加密（ECB），key 16 或 32 字节。"""
    return _ecb(bytes(key)).encrypt(bytes(block))


def aes_blocks(key, blocks):
    """AES-ECB 一次加密多块（长度是 16 的倍数），CTR 的密钥流用这个批量算。"""
    return _ecb(bytes(key)).encrypt(bytes(blocks))


def _xor(a, b):
    n = min(len(a), len(b))
    return (int.from_bytes(a[:n], "big") ^ int.from_bytes(b[:n], "big")).to_bytes(n, "big")


# ---------------------------------------------------------------------------
# CCM（RFC 3610，L = 2）
# ---------------------------------------------------------------------------
def _ccm_mac(key, nonce, aad, msg, m, l):
    flags = (0x40 if aad else 0) | (((m - 2) // 2) << 3) | (l - 1)
    b0 = bytes([flags]) + nonce + len(msg).to_bytes(l, "big")
    data = b0
    if aad:
        a = len(aad).to_bytes(2, "big") + aad
        data += a + b"\x00" * (-len(a) % 16)
    data += msg + b"\x00" * (-len(msg) % 16)
    x = b"\x00" * 16
    for i in range(0, len(data), 16):
        x = aes_block(key, _xor(x, data[i:i + 16]))
    return x[:m]


def _ccm_ctr(key, nonce, data, l, start):
    head = bytes([l - 1]) + nonce
    ks = aes_blocks(key, b"".join(head + (start + i).to_bytes(l, "big") for i in range((len(data) + 15) // 16)))
    return _xor(data, ks)


def ccm_encrypt(key, nonce, aad, plaintext, mic_len=8, l=2):
    """返回 密文 ‖ MIC。nonce 长度必须是 15 - l（CCMP 是 13 字节）。"""
    if len(nonce) != 15 - l:
        raise ValueError("CCM nonce 必须是 %d 字节" % (15 - l))
    tag = _ccm_mac(key, nonce, aad, plaintext, mic_len, l)
    s0 = aes_block(key, bytes([l - 1]) + nonce + (0).to_bytes(l, "big"))
    return _ccm_ctr(key, nonce, plaintext, l, 1) + _xor(tag, s0[:mic_len])


def ccm_decrypt(key, nonce, aad, data, mic_len=8, l=2):
    """data = 密文 ‖ MIC。返回 (明文, MIC 是否通过)。MIC 不通过时明文仍然返回（取证时有用），调用方必须看第二个值。"""
    if len(nonce) != 15 - l:
        raise ValueError("CCM nonce 必须是 %d 字节" % (15 - l))
    if len(data) < mic_len:
        raise ValueError("数据比 MIC 还短")
    ct, enc_tag = data[:-mic_len], data[-mic_len:]
    pt = _ccm_ctr(key, nonce, ct, l, 1)
    s0 = aes_block(key, bytes([l - 1]) + nonce + (0).to_bytes(l, "big"))
    ok = _const_eq(_ccm_mac(key, nonce, aad, pt, mic_len, l), _xor(enc_tag, s0[:mic_len]))
    return pt, ok


def _const_eq(a, b):
    r = len(a) ^ len(b)
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


# ---------------------------------------------------------------------------
# GCM（NIST SP 800-38D，96 位 IV，16 字节 tag）
# ---------------------------------------------------------------------------
_R = 0xE1 << 120


def _gf_mul(x, y):
    """GF(2^128) 乘法（GCM 的位序：最高位是 x^0）。"""
    z, v = 0, y
    for i in range(127, -1, -1):
        if x >> i & 1:
            z ^= v
        v = (v >> 1) ^ _R if v & 1 else v >> 1
    return z


def _ghash(h, aad, ct):
    def blocks(b):
        b = b + b"\x00" * (-len(b) % 16)
        return [int.from_bytes(b[i:i + 16], "big") for i in range(0, len(b), 16)]
    y = 0
    for blk in blocks(aad) + blocks(ct):
        y = _gf_mul(y ^ blk, h)
    return _gf_mul(y ^ (len(aad) * 8 << 64 | len(ct) * 8), h)


def _gcm_ctr(key, j0, data):
    base = int.from_bytes(j0, "big")
    ctrs = []
    for _ in range((len(data) + 15) // 16):
        base = (base & ~0xFFFFFFFF) | ((base + 1) & 0xFFFFFFFF)       # 只有低 32 位在数，到头回绕
        ctrs.append(base.to_bytes(16, "big"))
    return _xor(data, aes_blocks(key, b"".join(ctrs)))


def gcm_encrypt(key, iv, aad, plaintext, tag_len=16):
    """返回 密文 ‖ tag。iv 必须是 12 字节（GCMP 的 nonce：A2 ‖ PN）。"""
    if len(iv) != 12:
        raise ValueError("GCM IV 必须是 12 字节")
    h = int.from_bytes(aes_block(key, b"\x00" * 16), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    ct = _gcm_ctr(key, j0, plaintext)
    s = _ghash(h, aad, ct)
    tag = _xor(s.to_bytes(16, "big"), aes_block(key, j0))
    return ct + tag[:tag_len]


def gcm_decrypt(key, iv, aad, data, tag_len=16):
    """data = 密文 ‖ tag。返回 (明文, tag 是否通过)。"""
    if len(iv) != 12:
        raise ValueError("GCM IV 必须是 12 字节")
    if len(data) < tag_len:
        raise ValueError("数据比 tag 还短")
    ct, tag = data[:-tag_len], data[-tag_len:]
    h = int.from_bytes(aes_block(key, b"\x00" * 16), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    s = _ghash(h, aad, ct)
    calc = _xor(s.to_bytes(16, "big"), aes_block(key, j0))[:tag_len]
    return _gcm_ctr(key, j0, ct), _const_eq(calc, tag)


# ---------------------------------------------------------------------------
# RC4、CRC-32、WEP
# ---------------------------------------------------------------------------
def rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out.append(byte ^ s[(s[i] + s[j]) & 255])
    return bytes(out)


def crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def wep_decrypt(key, body):
    """body = IV(3) ‖ 密钥序号(1) ‖ 密文 ‖ ICV(4)（ICV 也是加密的）。返回 (明文, key_id, ICV 是否通过)。"""
    if len(body) < 4 + 4:
        raise ValueError("WEP 数据太短")
    iv, key_id = body[:3], body[3] >> 6
    pt = rc4(iv + bytes(key), body[4:])
    data, icv = pt[:-4], pt[-4:]
    return data, key_id, struct.unpack("<I", icv)[0] == crc32(data)


def wep_encrypt(key, iv, key_id, plaintext):
    """返回 IV ‖ 密钥序号 ‖ RC4(明文 ‖ ICV)。"""
    return bytes(iv) + bytes([key_id << 6]) + rc4(bytes(iv) + bytes(key), plaintext + struct.pack("<I", crc32(plaintext)))


# ---------------------------------------------------------------------------
# TKIP：密钥混合（IEEE 802.11i）
# ---------------------------------------------------------------------------
def _aes_sbox():
    """AES S 盒（TKIP 的 S 盒由它推出）：GF(2^8) 求逆再做仿射变换。"""
    def mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = (a << 1) ^ 0x11B if a & 0x80 else a << 1
            b >>= 1
        return r
    box = []
    for x in range(256):
        inv = 0 if x == 0 else next(y for y in range(1, 256) if mul(x, y) == 1)
        b = inv
        s = inv
        for _ in range(4):
            b = ((b << 1) | (b >> 7)) & 255
            s ^= b
        box.append(s ^ 0x63)
    return box


_AES_S = _aes_sbox()
# TKIP 的 16 位 S 盒：高字节 = 2 * S(i)，低字节 = 3 * S(i)（GF(2^8) 里），共 256 项
TKIP_SBOX = [((((s << 1) ^ (0x11B if s & 0x80 else 0)) & 255) << 8) | ((((s << 1) ^ (0x11B if s & 0x80 else 0)) & 255) ^ s) for s in _AES_S]


def _S(v):
    return TKIP_SBOX[v & 255] ^ (((TKIP_SBOX[v >> 8] << 8) | (TKIP_SBOX[v >> 8] >> 8)) & 0xFFFF)


def _mk16(hi, lo):
    return hi << 8 | lo


def _rotr1(v):
    return ((v >> 1) | (v << 15)) & 0xFFFF


def tkip_phase1(tk, ta, tsc_hi):
    """第 1 阶段：TK(16) + 发送方地址(6) + TSC 高 32 位 -> TTAK（5 个 16 位字）。"""
    t = [tsc_hi & 0xFFFF, tsc_hi >> 16 & 0xFFFF, _mk16(ta[1], ta[0]), _mk16(ta[3], ta[2]), _mk16(ta[5], ta[4])]
    for i in range(8):
        j = 2 * (i & 1)
        t[0] = (t[0] + _S(t[4] ^ _mk16(tk[1 + j], tk[0 + j]))) & 0xFFFF
        t[1] = (t[1] + _S(t[0] ^ _mk16(tk[5 + j], tk[4 + j]))) & 0xFFFF
        t[2] = (t[2] + _S(t[1] ^ _mk16(tk[9 + j], tk[8 + j]))) & 0xFFFF
        t[3] = (t[3] + _S(t[2] ^ _mk16(tk[13 + j], tk[12 + j]))) & 0xFFFF
        t[4] = (t[4] + _S(t[3] ^ _mk16(tk[1 + j], tk[0 + j])) + i) & 0xFFFF
    return t


def tkip_phase2(tk, ttak, tsc_lo):
    """第 2 阶段：TK + TTAK + TSC 低 16 位 -> 16 字节 RC4 种子（WEP seed）。"""
    p = list(ttak) + [(ttak[4] + tsc_lo) & 0xFFFF]
    p[0] = (p[0] + _S(p[5] ^ _mk16(tk[1], tk[0]))) & 0xFFFF
    p[1] = (p[1] + _S(p[0] ^ _mk16(tk[3], tk[2]))) & 0xFFFF
    p[2] = (p[2] + _S(p[1] ^ _mk16(tk[5], tk[4]))) & 0xFFFF
    p[3] = (p[3] + _S(p[2] ^ _mk16(tk[7], tk[6]))) & 0xFFFF
    p[4] = (p[4] + _S(p[3] ^ _mk16(tk[9], tk[8]))) & 0xFFFF
    p[5] = (p[5] + _S(p[4] ^ _mk16(tk[11], tk[10]))) & 0xFFFF
    p[0] = (p[0] + _rotr1(p[5] ^ _mk16(tk[13], tk[12]))) & 0xFFFF
    p[1] = (p[1] + _rotr1(p[0] ^ _mk16(tk[15], tk[14]))) & 0xFFFF
    p[2] = (p[2] + _rotr1(p[1])) & 0xFFFF
    p[3] = (p[3] + _rotr1(p[2])) & 0xFFFF
    p[4] = (p[4] + _rotr1(p[3])) & 0xFFFF
    p[5] = (p[5] + _rotr1(p[4])) & 0xFFFF
    seed = bytearray(16)
    seed[0] = tsc_lo >> 8
    seed[1] = (seed[0] | 0x20) & 0x7F
    seed[2] = tsc_lo & 0xFF
    seed[3] = ((p[5] ^ _mk16(tk[1], tk[0])) >> 1) & 0xFF
    for i in range(6):
        seed[4 + 2 * i] = p[i] & 0xFF
        seed[5 + 2 * i] = p[i] >> 8
    return bytes(seed)


def tkip_rc4_seed(tk, ta, tsc):
    """TSC 是 48 位序号。返回 RC4 种子。"""
    return tkip_phase2(tk, tkip_phase1(tk, ta, tsc >> 16), tsc & 0xFFFF)


def tkip_decrypt(tk, ta, body):
    """body = TKIP 头(8: TSC1, WEPSeed, TSC0, ExtIV|KeyID<<6, TSC2..TSC5) ‖ 密文 ‖ ICV(4)。
    返回 (明文 ‖ Michael MIC(8)，TSC，ICV 是否通过)。Michael 要另外用 tkip_michael 校验（需要 DA / SA / 优先级）。"""
    if len(body) < 8 + 4:
        raise ValueError("TKIP 数据太短")
    tsc = body[2] | body[0] << 8 | body[4] << 16 | body[5] << 24 | body[6] << 32 | body[7] << 40
    pt = rc4(tkip_rc4_seed(tk, ta, tsc), body[8:])
    data, icv = pt[:-4], pt[-4:]
    return data, tsc, struct.unpack("<I", icv)[0] == crc32(data)


def tkip_encrypt(tk, ta, tsc, key_id, plaintext):
    """plaintext 末尾应已带 Michael MIC。返回 TKIP 头 ‖ RC4(明文 ‖ ICV)。"""
    seed = tkip_rc4_seed(tk, ta, tsc)
    hdr = bytes([tsc >> 8 & 255, seed[1], tsc & 255, 0x20 | key_id << 6]) + (tsc >> 16).to_bytes(4, "little")
    return hdr + rc4(seed, plaintext + struct.pack("<I", crc32(plaintext)))


# ---------------------------------------------------------------------------
# Michael
# ---------------------------------------------------------------------------
def _rol32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _ror32(v, n):
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def _xswap(v):
    return ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8)


def michael(key, data):
    """Michael(密钥 8 字节, 消息) -> 8 字节。消息先补 0x5a 再补零到 4 的整数倍（至少补 4 字节零）。"""
    l, r = struct.unpack("<II", key)
    data = data + b"\x5a" + b"\x00" * (4 + (-(len(data) + 1)) % 4)
    for (m,) in struct.iter_unpack("<I", data):
        l ^= m
        r ^= _rol32(l, 17)
        l = (l + r) & 0xFFFFFFFF
        r ^= _xswap(l)
        l = (l + r) & 0xFFFFFFFF
        r ^= _rol32(l, 3)
        l = (l + r) & 0xFFFFFFFF
        r ^= _ror32(l, 2)
        l = (l + r) & 0xFFFFFFFF
    return struct.pack("<II", l, r)


def tkip_michael_input(da, sa, priority, msdu):
    """Michael 的输入：DA ‖ SA ‖ 优先级(1) ‖ 0 0 0 ‖ MSDU 数据。"""
    return bytes(da) + bytes(sa) + bytes([priority, 0, 0, 0]) + bytes(msdu)
