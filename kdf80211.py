# -*- coding: utf-8 -*-
"""
802.11 的密钥推导与密钥保护原语。纯标准库 + pycryptodome 的 AES 单块。

    PRF-SHA1       WPA / WPA2（AKM 1、2）的 PTK 推导：HMAC-SHA1 反复拼接，计数从 0 开始
    KDF-SHA256 / 384 / 512
                   SHA-256 系列 AKM（FT、SAE、PSK-SHA256 等）的推导（802.11-2016 12.7.1.7.2）：
                   HMAC-Hash(密钥, 计数(2 字节小端，从 1 开始) ‖ 标签 ‖ 上下文 ‖ 输出比特数(2 字节小端))
    AES-CMAC       RFC 4493，EAPOL-Key 的 MIC（描述符版本 3）和管理帧保护 BIP 都用它
    AES key wrap   RFC 3394，EAPOL-Key 的 Key Data 加密（描述符版本 2、3、0）
    RC4 key unwrap 描述符版本 1（WPA1 / TKIP）：RC4 密钥是 IV ‖ KEK，丢掉前 256 字节密钥流
这里只有算法；用哪种、取多长，由 AKM 和密码套件决定，放在握手流程里。
"""
import hashlib
import hmac
import struct

import crypto80211


def prf_sha1(key, label, data, nbytes):
    """PRF-n(K, A, B) = 连接 HMAC-SHA1(K, A ‖ 0x00 ‖ B ‖ i)，i 从 0 开始，取前 nbytes 字节。
    label 是 A（例如 b"Pairwise key expansion"），data 是 B。"""
    out = b""
    i = 0
    while len(out) < nbytes:
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:nbytes]


def kdf(hash_name, key, label, context, nbits):
    """KDF-Hash-Length(K, label, context)：连接 HMAC-Hash(K, i(2 字节小端) ‖ label ‖ context ‖ Length(2 字节小端))，i 从 1 开始，
    取前 nbits 比特（nbits 必须是 8 的倍数）。hash_name：sha256 / sha384 / sha512。"""
    if nbits % 8:
        raise ValueError("KDF 输出比特数必须是 8 的倍数")
    out = b""
    i = 1
    while len(out) * 8 < nbits:
        out += hmac.new(key, struct.pack("<H", i) + label + context + struct.pack("<H", nbits), getattr(hashlib, hash_name)).digest()
        i += 1
    return out[:nbits // 8]


# ---------------------------------------------------------------------------
# AES-CMAC（RFC 4493）
# ---------------------------------------------------------------------------
def _dbl(b):
    v = int.from_bytes(b, "big") << 1
    if v >> 128:
        v = (v & ((1 << 128) - 1)) ^ 0x87
    return v.to_bytes(16, "big")


def aes_cmac(key, msg, taglen=16):
    """AES-CMAC，key 16 或 32 字节（AES-128 / 256）；返回前 taglen 字节。"""
    l = crypto80211.aes_block(key, bytes(16))
    k1 = _dbl(l)
    k2 = _dbl(k1)
    n = (len(msg) + 15) // 16 or 1
    complete = len(msg) > 0 and len(msg) % 16 == 0
    last = msg[(n - 1) * 16:]
    last = bytes(a ^ b for a, b in zip(last, k1)) if complete else bytes(a ^ b for a, b in zip(last + b"\x80" + bytes(15 - len(last)), k2))
    x = bytes(16)
    for i in range(n - 1):
        x = crypto80211.aes_block(key, bytes(a ^ b for a, b in zip(x, msg[i * 16:(i + 1) * 16])))
    return crypto80211.aes_block(key, bytes(a ^ b for a, b in zip(x, last)))[:taglen]


# ---------------------------------------------------------------------------
# AES key wrap（RFC 3394）
# ---------------------------------------------------------------------------
_IV = b"\xa6" * 8


def _aes_dec_block(key, block):
    from Crypto.Cipher import AES
    return AES.new(bytes(key), AES.MODE_ECB).decrypt(bytes(block))


def aes_key_wrap(kek, plaintext):
    """plaintext 是 8 字节的整数倍（至少 16 字节）。返回 密文（比明文长 8 字节）。"""
    if len(plaintext) % 8 or len(plaintext) < 16:
        raise ValueError("要包装的密钥必须是 8 字节的整数倍且不少于 16 字节")
    n = len(plaintext) // 8
    a = _IV
    r = [plaintext[i * 8:(i + 1) * 8] for i in range(n)]
    for j in range(6):
        for i in range(n):
            b = crypto80211.aes_block(kek, a + r[i])
            t = n * j + i + 1
            a = (int.from_bytes(b[:8], "big") ^ t).to_bytes(8, "big")
            r[i] = b[8:]
    return a + b"".join(r)


def aes_key_unwrap(kek, ciphertext):
    """返回 (明文, 完整性校验是否通过：开头 8 字节是否还原成 A6A6A6A6A6A6A6A6)。"""
    if len(ciphertext) % 8 or len(ciphertext) < 24:
        raise ValueError("被包装的密钥必须是 8 字节的整数倍且不少于 24 字节")
    n = len(ciphertext) // 8 - 1
    a = ciphertext[:8]
    r = [ciphertext[(i + 1) * 8:(i + 2) * 8] for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n - 1, -1, -1):
            t = n * j + i + 1
            b = _aes_dec_block(kek, (int.from_bytes(a, "big") ^ t).to_bytes(8, "big") + r[i])
            a = b[:8]
            r[i] = b[8:]
    return b"".join(r), a == _IV


def rc4_key_unwrap(kek, iv, data):
    """EAPOL-Key 描述符版本 1：RC4 密钥 = Key IV(16) ‖ KEK(16)，丢掉前 256 字节密钥流，再解密 Key Data。"""
    return crypto80211.rc4(bytes(iv) + bytes(kek), bytes(256) + bytes(data))[256:]
