# -*- coding: utf-8 -*-
"""测试用的 QUIC Initial 包构造器——和 wifi80211/quic.py 不共用任何代码：AES-GCM 和 ECB 来自 pycryptodome，HKDF 自己按 RFC 5869 写。
先用 RFC 9001 附录 A.2 的向量证明它是对的（tests/test_quic.py），之后再用它造各种包去考 quic.py 和 tshark。"""
import hashlib
import hmac
import struct

from Crypto.Cipher import AES

SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def label(secret, name, n):
    full = b"tls13 " + name
    return hkdf_expand(secret, struct.pack(">H", n) + bytes([len(full)]) + full + b"\0", n)


def keys(dcid, version=1):
    v2 = version == 0x6b3343cf
    prefix = b"quicv2 " if v2 else b"quic "
    secret = label(hkdf_extract(SALT_V2 if v2 else SALT_V1, dcid), b"client in", 32)
    return label(secret, prefix + b"key", 16), label(secret, prefix + b"iv", 12), label(secret, prefix + b"hp", 16)


def vint(n, size=None):
    for s, bits in ((1, 6), (2, 14), (4, 30), (8, 62)):
        if n < (1 << bits) and (size is None or size == s):
            return (n | {1: 0, 2: 0x4000, 4: 0x80000000, 8: 0xC000000000000000}[s]).to_bytes(s, "big")
    raise ValueError


def crypto_frame(offset, data):
    return b"\x06" + vint(offset) + vint(len(data), 2) + data


def build(dcid, scid, payload, pn=2, pn_len=4, version=1, token=b"", pad_to=1200, first_xor=0):
    """payload 是未加密的帧；不足 pad_to 字节（整个数据报）就在后面补 PADDING 帧。"""
    k, iv, hp = keys(dcid, version)
    first = 0xC0 | ((1 if version == 0x6b3343cf else 0) << 4) | (pn_len - 1)
    first ^= first_xor                                                          # 测试用：把首字节的某些位翻过来（头里的位也在认证范围内，包照样是「合法」的）
    pnb = pn.to_bytes(pn_len, "big")

    def head(length):
        return bytes([first]) + struct.pack(">I", version) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + vint(len(token)) + token + vint(length, 2)
    need = pad_to - (len(head(0)) + pn_len + 16 + len(payload))
    payload += b"\0" * max(0, need)
    header = head(pn_len + len(payload) + 16) + pnb
    c = AES.new(k, AES.MODE_GCM, nonce=bytes(a ^ b for a, b in zip(iv, b"\0" * (12 - pn_len) + pnb)))
    c.update(header)
    ct, tag = c.encrypt_and_digest(payload)
    body = ct + tag
    mask = AES.new(hp, AES.MODE_ECB).encrypt((pnb + body)[4:20])
    prot = bytes([header[0] ^ (mask[0] & 0x0F)]) + header[1:-pn_len] + bytes(a ^ b for a, b in zip(pnb, mask[1:1 + pn_len]))
    return prot + body


def client_hello(sni, extra=0):
    """最小的 TLS 1.3 ClientHello（SNI + supported_versions + 可选的 padding 扩展撑大），整条握手消息含 4 字节头。"""
    def ext(t, d):
        return struct.pack(">HH", t, len(d)) + d
    exts = b""
    if sni is not None:
        name = sni.encode()
        exts += ext(0, struct.pack(">HBH", len(name) + 3, 0, len(name)) + name)
    exts += ext(43, b"\x02\x03\x04") + ext(10, b"\x00\x02\x00\x1d") + ext(13, b"\x00\x02\x04\x03")
    if extra:
        exts += ext(21, b"\0" * extra)
    body = b"\x03\x03" + bytes(range(32)) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    return b"\x01" + len(body).to_bytes(3, "big") + body
