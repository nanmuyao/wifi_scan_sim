#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""kdf80211：AES-CMAC（RFC 4493）、AES key wrap（RFC 3394）、RC4 密钥解包、PRF / KDF 的定义。
PRF / KDF 没有独立向量可引（这里只核对定义本身）；它们由 D4 用 tshark 给出的 KCK / KEK / TK 逐把验证。"""
import hashlib
import hmac
import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto80211 as c  # noqa: E402
import kdf80211 as k  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


H = bytes.fromhex
rnd = random.Random(4493)

print("== AES-CMAC（RFC 4493）==")
key = H("2b7e151628aed2a6abf7158809cf4f3c")
M = H("6bc1bee22e409f96e93d7e117393172a" "ae2d8a571e03ac9c9eb76fac45af8e51" "30c81c46a35ce411e5fbc1191a0a52ef" "f69f2445df4f9b17ad2b417be66c3710")
l = c.aes_block(key, bytes(16))
check(k._dbl(l) == H("fbeed618357133667c85e08f7236a8de") and k._dbl(k._dbl(l)) == H("f7ddac306ae266ccf90bc11ee46d513b"), "子密钥 K1 = fbeed618…，K2 = f7ddac30…")
for n, want in ((0, "bb1d6929e95937287fa37d129b756746"), (16, "070a16b46b4d4144f79bdd9dd04a287c"),
                (40, "dfa66747de9ae63030ca32611497c827"), (64, "51f0bebf7e3b9d92fc49741779363cfe")):
    check(k.aes_cmac(key, M[:n]).hex() == want, "消息 %d 字节 -> %s" % (n, want))
check(k.aes_cmac(key, M[:40], 8) == H("dfa66747de9ae630"), "截断到 8 字节取前 8 字节")
from Crypto.Hash import CMAC  # noqa: E402
from Crypto.Cipher import AES  # noqa: E402
n_ok = 0
for _ in range(100):
    kk, mm = rnd.randbytes(rnd.choice((16, 32))), rnd.randbytes(rnd.randrange(0, 100))
    n_ok += k.aes_cmac(kk, mm) == CMAC.new(kk, ciphermod=AES, msg=mm).digest()
check(n_ok == 100, "100 组随机输入（AES-128 / 256，消息 0-99 字节）与 pycryptodome 的 CMAC 一致")

print("== AES key wrap（RFC 3394）==")
kek128, kek256 = bytes(range(16)), bytes(range(32))
d128, d256 = H("00112233445566778899AABBCCDDEEFF"), H("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
vecs = ((kek128, d128, "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"),
        (kek256, d128, "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"),
        (kek256, d256, "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"))
for kk, dd, want in vecs:
    check(k.aes_key_wrap(kk, dd).hex().upper() == want, "包装：KEK %d 位、密钥 %d 位 -> %s…" % (len(kk) * 8, len(dd) * 8, want[:16]))
    check(k.aes_key_unwrap(kk, H(want)) == (dd, True), "解包：同一向量，完整性通过")
w = bytearray(k.aes_key_wrap(kek128, d128))
w[10] ^= 1
check(k.aes_key_unwrap(kek128, bytes(w))[1] is False, "密文改 1 位：完整性不通过")
check(k.aes_key_unwrap(bytes(range(1, 17)), k.aes_key_wrap(kek128, d128))[1] is False, "KEK 不对：完整性不通过")
n_ok = 0
for _ in range(60):
    kk, dd = rnd.randbytes(rnd.choice((16, 32))), rnd.randbytes(8 * rnd.randrange(2, 12))
    n_ok += k.aes_key_unwrap(kk, k.aes_key_wrap(kk, dd)) == (dd, True)
check(n_ok == 60, "60 组随机的 包装 -> 解包 往返")
for fn, bad in ((lambda: k.aes_key_wrap(kek128, b"x" * 15), "不是 8 的整数倍"), (lambda: k.aes_key_wrap(kek128, b"x" * 8), "不足 16 字节"),
                (lambda: k.aes_key_unwrap(kek128, b"x" * 20), "解包：不是 8 的整数倍"), (lambda: k.aes_key_unwrap(kek128, b"x" * 16), "解包：不足 24 字节")):
    try:
        fn()
        check(False, bad + "应报错")
    except ValueError:
        check(True, bad + "：ValueError")

print("== RC4 密钥解包（描述符版本 1）==")
iv, kek, data = bytes(range(16)), bytes(range(100, 116)), b"secret group key data!!"
wrapped = c.rc4(iv + kek, bytes(256) + data)[256:]
check(k.rc4_key_unwrap(kek, iv, wrapped) == data, "RC4(IV ‖ KEK) 丢掉前 256 字节密钥流，再解密")
check(k.rc4_key_unwrap(kek, iv, data) != data and k.rc4_key_unwrap(kek, bytes(16), wrapped) != data, "IV 不对 / 没丢前 256 字节：结果不同")
check(c.rc4(iv + kek, data) != c.rc4(iv + kek, bytes(256) + data)[256:], "丢 256 字节确实改变了密钥流")

print("== PRF / KDF（只核对定义）==")
key20, a, b = bytes(range(32)), b"Pairwise key expansion", bytes(range(60))
want0 = hmac.new(key20, a + b"\x00" + b + b"\x00", hashlib.sha1).digest()
want1 = hmac.new(key20, a + b"\x00" + b + b"\x01", hashlib.sha1).digest()
check(k.prf_sha1(key20, a, b, 20) == want0 and k.prf_sha1(key20, a, b, 40) == want0 + want1, "PRF-SHA1：计数从 0 开始，第 2 块用计数 1")
check(k.prf_sha1(key20, a, b, 48) == (want0 + want1 + hmac.new(key20, a + b"\x00" + b + b"\x02", hashlib.sha1).digest())[:48] and len(k.prf_sha1(key20, a, b, 48)) == 48, "PRF-SHA1：取前 n 字节（48 = 20 + 20 + 8）")
check(k.prf_sha1(key20, a, b, 64)[:48] == k.prf_sha1(key20, a, b, 48), "较短的输出是较长输出的前缀")
for h, hl in (("sha256", 32), ("sha384", 48), ("sha512", 64)):
    d1 = hmac.new(key20, struct.pack("<H", 1) + a + b + struct.pack("<H", 8 * hl), getattr(hashlib, h)).digest()
    check(k.kdf(h, key20, a, b, 8 * hl) == d1, "KDF-%s：第 1 块 = HMAC(计数 1 小端 ‖ 标签 ‖ 上下文 ‖ 比特数小端)" % h.upper())
d256 = k.kdf("sha256", key20, a, b, 384)
check(len(d256) == 48 and d256[:32] == hmac.new(key20, struct.pack("<H", 1) + a + b + struct.pack("<H", 384), hashlib.sha256).digest()
      and d256[32:] == hmac.new(key20, struct.pack("<H", 2) + a + b + struct.pack("<H", 384), hashlib.sha256).digest()[:16], "KDF-SHA256 输出 384 比特：第 2 块用计数 2，截断")
check(k.kdf("sha256", key20, a, b, 128) != k.kdf("sha256", key20, a, b, 256)[:16], "输出长度（比特数）也混进了 HMAC：同一个前缀不相等")
for nb in (130, 132, 7):
    try:
        k.kdf("sha256", key20, a, b, nb)
        check(False, "比特数 %d 应报错" % nb)
    except ValueError:
        check(True, "输出比特数 %d 不是 8 的倍数：ValueError（132 是 4 的倍数，也不行）" % nb)

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
