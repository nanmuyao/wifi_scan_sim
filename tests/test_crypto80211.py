#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""crypto80211 的原语测试：官方向量 + 与 pycryptodome（独立实现）的随机交叉验证。
TKIP 的密钥混合没有可靠的独立向量，这里只测性质；它由 D4 用真实 TKIP 帧对照 tshark 验证。"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto80211 as c  # noqa: E402
from Crypto.Cipher import AES  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


H = bytes.fromhex
rnd = random.Random(80211)

print("== CCM ==")
key = H("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF")
nonce = H("00000003020100A0A1A2A3A4A5")
aad, pt = bytes(range(8)), bytes(range(8, 31))
want = H("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0")
check(c.ccm_encrypt(key, nonce, aad, pt, 8) == want, "RFC 3610 第 1 个向量（AES-128，M=8，L=2）加密")
check(c.ccm_decrypt(key, nonce, aad, want, 8) == (pt, True), "同一向量解密，MIC 通过")
bad = bytearray(want)
bad[-1] ^= 1
check(c.ccm_decrypt(key, nonce, aad, bytes(bad), 8)[1] is False, "MIC 改 1 位：不通过")
bad = bytearray(want)
bad[3] ^= 1
check(c.ccm_decrypt(key, nonce, aad, bytes(bad), 8)[1] is False, "密文改 1 位：不通过")
check(c.ccm_decrypt(key, nonce, aad + b"x", want, 8)[1] is False, "AAD 不同：不通过")
check(c.ccm_decrypt(key, nonce[:-1] + b"\x00", aad, want, 8)[1] is False, "nonce 不同：不通过")
n_ok = 0
for _ in range(120):
    klen, mlen = rnd.choice((16, 32)), rnd.choice((8, 16))
    k, nn, a, p = rnd.randbytes(klen), rnd.randbytes(13), rnd.randbytes(rnd.randrange(0, 40)), rnd.randbytes(rnd.randrange(0, 90))
    ref = AES.new(k, AES.MODE_CCM, nonce=nn, mac_len=mlen, msg_len=len(p), assoc_len=len(a))
    ref.update(a)
    ct, tag = ref.encrypt_and_digest(p)
    n_ok += c.ccm_encrypt(k, nn, a, p, mlen) == ct + tag and c.ccm_decrypt(k, nn, a, ct + tag, mlen) == (p, True)
check(n_ok == 120, "120 组随机输入（AES-128 / 256，M=8 / 16，AAD 0-39 字节，数据 0-89 字节）与 pycryptodome 的 CCM 逐字节一致")
n_ok = 0
for mlen in (8, 16):
    for k in (rnd.randbytes(16), rnd.randbytes(32)):
        for plen in (0, 1, 15, 16, 17, 33):
            nn, p = rnd.randbytes(13), rnd.randbytes(plen)
            ref = AES.new(k, AES.MODE_CCM, nonce=nn, mac_len=mlen, msg_len=plen, assoc_len=0)
            ct, tag = ref.encrypt_and_digest(p)
            n_ok += c.ccm_encrypt(k, nn, b"", p, mlen) == ct + tag
check(n_ok == 24, "AAD 为空（Adata 位不置）的 24 组与 pycryptodome 一致")
for bad_nonce in (b"", b"x" * 12, b"x" * 14):
    for fn in (lambda n: c.ccm_encrypt(key, n, b"", b"", 8), lambda n: c.ccm_decrypt(key, n, b"", bytes(8), 8)):
        try:
            fn(bad_nonce)
            check(False, "nonce %d 字节应报错" % len(bad_nonce))
        except ValueError as e:
            check("nonce" in str(e), "nonce %d 字节：ValueError，报的是 nonce 的问题（不是 AES 层的错）" % len(bad_nonce))
try:
    c.ccm_decrypt(key, nonce, b"", b"abc", 8)
    check(False, "数据比 MIC 短应报错")
except ValueError:
    check(True, "数据比 MIC 短：ValueError")

print("== GCM ==")
z16, z12 = bytes(16), bytes(12)
check(c.gcm_encrypt(z16, z12, b"", b"") == H("58e2fccefa7e3061367f1d57a4e7455a"), "NIST 测试用例 1（空明文）的 tag")
check(c.gcm_encrypt(z16, z12, b"", z16) == H("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"), "NIST 测试用例 2 的密文 + tag")
k3 = H("feffe9928665731c6d6a8f9467308308")
iv3 = H("cafebabefacedbaddecaf888")
p3 = H("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
c3 = H("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985") + H("4d5c2af327cd64a62cf35abd2ba6fab4")
check(c.gcm_encrypt(k3, iv3, b"", p3) == c3, "NIST 测试用例 3（64 字节明文）")
check(c.gcm_decrypt(k3, iv3, b"", c3) == (p3, True), "解密，tag 通过")
check(c.gcm_decrypt(k3, iv3, b"x", c3)[1] is False and c.gcm_decrypt(k3, iv3, b"", c3[:-1] + b"\x00")[1] is False, "AAD 不同 / tag 改动：不通过")
n_ok = 0
for _ in range(120):
    klen = rnd.choice((16, 32))
    k, iv, a, p = rnd.randbytes(klen), rnd.randbytes(12), rnd.randbytes(rnd.randrange(0, 40)), rnd.randbytes(rnd.randrange(0, 90))
    ref = AES.new(k, AES.MODE_GCM, nonce=iv)
    ref.update(a)
    ct, tag = ref.encrypt_and_digest(p)
    n_ok += c.gcm_encrypt(k, iv, a, p) == ct + tag and c.gcm_decrypt(k, iv, a, ct + tag) == (p, True)
check(n_ok == 120, "120 组随机输入（AES-128 / 256）与 pycryptodome 的 GCM 逐字节一致")
try:
    c.gcm_encrypt(z16, b"x" * 13, b"", b"")
    check(False, "IV 13 字节应报错")
except ValueError:
    check(True, "IV 不是 12 字节：ValueError")

print("== RC4 / CRC-32 / WEP ==")
check(c.rc4(H("0102030405"), bytes(16)) == H("b2396305f03dc027ccc3524a0a1118a8"), "RFC 6229：密钥 0102030405 的前 16 字节密钥流")
check(c.rc4(b"Key", b"Plaintext") == H("BBF316E8D940AF0AD3"), "常用向量：Key / Plaintext")
check(c.crc32(b"123456789") == 0xCBF43926 and c.crc32(b"") == 0, "CRC-32 的标准校验值 0xCBF43926")
iv, wkey = H("a1b2c3"), H("1234567890")
frame = c.wep_encrypt(wkey, iv, 2, b"hello wep world")
check(frame[:3] == iv and frame[3] == 0x80 and len(frame) == 4 + 15 + 4, "WEP 帧：IV(3) + 密钥序号(1，高 2 位)；密文长度 = 数据 + 4 字节 ICV")
check(c.wep_decrypt(wkey, frame) == (b"hello wep world", 2, True), "解密：明文、密钥序号 2、ICV 通过")
check(c.wep_decrypt(H("1234567891"), frame)[2] is False, "密钥不对：ICV 不通过")
t = bytearray(frame)
t[6] ^= 1
check(c.wep_decrypt(wkey, bytes(t))[2] is False, "密文改 1 位：ICV 不通过")
check(c.wep_decrypt(wkey, c.wep_encrypt(wkey, iv, 0, b""))[0] == b"", "空数据也行")

print("== Michael ==")
# 802.11i 附录 H 的向量是链式的：每一步的密钥是上一步的输出
chain = [(b"", "82925c1ca1d130b8"), (b"M", "434721ca40639b3f"), (b"Mi", "e8f9becae97e5d29"), (b"Mic", "90038fc6cf13c1db"),
         (b"Mich", "d55e100510128986"), (b"Michael", "0a942b124ecaa546")]
mk = bytes(8)
for m, want in chain:
    got = c.michael(mk, m)
    check(got.hex() == want, "Michael(密钥 %s, %r) = %s" % (mk.hex(), m, want))
    mk = got
mk = H("82925c1ca1d130b8")
check(c.michael(mk, b"abc") != c.michael(mk, b"abd") and c.michael(mk, b"abc") != c.michael(H("82925c1ca1d130b9"), b"abc"), "消息或密钥改 1 位：MIC 不同")
check(c.tkip_michael_input(b"D" * 6, b"S" * 6, 5, b"xyz") == b"DDDDDDSSSSSS\x05\x00\x00\x00xyz", "Michael 输入：DA ‖ SA ‖ 优先级 ‖ 000 ‖ 数据")

print("== TKIP ==")
check(c.TKIP_SBOX[:4] == [0xC6A5, 0xF884, 0xEE99, 0xF68D] and len(c.TKIP_SBOX) == 256, "TKIP S 盒前 4 项 C6A5 F884 EE99 F68D（标准表）")
check(all((e >> 8) == ((c._AES_S[i] << 1) ^ (0x11B if c._AES_S[i] & 0x80 else 0)) & 255 and (e & 255) == (e >> 8) ^ c._AES_S[i] for i, e in enumerate(c.TKIP_SBOX)),
      "每一项 = (2·S(i)) 在高字节、(3·S(i)) 在低字节")
check(c._AES_S[:4] == [0x63, 0x7C, 0x77, 0x7B] and c._AES_S[255] == 0x16 and len(set(c._AES_S)) == 256, "AES S 盒：63 7c 77 7b …，最后一项 0x16，256 项互不相同")
tk, ta = bytes(range(16)), H("0002b3010203")
p1 = c.tkip_phase1(tk, ta, 0x12345678)
check(len(p1) == 5 and all(0 <= v < 65536 for v in p1) and p1 == c.tkip_phase1(tk, ta, 0x12345678) and p1 != c.tkip_phase1(tk, ta, 0x12345679), "第 1 阶段：5 个 16 位字，确定性，TSC 高位变了结果变")
seed = c.tkip_phase2(tk, p1, 0xABCD)
check(len(seed) == 16 and seed[0] == 0xAB and seed[2] == 0xCD and seed[1] == (0xAB | 0x20) & 0x7F, "第 2 阶段：种子前 3 字节是 TSC1、(TSC1|0x20)&0x7f、TSC0")
check(seed != c.tkip_phase2(tk, p1, 0xABCE) and seed != c.tkip_phase2(bytes(range(1, 17)), p1, 0xABCD), "TSC 低位或 TK 变了：种子不同")
check(c.tkip_rc4_seed(tk, ta, 0x12345678ABCD) == seed, "tkip_rc4_seed = 第 1 阶段（TSC 高 32 位）+ 第 2 阶段（低 16 位）")
plain = b"\xaa\xaa\x03\x00\x00\x00\x08\x00hello" + c.michael(mk, b"msg")
enc = c.tkip_encrypt(tk, ta, 0x0000_0001_0002, 1, plain)
dec, tsc, ok = c.tkip_decrypt(tk, ta, enc)
check((dec, tsc, ok) == (plain, 0x0000_0001_0002, True), "加密再解密：明文、TSC、ICV 通过")
check(enc[:4] == bytes([0x00, enc[1], 0x02, 0x60]) and enc[4:8] == bytes([1, 0, 0, 0]), "TKIP 头：TSC1 WEPSeed TSC0 (ExtIV | 密钥序号 << 6) TSC2-5")
check(c.tkip_decrypt(tk, H("0002b3010204"), enc)[2] is False and c.tkip_decrypt(bytes(range(1, 17)), ta, enc)[2] is False, "发送方地址或 TK 不对：ICV 不通过")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
