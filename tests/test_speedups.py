#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""提速改动的等价性：CCM / GCM 的 CTR 批量密钥流、整数异或、AES 对象复用，对照直接照算法写的慢实现（每块一个新 AES 对象、逐字节异或），
各种长度（空、不满一块、整块、跨块）和 GCM 计数器低 32 位回绕；iter_frames 给路径和给读好的抓包结果相同；mac_str 同一个地址返回同一个对象。"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from Crypto.Cipher import AES  # noqa: E402
from wifi80211 import capture, crypto, frames, parser  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def slow_block(key, block):
    return AES.new(bytes(key), AES.MODE_ECB).encrypt(bytes(block))


def slow_xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def slow_ccm_ctr(key, nonce, data, l, start):
    out = bytearray()
    for i in range(0, len(data), 16):
        out += slow_xor(data[i:i + 16], slow_block(key, bytes([l - 1]) + nonce + (start + i // 16).to_bytes(l, "big")))
    return bytes(out)


def slow_gcm_ctr(key, j0, data):
    out = bytearray()
    ctr = int.from_bytes(j0, "big")
    for i in range(0, len(data), 16):
        ctr = (ctr & ~0xFFFFFFFF) | ((ctr + 1) & 0xFFFFFFFF)
        out += slow_xor(data[i:i + 16], slow_block(key, ctr.to_bytes(16, "big")))
    return bytes(out)


KEY16, KEY32 = bytes(range(16)), bytes(range(32))
LENGTHS = (0, 1, 15, 16, 17, 31, 32, 33, 100, 1500)

# 异或：长度不等取短的（和 zip 一样），空的是空的
check(crypto._xor(b"", b"") == b"" and crypto._xor(b"\xff\x00", b"\x0f") == b"\xf0", "异或：空串、长度不等取短的")
check(crypto._xor(b"\x00\x00\x01", b"\x00\x00\x00") == b"\x00\x00\x01", "异或：前导零不丢（结果长度固定）")

DATA = (bytes(range(256)) * 6)[:1500]
for key in (KEY16, KEY32):
    bad = [n for n in LENGTHS if crypto._ccm_ctr(key, b"N" * 13, DATA[:n], 2, 1) != slow_ccm_ctr(key, b"N" * 13, DATA[:n], 2, 1)]
    check(not bad, "CCM CTR（密钥 %d 字节）各种长度和慢实现逐字节相同%s" % (len(key), "" if not bad else "，不同的长度：%s" % bad))

bad = [n for n in LENGTHS if crypto._ccm_ctr(KEY16, b"N" * 13, b"\xa5" * n, 2, 0) != slow_ccm_ctr(KEY16, b"N" * 13, b"\xa5" * n, 2, 0)]
check(not bad, "CCM CTR 从计数 0 开始（算 MIC 用的 S0 那一块）也相同")

for j0 in (b"\x01" * 12 + b"\x00\x00\x00\x01", b"\x02" * 12 + b"\xff\xff\xff\xfe", b"\x03" * 12 + b"\xff\xff\xff\xff"):
    bad = [n for n in LENGTHS if crypto._gcm_ctr(KEY32, j0, b"\x5a" * n) != slow_gcm_ctr(KEY32, j0, b"\x5a" * n)]
    check(not bad, "GCM CTR 计数器 …%s（含低 32 位回绕）各种长度相同" % j0[-4:].hex())

# 整条 CCM / GCM 往返还要能认出被改过的数据（批量密钥流不能把校验搞丢）
ct = crypto.ccm_encrypt(KEY16, b"N" * 13, b"aad", b"hello world" * 5)
check(crypto.ccm_decrypt(KEY16, b"N" * 13, b"aad", ct) == (b"hello world" * 5, True), "CCM 往返")
check(crypto.ccm_decrypt(KEY16, b"N" * 13, b"aad", ct[:-1] + bytes([ct[-1] ^ 1]))[1] is False, "CCM 改一位 MIC 就不通过")
check(crypto.ccm_decrypt(KEY16, b"N" * 13, b"aae", ct)[1] is False, "CCM 改 AAD 就不通过")
gt = crypto.gcm_encrypt(KEY32, b"I" * 12, b"aad", b"x" * 77)
check(crypto.gcm_decrypt(KEY32, b"I" * 12, b"aad", gt) == (b"x" * 77, True), "GCM 往返")
check(crypto.gcm_decrypt(KEY32, b"I" * 12, b"aad", gt[:-1] + bytes([gt[-1] ^ 1]))[1] is False, "GCM 改一位 tag 就不通过")

# AES 对象复用：同一把密钥同一个对象，不同密钥互不串
check(crypto._ecb(KEY16) is crypto._ecb(bytes(KEY16)), "同一把密钥复用同一个 AES 对象")
check(crypto.aes_block(KEY16, b"\x00" * 16) != crypto.aes_block(bytes(16), b"\x00" * 16) and
      crypto.aes_block(bytes(16), b"\x00" * 16) == slow_block(bytes(16), b"\x00" * 16), "不同密钥的结果不串")

# mac_str：同一个地址是同一个对象，输入可以是 bytes / bytearray / memoryview
a, b = parser.mac_str(b"\x00\x11\x22\x33\x44\x55"), parser.mac_str(bytearray(b"\x00\x11\x22\x33\x44\x55"))
check(a == "00:11:22:33:44:55" and a is b, "mac_str 格式正确，同一个地址返回同一个对象")
check(parser.mac_str(memoryview(b"\xff" * 6)) == "ff:ff:ff:ff:ff:ff", "mac_str 接受 memoryview")

# iter_frames：路径和读好的抓包结果一样
dot11 = struct.pack("<HH", 0x0008 | 0x4000 | 0x0100, 0) + bytes.fromhex("112233445566") + bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + b"\x00\x00" + b"\x01" * 20
pcap = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
for i in range(3):
    pcap += struct.pack("<IIII", 100 + i, 0, len(dot11), len(dot11)) + dot11
import tempfile  # noqa: E402
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "a.pcap")
    open(p, "wb").write(pcap)
    from_path = list(frames.iter_frames(p))
    from_cap = list(frames.iter_frames(capture.read_capture(p)))
check(len(from_path) == 3 and from_path == from_cap, "iter_frames 给路径和给读好的抓包结果完全相同（3 帧）")

print("\n结果: %s" % ("全部通过（0 项失败）" if not failures else "存在失败（%d 项）" % len(failures)))
sys.exit(1 if failures else 0)
