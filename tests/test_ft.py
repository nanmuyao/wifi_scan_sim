#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ft80211：快速切换密钥层级。没有公开的标准向量，所以用真实抓包里的值做已知答案：
  wpa2-ft-eap（SHA-256）：M2 的 PMKID 就是真实设备算出的 PMKR1Name，tshark 也打出了 KCK / TK；
  wpa3-ft-sae-ext-key-group20（SHA-384）：整个 PTK 用真实 M2 的 MIC 验证过（tshark 4.4 对它没有答案）。
再加上哈希 / 标签 / 输入顺序的结构测试（每个输入变了结果都得变）。真实抓包的端到端对照在 tests/oracle/test_handshake_oracle.py。"""
import hashlib
import hmac
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import ft80211 as ft  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


H = bytes.fromhex
STA, BSSID = H("020000000200"), H("020000000100")
print("== 已知答案：wpa2-ft-eap（SHA-256，XXKey = MSK 的第二个 256 比特）==")
XX = H("b1471711baffb8611b28d2a09cc1a6aaffbbfdf3cccf12db57f175c53bfe2b7b")
r0, r0n = ft.derive_r0(XX, "sha256", b"wireshark-ft-eap", H("0102"), b"wireshark.ft.eap.test", STA)
r1, r1n = ft.derive_r1(r0, "sha256", r0n, H("020000000100"), STA)
check(r1n == H("add04faca3d8c0b0d98d04572589ec20"), "PMKR1Name = 真实 M2 里的 PMKID（add04fac…）")
check(r1.hex() == "72ae225213f93eb765fdf6d504155f840a3d4b26e4b23b52d24fec8657326bb6", "PMK-R1")
an = H("ccf4aabc222c76f53a63aaae75de944571a52c20c79bb9d512c4b6d23148cd61")
sn = H("b3a06e16f652af81e30f38f998aba78fb5db3daff6110fd59d09f9053070fee3")
kck, kek, tk = ft.derive_ptk(r1, "sha256", sn, an, BSSID, STA, 16, 16, 16)
check((kck.hex(), tk.hex()) == ("61ed670efdd76e7ff1c342c9816515dc", "65471b64605bf2a04af296284cb4ae2a"), "KCK 和 TK = tshark 打出的值")
check(kek.hex() == "be538fc279c069b8f53853f01ec0c562", "KEK（被 M3 的 Key Data 解包验证过）")

print("== 已知答案：wpa3-ft-sae-ext-key-group20（SHA-384，AKM 25）==")
XX = H("2951faa09bf248ce29a468fb0e8afeb7e5e0ba13e5e74ce6300c9c27dafbc0a26edc0d8019d8bd29367a4085097c44f9")
STA2, BSS2 = H("020000000000"), H("020000000300")
r0, r0n = ft.derive_r0(XX, "sha384", b"test-ft", H("a1b2"), b"nas1.w1.fi", STA2)
r1, r1n = ft.derive_r1(r0, "sha384", r0n, H("000102030405"), STA2)
check(len(r0) == 48 and len(r1) == 48 and len(r0n) == 16 and len(r1n) == 16, "SHA-384：PMK-R0 / PMK-R1 各 48 字节，名字 16 字节")
an = H("f3b009ef3c3c7d0c0050492ae9b0841b3253708fcd5e0f120d8f677c4bcad079")
sn = H("c9f20e09d44b7b0e1f78f424a75923b0d20704a42140194588c8e238f1d34c2b")
kck, kek, tk = ft.derive_ptk(r1, "sha384", sn, an, BSS2, STA2, 24, 32, 16)
check(r1.hex() == "76a34565aa3f6949d38811ae47ec8be6ff0fa508836b5f36882ddfce9bc47d51ee78c4ed8fd0f1cd7e45ca5428a57169", "PMK-R1（真实 M2 的 PMKR1Name 与 MIC 都吻合）")
check((kck.hex(), kek.hex(), tk.hex()) == ("bf5feec8fc2b40ad7f06c091fe6045c897e4ab7776d55edb", "75d4fa4f18c494c38c447e2823eb959a092596506909c0775cda5d461ec6899c", "f6477a5a12c6be6fd59832069d25c075"),
      "PTK：KCK 24 字节、KEK 32 字节、TK 16 字节")

print("== 结构：和用 hmac 手写的公式一致，输入各自起作用 ==")


def kdf(h, key, label, ctx, nbits):
    out, i = b"", 1
    while len(out) * 8 < nbits:
        out += hmac.new(key, struct.pack("<H", i) + label + ctx + struct.pack("<H", nbits), getattr(hashlib, h)).digest()
        i += 1
    return out[:nbits // 8]


K, SSID, MDID, R0KH, R1KH = bytes(range(32)), b"net", b"\x01\x02", b"r0", H("0a0b0c0d0e0f")
d = kdf("sha256", K, b"FT-R0", bytes([3]) + SSID + MDID + bytes([2]) + R0KH + STA, 384)
exp_r0, exp_name = d[:32], hashlib.sha256(b"FT-R0N" + d[32:]).digest()[:16]
got_r0, got_name = ft.derive_r0(K, "sha256", SSID, MDID, R0KH, STA)
check((got_r0, got_name) == (exp_r0, exp_name), "R0：长度前缀的上下文、384 比特输出拆成 PMK-R0 与盐、名字 = 前 128 比特 SHA-256(\"FT-R0N\" ‖ 盐)")
exp_r1 = kdf("sha256", exp_r0, b"FT-R1", R1KH + STA, 256)
exp_n1 = hashlib.sha256(b"FT-R1N" + exp_name + R1KH + STA).digest()[:16]
check(ft.derive_r1(exp_r0, "sha256", exp_name, R1KH, STA) == (exp_r1, exp_n1), "R1：上下文 R1KH-ID ‖ S1KH-ID，名字 = SHA-256(\"FT-R1N\" ‖ PMKR0Name ‖ R1KH-ID ‖ S1KH-ID) 的前 128 比特")
SN, AN = bytes(range(32)), bytes(range(32, 64))
exp = kdf("sha256", exp_r1, b"FT-PTK", SN + AN + BSSID + STA, 384)
check(ft.derive_ptk(exp_r1, "sha256", SN, AN, BSSID, STA, 16, 16, 16) == (exp[:16], exp[16:32], exp[32:]), "PTK：上下文 SNonce ‖ ANonce ‖ BSSID ‖ STA，输出按 KCK ‖ KEK ‖ TK 切")
base = ft.derive_ptk(exp_r1, "sha256", SN, AN, BSSID, STA, 16, 16, 16)
check(ft.derive_ptk(exp_r1, "sha256", AN, SN, BSSID, STA, 16, 16, 16) != base, "Nonce 顺序不能换")
check(ft.derive_ptk(exp_r1, "sha256", SN, AN, STA, BSSID, 16, 16, 16) != base, "地址顺序不能换（BSSID 在前，不是排大小）")
check(ft.derive_ptk(exp_r1, "sha256", SN, AN, BSSID, STA, 16, 16, 32)[0] != base[0], "输出长度进入 KDF（Length 字段）：TK 变长（CCMP-256）整个 PTK 都不同，KCK 也变")
for i, (nm, args) in enumerate((("SSID", (K, "sha256", b"nex", MDID, R0KH, STA)), ("MDID", (K, "sha256", SSID, b"\x01\x03", R0KH, STA)),
                                ("R0KH-ID", (K, "sha256", SSID, MDID, b"r1", STA)), ("STA", (K, "sha256", SSID, MDID, R0KH, BSSID)), ("XXKey", (K[::-1], "sha256", SSID, MDID, R0KH, STA)))):
    check(ft.derive_r0(*args) != (exp_r0, exp_name), "R0 的输入「%s」变了，结果变" % nm)
check(ft.derive_r1(exp_r0, "sha256", exp_name, H("0a0b0c0d0e00"), STA)[0] != exp_r1 and ft.derive_r1(exp_r0, "sha256", exp_name, R1KH, BSSID)[0] != exp_r1, "R1 的 R1KH-ID / STA 变了，结果变")
check(ft.derive_r0(K, "sha384", SSID, MDID, R0KH, STA)[0] != exp_r0 and len(ft.derive_r0(K, "sha512", SSID, MDID, R0KH, STA)[0]) == 64, "哈希换成 SHA-384 / SHA-512：结果和长度跟着变")
check(ft.DIGEST_LEN == {"sha256": 32, "sha384": 48, "sha512": 64}, "摘要长度表")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
