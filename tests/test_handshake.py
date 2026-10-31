#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""handshake80211：MIC 算法（RFC 2202 / 4231 向量）、PTK 推导的结构、候选 PMK、MLD 地址，以及用合成握手测追踪流程的接线。
推导本身是否正确由真实抓包验证（tests/oracle/test_handshake_oracle.py：23 个握手 MIC 自证 + tshark 的 KCK / TK）。"""
import hashlib
import os
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "oracle"))
from wifi80211 import eapol  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import handshake as hs  # noqa: E402
from wifi80211 import ft as ft80211  # noqa: E402
from wifi80211 import groupkeys as gk  # noqa: E402
from wifi80211 import kdf  # noqa: E402
from wifi80211 import ie  # noqa: E402
import synth  # noqa: E402
import wpa2_handshake as old  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


H = bytes.fromhex

print("== MIC 算法（RFC 2202 / RFC 4231 的第 1 个向量：密钥 0x0b…，数据 \"Hi There\"）==")
check(hs.compute_mic("hmac-md5", b"\x0b" * 16, b"Hi There", 16).hex() == "9294727a3638bb1c13f48ef8158bfc9d", "HMAC-MD5")
check(hs.compute_mic("hmac-sha1", b"\x0b" * 20, b"Hi There", 16).hex() == "b617318655057264e28bc0b6fb378c8e", "HMAC-SHA1（取前 16 字节）")
check(hs.compute_mic("hmac-sha256", b"\x0b" * 20, b"Hi There", 16).hex() == "b0344c61d8db38535ca8afceaf0bf12b", "HMAC-SHA256（取前 16 字节）")
check(hs.compute_mic("hmac-sha384", b"\x0b" * 20, b"Hi There", 24).hex() == "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec6", "HMAC-SHA384（取前 24 字节）")
check(hs.compute_mic("hmac-sha512", b"\x0b" * 20, b"Hi There", 32).hex() == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde", "HMAC-SHA512（取前 32 字节）")
key = H("2b7e151628aed2a6abf7158809cf4f3c")
check(hs.compute_mic("cmac", key, H("6bc1bee22e409f96e93d7e117393172a"), 16).hex() == "070a16b46b4d4144f79bdd9dd04a287c", "AES-128-CMAC（RFC 4493）")
try:
    hs.compute_mic("rot13", key, b"", 16)
    check(False, "不认识的算法应报错")
except ValueError:
    check(True, "不认识的 MIC 算法：ValueError")

print("== MIC 算法的选择 ==")
for args, want in (((1, 16, 2), "hmac-md5"), ((2, 16, 2), "hmac-sha1"), ((3, 16, 6), "cmac"), ((0, 16, 8), "cmac"), ((0, 16, 18), "hmac-sha256"),
                   ((0, 24, 18), "hmac-sha384"), ((0, 32, 18), "hmac-sha512"), ((0, 24, 12), "hmac-sha384"), ((0, 16, 24), "hmac-sha256"),
                   ((0, 32, 24), "hmac-sha512"), ((0, 20, 18), None), ((0, 16, 9), "cmac"), ((3, 16, 4), "cmac"), ((0, 24, 25), "hmac-sha384")):
    check(hs.mic_algorithm(*args) == want, "描述符版本 %d、MIC %d 字节、AKM %s -> %s" % (args + (want,)))

print("== msk 的偏移（快速切换的 802.1X 取第二个 256 比特）==")
check(hs.candidate_pmks([("msk", bytes(range(64)).hex())], None, 32, 32)[0][1] == bytes(range(32, 64)), "msk_offset = 32：取后 32 字节")
check(hs.candidate_pmks([("msk", bytes(range(64)).hex())], None, 48, 32) == [] and len(hs.candidate_pmks([("msk", bytes(range(80)).hex())], None, 48, 32)[0][1]) == 48, "偏移加长度超过 msk 长度：不取；够长：取 48 字节")
check(hs.FT_MSK_OFFSET == {3: 32, 13: 32} and set(hs.FT_HASH) == set(hs.FT_AKMS) == set(hs.FT_XXKEY_LEN), "快速切换的 AKM 表：哈希、XXKey 长度、msk 偏移的键一致")

print("== PTK 推导的结构 ==")
pmk, aa, spa = bytes(range(32)), H("020000000001"), H("020000000002")
an, sn = bytes([1]) * 32, bytes([2]) * 32
k1 = hs.derive_ptk(pmk, aa, spa, an, sn, "sha1", 16, 16, 16)
check([len(x) for x in k1] == [16, 16, 16], "KCK 16、KEK 16、TK 16 字节")
check(hs.derive_ptk(pmk, spa, aa, sn, an, "sha1", 16, 16, 16) == k1, "地址和 nonce 的顺序对调：结果相同（上下文取 min / max）")
check(hs.derive_ptk(pmk, aa, spa, an, bytes([3]) * 32, "sha1", 16, 16, 16) != k1 and hs.derive_ptk(pmk, aa, H("020000000003"), an, sn, "sha1", 16, 16, 16) != k1, "nonce 或地址变了：结果不同")
k2 = hs.derive_ptk(pmk, aa, spa, an, sn, "sha1", 16, 16, 32)
check(k2[0] == k1[0] and k2[1] == k1[1] and k2[2][:16] == k1[2] and len(k2[2]) == 32, "TK 长度 32（TKIP / 256 位套件）：KCK / KEK / TK 前 16 字节与 16 字节时一致")
k3 = hs.derive_ptk(pmk, aa, spa, an, sn, "sha256", 16, 16, 16)
check(k3 != k1, "SHA-256 的 KDF 和 SHA-1 的 PRF 结果不同")
k4 = hs.derive_ptk(bytes(48), aa, spa, an, sn, "sha384", 24, 32, 32)
check([len(x) for x in k4] == [24, 32, 32], "SHA-384 档：KCK 24、KEK 32、TK 32 字节")
check(hs.KEY_LENGTHS == {"sha1": (16, 16), "sha256": (16, 16), "sha384": (24, 32), "sha512": (32, 32)}, "各哈希档位的 KCK / KEK 长度")
check(hs.CIPHERS[2] == ("TKIP", 32) and hs.CIPHERS[4][1] == 16 and hs.CIPHERS[10][1] == 32 and hs.CIPHERS[9][1] == 32 and hs.CIPHERS[8][1] == 16, "各密码套件的 TK 长度：TKIP 32、CCMP-128 16、GCMP-128 16、CCMP-256 / GCMP-256 32")

print("== 候选 PMK ==")
std = hs.candidate_pmks([("wpa-pwd", "password:IEEE")], None, 32)
check(len(std) == 1 and std[0][1].hex() == old.PMK_STD_VECTOR, "口令 password + SSID IEEE = 802.11i 标准向量 f42c6fc5…")
check(hs.candidate_pmks([("wpa-pwd", "password")], b"IEEE", 32)[0][1] == std[0][1], "口令里没带 SSID：用抓包里看到的")
check(hs.candidate_pmks([("wpa-pwd", "password:Other")], b"IEEE", 32)[0][1] != std[0][1], "口令里带了 SSID：以它为准，不用抓包里的")
check(hs.candidate_pmks([("wpa-pwd", "password")], None, 32) == [], "没有 SSID 也没写：不能推 PMK")
check(hs.candidate_pmks([("wpa-pwd", "password:IEEE")], None, 48) == [], "口令只能推 32 字节的 PMK：要 48 字节的哈希档位不用口令")
check([k[1] for k in hs.candidate_pmks([("wpa-psk", "ab" * 32), ("wpa-psk", "cd" * 48), ("wpa-psk", "ef" * 64), ("wpa-psk", "zz" * 32)], None, 32)] == [H("ab" * 32)],
      "wpa-psk：只取长度对得上的（32 字节），16 进制不合法的跳过")
check([k[1] for k in hs.candidate_pmks([("wpa-psk", "cd" * 48)], None, 48)] == [H("cd" * 48)] and hs.candidate_pmks([("wpa-psk", "ef" * 64)], None, 64)[0][1] == H("ef" * 64), "48 字节（SHA-384）、64 字节（SHA-512）的 PMK")
check(hs.candidate_pmks([("msk", bytes(range(64)).hex())], None, 32)[0][1] == bytes(range(32)), "msk（64 字节）：取前 32 字节（不是后 32 字节）")
check(hs.candidate_pmks([("msk", bytes(range(64)).hex())], None, 48)[0][1] == bytes(range(48)), "msk 取前 48 字节（SHA-384 档的 PMK 长度）")
check(hs.candidate_pmks([("msk", "01" * 16)], None, 32) == [] and hs.candidate_pmks([("wep", "1234567890")], b"x", 32) == [], "msk 太短、wep：不是 PMK")
check(len(hs.candidate_pmks([("wpa-pwd", "a"), ("wpa-psk", "ab" * 32), ("msk", "01" * 64)], b"s", 32)) == 3, "三种来源都给：三个候选，顺序同密钥表")

print("== 追踪（合成握手）==")
AP, STA = H("02aabbccdd01"), H("02aabbccdd02")


def mac(b):
    return ":".join("%02x" % x for x in b)


def with_addrs(a1, a2, a3, fn):
    old_a = (synth.A1, synth.A2, synth.A3)
    synth.A1, synth.A2, synth.A3 = a1, a2, a3
    try:
        return fn()
    finally:
        synth.A1, synth.A2, synth.A3 = old_a


def eapol_key(ki, nonce, replay, mic=bytes(16), data=b"", desc=2):
    body = bytes([desc]) + struct.pack(">HHQ", ki, 16, replay) + nonce + bytes(16) + bytes(8) + bytes(8) + mic + struct.pack(">H", len(data)) + data
    return bytes([2, 3]) + struct.pack(">H", len(body)) + body


LLC = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
SUITE = lambda t: b"\x00\x0f\xac" + bytes([t])      # noqa: E731


def rsn(akm=2, cipher=4):
    return ie_(48, struct.pack("<H", 1) + SUITE(cipher) + struct.pack("<H", 1) + SUITE(cipher) + struct.pack("<H", 1) + SUITE(akm) + struct.pack("<H", 0))


def ie_(i, d):
    return bytes([i, len(d)]) + d


def build(passphrase="password", ssid=b"IEEE", akm=2, cipher=4, replay2=None, key_data=None, version=2, ki2=None, rekey=False):
    """beacon + M1 + M2（MIC 用对应口令推出的 KCK 算好），返回 pcap 里的帧列表。"""
    an, sn = bytes([7]) * 32, bytes([9]) * 32
    pmk = hs.pmk_from_passphrase(passphrase, ssid)
    kdf_hash = hs.AKMS.get(akm, "sha1")
    kck_len, kek_len = hs.KEY_LENGTHS[kdf_hash]
    kck, _, _ = hs.derive_ptk(pmk, AP, STA, an, sn, kdf_hash, kck_len, kek_len, hs.CIPHERS.get(cipher, ("x", 16))[1])
    data = key_data if key_data is not None else rsn(akm, cipher)
    m2_ki = ki2 if ki2 is not None else 0x0100 | 0x0008 | version
    m2 = eapol_key(m2_ki, sn, 1 if replay2 is None else replay2, data=data)
    m2 = eapol.zero_mic(m2, 16)
    mic = hs.compute_mic(hs.mic_algorithm(version, 16, akm), kck, m2, 16)
    m2 = m2[:81] + mic + m2[97:]
    m1 = eapol_key(0x0088 | 0x0008 | version, an, 1)
    frames = [with_addrs(b"\xff" * 6, AP, AP, lambda: synth.frame(0, 8, body=bytes(12) + ie_(0, ssid))),
              with_addrs(STA, AP, AP, lambda: synth.frame(2, 0, 0, 1, body=LLC + m1)),
              with_addrs(AP, STA, AP, lambda: synth.frame(2, 0, 1, 0, body=LLC + m2))]
    if rekey:
        frames += frames[1:]
    return frames


def run(frames, keys):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "t.pcap")
        synth.write_pcap(path, frames)
        return hs.track(list(fr.iter_frames(path)), keys)


done, skipped = run(build(), [("wpa-pwd", "password")])
check(len(done) == 1 and not skipped, "口令 + 信标里的 SSID：握手成功")
h = done[0]
check((h.ap, h.sta, h.akm, h.cipher, h.mic_alg, h.mic_len, h.kdf) == (mac(AP), mac(STA), 2, "CCMP-128", "hmac-sha1", 16, "sha1"), "地址、AKM 2、CCMP-128、HMAC-SHA1、16 字节 MIC、PRF-SHA1")
check(h.pmk[0] == "wpa-pwd:password" and h.pmk[1] == hs.pmk_from_passphrase("password", b"IEEE") and len(h.kck) == 16 and len(h.kek) == 16 and len(h.tk) == 16, "用的是哪个候选、PMK、KCK / KEK / TK 的长度")
check(h.anonce == bytes([7]) * 32 and h.snonce == bytes([9]) * 32 and h.frames == {"m1": 2, "m2": 3}, "ANonce、SNonce、M1 / M2 的帧号（beacon 是第 1 帧）")
done, skipped = run(build(), [("wpa-pwd", "wrong"), ("wpa-psk", "00" * 32), ("wpa-pwd", "password")])
check(len(done) == 1 and done[0].pmk[0] == "wpa-pwd:password", "密钥表里有错的在前面：逐个试，MIC 吻合的那个胜出")
done, skipped = run(build(), [("wpa-pwd", "wrong")])
check(done == [] and skipped == [(3, "没有候选 PMK 让 M2 的 MIC 吻合")], "口令不对：失败，原因是没有候选让 MIC 吻合，指向 M2 的帧号")
done, skipped = run(build(replay2=5), [("wpa-pwd", "password")])
check(done == [] and skipped == [(3, "找不到与 Replay Counter 对应的 M1")], "M2 的 Replay Counter 与 M1 不同：找不到对应的 M1")
done, skipped = run(build(key_data=b""), [("wpa-pwd", "password")])
check(done == [] and skipped and "没有 RSN" in skipped[0][1], "M2 的 Key Data 里没有 RSN 元素：跳过并说明")
done, skipped = run(build(akm=4), [("wpa-pwd", "password")])
check(done == [] and skipped == [(3, "没有候选 PMK 让 M2 的 MIC 吻合")], "FT 的 AKM 4，但抓包里没有带移动域 / FTE 的关联响应：推不出 PMK-R0，失败并说明（真实的 FT 握手见 test_handshake_oracle）")
done, skipped = run(build(cipher=1), [("wpa-pwd", "password")])
check(done == [] and "不支持的 AKM 2 / 密码套件 1" in skipped[0][1], "不支持的密码套件（WEP-40）：跳过并说明")
done, skipped = run(build(akm=99), [("wpa-pwd", "password")])
check(done == [] and "不支持的 AKM 99" in skipped[0][1], "不认识的 AKM：跳过并说明")
done, _ = run(build(passphrase="secret", ssid=b"MyNet"), [("wpa-pwd", "secret")])
check(len(done) == 1, "SSID 不是 IEEE：照样从信标里取")
done, _ = run(build(passphrase="secret", ssid=b"MyNet"), [("wpa-pwd", "secret:MyNet")])
check(len(done) == 1, "口令带 SSID（口令:SSID）")
done, _ = run(build(rekey=True), [("wpa-pwd", "password")])
check(len(done) == 2 and done[0].kck == done[1].kck, "同一对设备握手两次（同样的 nonce，重传）：各自成功一次")
done, _ = run(build(cipher=2, version=1), [("wpa-pwd", "password")])
check(len(done) == 1 and done[0].cipher == "TKIP" and done[0].mic_alg == "hmac-md5" and len(done[0].tk) == 32, "TKIP + 描述符版本 1：HMAC-MD5，TK 32 字节")
done, _ = run(build(akm=6, version=3), [("wpa-pwd", "password")])
check(len(done) == 1 and done[0].mic_alg == "cmac" and done[0].kdf == "sha256", "AKM 6 + 版本 3：AES-CMAC，KDF-SHA256")
done, _ = run(build(cipher=10), [("wpa-pwd", "password")])
check(len(done) == 1 and done[0].cipher == "CCMP-256" and len(done[0].tk) == 32, "CCMP-256：TK 32 字节")
frames = build()
done, _ = run([frames[0], frames[2]], [("wpa-pwd", "password")])
check(done == [], "没有 M1 只有 M2：不成功")

print("== SSID 与 MLD 地址 ==")
bc = lambda sub, ssid: with_addrs(b"\xff" * 6, AP, AP, lambda: synth.frame(0, sub, body=bytes(ie.FIXED_LEN[sub]) + ie_(0, ssid)))      # noqa: E731
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "t.pcap")
    other = H("02aabbccdd09")
    synth.write_pcap(path, [with_addrs(b"\xff" * 6, other, other, lambda: synth.frame(0, 8, prot=1, body=bytes(12) + ie_(0, b"enc"))),
                            bc(8, b"First"), bc(5, b"Second"), with_addrs(b"\xff" * 6, other, other, lambda: synth.frame(0, 8, body=bytes(12) + ie_(0, b"")))])
    ss = hs.ssids_by_bssid(list(fr.iter_frames(path)))
    check(ss == {mac(AP): b"First", mac(other): b""}, "SSID 按 BSSID：同一个 BSSID 取第一个；隐藏网络是空串；受保护的帧不看")


def ml_el(mld, stas, fixed=b"\x00\x00"):
    body = struct.pack("<H", 0) + bytes([7]) + mld
    for lid, m in stas:
        info = bytes([7]) + m
        data = struct.pack("<H", lid | 0x10 | 0x20) + info + fixed
        body += bytes([0, len(data)]) + data
    return ie_(255, bytes([107]) + body)


MLD_A, MLD_B, LINK2 = H("0200000000aa"), H("0200000000bb"), H("0200000000cc")
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "t.pcap")
    req = with_addrs(AP, STA, AP, lambda: synth.frame(0, 0, body=bytes(4) + ml_el(MLD_A, [(1, LINK2)])))
    resp = with_addrs(STA, AP, AP, lambda: synth.frame(0, 1, body=bytes(6) + ml_el(MLD_B, [])))
    plain = with_addrs(STA, AP, AP, lambda: synth.frame(0, 1, body=bytes(6)))
    prot_req = with_addrs(AP, H("02aabbccdd77"), AP, lambda: synth.frame(0, 0, prot=1, body=bytes(4) + ml_el(MLD_B, [])))
    synth.write_pcap(path, [prot_req, req, resp, plain])
    m = hs.mld_addresses(list(fr.iter_frames(path)))
    check(m == {mac(STA): mac(MLD_A), mac(LINK2): mac(MLD_A), mac(AP): mac(MLD_B)}, "关联请求给发送方的 MLD 地址和它其它链路的地址；关联响应给 AP 的 MLD 地址；没有 Multi-Link 的帧不产生映射")

print("== ft_contexts：关联响应里的移动域和 FTE ==")
def fte_el(r0, r1):
    sub = (bytes([1, 6]) + r1 if r1 else b"") + (bytes([3, len(r0)]) + r0 if r0 else b"")
    return bytes([55, 2 + 16 + 64 + len(sub)]) + bytes(2 + 16 + 64) + sub


MDE = bytes([54, 3, 0x01, 0x02, 0x01])
R1 = H("020000000100")
good = with_addrs(STA, AP, AP, lambda: synth.frame(0, 1, body=bytes(6) + MDE + fte_el(b"r0kh-name", R1)))
no_r1 = with_addrs(STA, H("02aabbccdd01"), H("02aabbccdd01"), lambda: synth.frame(0, 1, body=bytes(6) + MDE + fte_el(b"r0", None)))
no_mde = with_addrs(STA, H("02aabbccdd02"), H("02aabbccdd02"), lambda: synth.frame(0, 1, body=bytes(6) + fte_el(b"r0", R1)))
reassoc = with_addrs(STA, H("02aabbccdd03"), H("02aabbccdd03"), lambda: synth.frame(0, 3, body=bytes(6) + MDE + fte_el(b"rr", R1)))
reqf = with_addrs(AP, STA, AP, lambda: synth.frame(0, 0, body=bytes(4) + MDE + fte_el(b"r0kh-name", R1)))
prot = with_addrs(STA, H("02aabbccdd04"), H("02aabbccdd04"), lambda: synth.frame(0, 1, prot=1, body=bytes(6) + MDE + fte_el(b"r0", R1)))
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "t.pcap")
    synth.write_pcap(path, [good, no_r1, no_mde, reassoc, reqf, prot])
    ctx = hs.ft_contexts(list(fr.iter_frames(path)))
check(set(ctx) == {(mac(AP), mac(STA)), (mac(H("02aabbccdd03")), mac(STA))}, "只收（重）关联响应；缺 R1KH-ID、缺移动域、关联请求、受保护的帧都不收；键 = (BSSID, STA)")
c = ctx[(mac(AP), mac(STA))]
check((c.mdid, c.r0kh_id, c.r1kh_id) == (H("0102"), b"r0kh-name", R1), "移动域 ID 取元素里的原始 2 字节；R0KH-ID、R1KH-ID 来自 FTE 子元素")

print("== 快速切换的初始握手（合成：关联响应带移动域 + FTE，M2 带 PMKID）==")
R0KH_ID, R1KH_ID_, MDID_ = b"r0kh.example", H("0a0b0c0d0e0f"), H("a1b2")
FT_SSID = b"ft-net"


def rsn_ft(akm, pmkid):
    body = struct.pack("<H", 1) + SUITE(4) + struct.pack("<H", 1) + SUITE(4) + struct.pack("<H", 1) + SUITE(akm) + struct.pack("<H", 0)
    if pmkid is not None:
        body += struct.pack("<H", 1) + pmkid
    return ie_(48, body)


def build_ft(akm, hash_name, xx, mic_len, version, pmkid="right", drop_ctx=False):
    """beacon + 关联响应（MDE + FTE）+ M1 + M2。哈希、XXKey 的取法由调用方按标准给出，这里只负责合成。"""
    an, sn = bytes([5]) * 32, bytes([6]) * 32
    n = ft80211.DIGEST_LEN[hash_name]
    kck_len, kek_len = hs.KEY_LENGTHS[hash_name]
    r0, r0n = ft80211.derive_r0(xx, hash_name, FT_SSID, MDID_, R0KH_ID, STA)
    r1, r1n = ft80211.derive_r1(r0, hash_name, r0n, R1KH_ID_, STA)
    kck, _, _ = ft80211.derive_ptk(r1, hash_name, sn, an, AP, STA, kck_len, kek_len, 16)
    pm = {"right": r1n, "wrong": bytes(16), "none": None}[pmkid]
    m2 = eapol_key(0x0100 | 0x0008 | version, sn, 1, mic=bytes(mic_len), data=rsn_ft(akm, pm))
    m2 = eapol.zero_mic(m2, mic_len)
    mic = hs.compute_mic(hs.mic_algorithm(version, mic_len, akm), kck, m2, mic_len)
    m2 = m2[:81] + mic + m2[81 + mic_len:]
    m1 = eapol_key(0x0088 | 0x0008 | version, an, 1, mic=bytes(mic_len))
    mde = bytes([54, 3]) + MDID_ + b"\x01"
    sub = bytes([1, 6]) + R1KH_ID_ + bytes([3, len(R0KH_ID)]) + R0KH_ID
    fte = bytes([55, 2 + mic_len + 64 + len(sub)]) + bytes(2 + mic_len + 64) + sub
    frames = [with_addrs(b"\xff" * 6, AP, AP, lambda: synth.frame(0, 8, body=bytes(12) + ie_(0, FT_SSID))),
              with_addrs(STA, AP, AP, lambda: synth.frame(0, 1, body=bytes(6) + (b"" if drop_ctx else mde + fte))),
              with_addrs(STA, AP, AP, lambda: synth.frame(2, 0, 0, 1, body=LLC + m1)),
              with_addrs(AP, STA, AP, lambda: synth.frame(2, 0, 1, 0, body=LLC + m2))]
    return frames


PSK32, MSK = bytes(range(32)), bytes(range(100, 180))
for akm, hash_name, xx, key, mic_len, ver, want_alg in (
        (4, "sha256", PSK32, ("wpa-psk", PSK32.hex()), 16, 3, "cmac"),
        (3, "sha256", MSK[32:64], ("msk", MSK.hex()), 16, 3, "cmac"),
        (9, "sha256", PSK32, ("wpa-psk", PSK32.hex()), 16, 0, "cmac"),
        (13, "sha384", MSK[32:80], ("msk", MSK.hex()), 24, 0, "hmac-sha384"),
        (19, "sha384", PSK32, ("wpa-psk", PSK32.hex()), 24, 0, "hmac-sha384"),
        (25, "sha256", PSK32, ("wpa-psk", PSK32.hex()), 16, 0, "hmac-sha256"),
        (25, "sha384", MSK[:48], ("wpa-psk", MSK[:48].hex()), 24, 0, "hmac-sha384"),
        (25, "sha512", MSK[:64], ("wpa-psk", MSK[:64].hex()), 32, 0, "hmac-sha512")):
    done, skipped = run(build_ft(akm, hash_name, xx, mic_len, ver), [key])
    ok = len(done) == 1 and not skipped
    h = done[0] if done else None
    check(ok and (h.akm, h.kdf, h.mic_alg, h.mic_len) == (akm, hash_name, want_alg, mic_len) and h.frames["pmkr1name_ok"] is True and len(h.kck) == hs.KEY_LENGTHS[hash_name][0],
          "AKM %d：%s，MIC %d 字节（%s），PMKID = PMKR1Name" % (akm, hash_name, mic_len, want_alg))
done, skipped = run(build_ft(4, "sha256", PSK32, 16, 3, pmkid="wrong"), [("wpa-psk", PSK32.hex())])
check(len(done) == 1 and done[0].frames["pmkr1name_ok"] is False, "M2 里的 PMKID 不是 PMKR1Name：握手仍成立（MIC 对），pmkr1name_ok 为 False")
done, skipped = run(build_ft(4, "sha256", PSK32, 16, 3, pmkid="none"), [("wpa-psk", PSK32.hex())])
check(len(done) == 1 and done[0].frames["pmkr1name_ok"] is False, "M2 没有 PMKID：pmkr1name_ok 为 False")
done, skipped = run(build_ft(4, "sha256", PSK32, 16, 3, drop_ctx=True), [("wpa-psk", PSK32.hex())])
check(done == [] and skipped == [(4, "没有候选 PMK 让 M2 的 MIC 吻合")], "关联响应里没有移动域 / FTE：推不出 PMK-R0，失败")
done, skipped = run(build_ft(3, "sha256", MSK[32:64], 16, 3), [("msk", MSK.hex()[:128]), ("wpa-psk", PSK32.hex())])
check(len(done) == 1, "FT-802.1X 的 XXKey 是 MSK 的第二个 256 比特（取前 256 比特的 MSK 推出的 PTK 对不上）")
done, skipped = run(build_ft(13, "sha384", MSK[32:80], 24, 0), [("msk", MSK[:64].hex())])
check(done == [], "AKM 13 的 XXKey 要 48 字节（MSK 的第 33-80 字节）：MSK 只有 64 字节时没有候选")

print("== 快速切换的空中漫游（合成：重关联请求的 FTE MIC）==")
NEW_AP, R1KH_NEW = H("02aabbccdd55"), H("02aabbccdd56")
RSNXE = ie_(244, b"\x20")


def roam_frame(akm, hash_name, xx, mic_len, rsnxe_used=True, bad_mic=False, r0kh=R0KH_ID, drop_rsnxe=False, no_fte=False, mdid=MDID_, r1kh=R1KH_NEW, bad_pmkid=False,
               drop_mde=False, drop_rsne=False, prot=0):
    """重关联请求：RSNE（PMKID = 新 AP 的 PMKR1Name）‖ MDE ‖ FTE ‖ [RSNXE]；MIC 由测试按标准独立算好（CMAC 用 pycryptodome）。"""
    from Crypto.Hash import CMAC
    from Crypto.Cipher import AES
    an, sn = bytes([21]) * 32, bytes([22]) * 32
    kck_len, kek_len = hs.KEY_LENGTHS[hash_name]
    r0, r0n = ft80211.derive_r0(xx, hash_name, FT_SSID, MDID_, R0KH_ID, STA)
    r1, r1n = ft80211.derive_r1(r0, hash_name, r0n, R1KH_NEW, STA)       # 密钥始终按「真」的 R1KH-ID 推；r1kh / mdid 参数只改帧里写的
    kck, _, _ = ft80211.derive_ptk(r1, hash_name, sn, an, NEW_AP, STA, kck_len, kek_len, 16)
    rsne = rsn_ft(akm, bytes(16) if bad_pmkid else r1n)
    mde = bytes([54, 3]) + mdid + b"\x01"
    sub = bytes([1, len(r1kh)]) + r1kh + bytes([3, len(r0kh)]) + r0kh
    ctrl = bytes([(1 if rsnxe_used else 0) | {16: 0, 24: 1, 32: 2}[mic_len] << 1, 3 + (1 if rsnxe_used else 0)])
    body = lambda mic: bytes([55, 2 + mic_len + 64 + len(sub)]) + ctrl + mic + an + sn + sub          # noqa: E731
    msg = STA + NEW_AP + b"\x05" + rsne + mde + body(bytes(mic_len)) + (RSNXE if rsnxe_used else b"")
    if akm in (3, 4, 9):
        mic = CMAC.new(kck, ciphermod=AES, msg=msg).digest()
    else:
        mic = hmac.new(kck, msg, getattr(hashlib, hash_name)).digest()[:mic_len]
    if bad_mic:
        mic = bytes(mic_len)
    elems = (b"" if drop_rsne else rsne) + (b"" if drop_mde else mde) + (b"" if no_fte else body(mic)) + (RSNXE if rsnxe_used and not drop_rsnxe else b"")
    return with_addrs(NEW_AP, STA, NEW_AP, lambda: synth.frame(0, 2, prot=prot, body=bytes(10) + elems)), r1, r1n


import hashlib  # noqa: E402
import hmac  # noqa: E402

for akm, hash_name, xx, key, mic_len, ver, rsnxe in (
        (4, "sha256", PSK32, ("wpa-psk", PSK32.hex()), 16, 3, False),
        (9, "sha256", PSK32, ("wpa-psk", PSK32.hex()), 16, 0, True),
        (25, "sha384", MSK[:48], ("wpa-psk", MSK[:48].hex()), 24, 0, True),
        (19, "sha384", PSK32, ("wpa-psk", PSK32.hex()), 24, 0, False)):
    init = build_ft(akm, hash_name, xx, mic_len, ver)
    rf, r1, r1n = roam_frame(akm, hash_name, xx, mic_len, rsnxe_used=rsnxe)
    done, skipped = run(init + [rf], [key])
    ok = len(done) == 2 and not skipped
    r = done[1] if ok else None
    check(ok and (r.ap, r.sta) == (mac(NEW_AP), mac(STA)) and r.pmk[1] == r1 and r.frames["roam"] and r.frames["pmkr1name_ok"] and r.ft["pmk_r0"] == done[0].ft["pmk_r0"] and r.kdf == hash_name,
          "AKM %d（%s）：漫游到新 AP，PMK-R1 / PMKR1Name 由同一个 PMK-R0 换了 R1KH-ID 推出，RSNXE %s" % (akm, hash_name, "在 MIC 里" if rsnxe else "不在"))
    bad, sk = run(init + [roam_frame(akm, hash_name, xx, mic_len, rsnxe_used=rsnxe, bad_mic=True)[0]], [key])
    check(len(bad) == 1 and sk and "空中漫游" in sk[0][1], "AKM %d：FTE 的 MIC 不对：不收，说明原因" % akm)
init = build_ft(9, "sha256", PSK32, 16, 0)
done, sk = run(init + [roam_frame(9, "sha256", PSK32, 16, rsnxe_used=True, drop_rsnxe=True)[0]], [("wpa-psk", PSK32.hex())])
check(len(done) == 1 and sk, "MIC Control 说用了 RSNXE，帧里却没有：不收")
done, sk = run(init + [roam_frame(9, "sha256", PSK32, 16, rsnxe_used=False)[0]], [("wpa-psk", PSK32.hex())])
check(len(done) == 2, "RSNXE 已用位没置：MIC 里不含 RSNXE，照样验证通过")
done, sk = run(init + [roam_frame(9, "sha256", PSK32, 16, no_fte=True)[0]], [("wpa-psk", PSK32.hex())])
check(len(done) == 1 and not sk, "没有 FTE 的重关联请求不是 FT 漫游：忽略，不当成失败")
done, sk = run(init + [roam_frame(9, "sha256", PSK32, 16, r0kh=b"other-r0kh")[0]], [("wpa-psk", PSK32.hex())])
check(len(done) == 1 and sk, "R0KH-ID 与初始握手的不同：找不到对应的 PMK-R0")
KEYS9 = [("wpa-psk", PSK32.hex())]
done, sk = run(init + [roam_frame(9, "sha256", PSK32, 16, mdid=H("c3d4"))[0]], KEYS9)
check(len(done) == 1 and sk, "重关联请求里的移动域 ID 与初始握手的不同（MIC 按帧里的算对）：不是同一个移动域，不收")
done, sk = run(init + [roam_frame(9, "sha256", PSK32, 16, r1kh=R1KH_NEW[:5])[0]], KEYS9)
check(len(done) == 1 and not sk, "R1KH-ID 不是 6 字节：不是合规的 FT 请求，忽略")
done, sk = run(init + [roam_frame(9, "sha256", PSK32, 16, bad_pmkid=True)[0]], KEYS9)
check(len(done) == 2 and done[1].frames["pmkr1name_ok"] is False, "RSNE 里的 PMKID 不是 PMKR1Name：MIC 对就收，pmkr1name_ok 为 False")
done, sk = run(init + [roam_frame(9, "sha256", PSK32, 16, drop_mde=True)[0]], KEYS9)
check(len(done) == 1 and not sk, "缺移动域元素：不是完整的 FT 请求，忽略")
done, sk = run(init + [roam_frame(9, "sha256", PSK32, 16, drop_rsne=True)[0]], KEYS9)
check(len(done) == 1 and not sk, "缺 RSNE：忽略")
done, sk = run(init + [roam_frame(9, "sha256", PSK32, 16, prot=1)[0]], KEYS9)
check(len(done) == 1 and not sk, "受保护（加密）的重关联请求：看不懂内容，忽略")
done, sk = run([roam_frame(9, "sha256", PSK32, 16)[0]], [("wpa-psk", PSK32.hex())])
check(done == [] and sk and "空中漫游" in sk[0][1], "没有初始握手：没有 PMK-R0 可用，不能凭空产生握手，说明原因")

print("== 漫游后新 AP 的 GTK / IGTK（重关联响应 FTE 的子元素，用漫游得到的 KEK 包装）==")
GTK_ = bytes(range(60, 76))
IGTK_ = bytes(range(80, 96))


def reassoc_resp(kek, gtk=GTK_, igtk=IGTK_, key_id=2, klen=None, prot=0, bad_len=False, ap=NEW_AP, igtk_kek=None, dup=False, pad=0):
    sub = bytes([1, 6]) + R1KH_NEW
    if gtk is not None:
        w = kdf.aes_key_wrap(kek, gtk)
        g = struct.pack("<H", key_id) + bytes([len(gtk) if klen is None else klen]) + bytes(range(8)) + w
        g += bytes(pad)
        sub += bytes([2, len(g) - (1 if bad_len else 0)]) + g[:len(g) - (1 if bad_len else 0)]
        if dup:
            g2 = struct.pack("<H", 3) + bytes([16]) + bytes(8) + kdf.aes_key_wrap(kek, bytes(16))
            sub += bytes([2, len(g2)]) + g2
    if igtk is not None:
        wi = kdf.aes_key_wrap(igtk_kek or kek, igtk)
        ig = struct.pack("<H", 5) + bytes([1, 2, 3, 4, 5, 6]) + bytes([len(igtk)]) + wi
        sub += bytes([4, len(ig)]) + ig
    fte = bytes([55, 2 + 16 + 64 + len(sub)]) + bytes(2 + 16 + 64) + sub
    mde = bytes([54, 3]) + MDID_ + b"\x01"
    return with_addrs(STA, ap, ap, lambda: synth.frame(0, 3, prot=prot, body=bytes(6) + mde + fte))


init = build_ft(4, "sha256", PSK32, 16, 3)
rf, r1, r1n = roam_frame(4, "sha256", PSK32, 16, rsnxe_used=False)
kek_roam = ft80211.derive_ptk(r1, "sha256", bytes([22]) * 32, bytes([21]) * 32, NEW_AP, STA, 16, 16, 16)[1]


def groups(extra):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "t.pcap")
        synth.write_pcap(path, init + [rf] + extra)
        frames_ = list(fr.iter_frames(path))
        done_, _ = hs.track(frames_, [("wpa-psk", PSK32.hex())])
        return gk.track_group(frames_, done_)


got = groups([reassoc_resp(kek_roam)])
check(len(got) == 1 and (got[0].ap, got[0].key_id, got[0].gtk, got[0].source, got[0].tx) == (mac(NEW_AP), 2, GTK_, "FT", True), "GTK：用漫游得到的 KEK 解开，密钥序号取低 2 位，来源 FT，AP = 响应的发送方")
check(got[0].igtk == (5, bytes([1, 2, 3, 4, 5, 6]), IGTK_), "IGTK 子元素：序号(2) ‖ IPN(6) ‖ 长度(1) ‖ 包装的密钥")
check(groups([reassoc_resp(kek_roam, igtk=None)])[0].igtk is None, "没有 IGTK 子元素：igtk 为 None")
check(groups([reassoc_resp(kek_roam, key_id=0x0e)])[0].key_id == 2, "密钥序号字节 0x0e：只取低 2 位 = 2")
check(groups([reassoc_resp(kek_roam, pad=1)]) == [], "包装的 GTK 长度不是 8 的倍数：不收（也不崩溃）")
check(groups([reassoc_resp(kek_roam, igtk_kek=bytes(16))])[0].igtk is None and groups([reassoc_resp(kek_roam, igtk_kek=bytes(16))])[0].gtk == GTK_, "IGTK 的包装校验不过：IGTK 丢掉，GTK 照收")
check(groups([reassoc_resp(kek_roam, dup=True)])[0].gtk == GTK_, "两个 GTK 子元素：取第一个")
check(groups([reassoc_resp(bytes(16))]) == [], "KEK 不对（完整性校验不过）：不收")
check(groups([reassoc_resp(kek_roam, klen=15)]) == [], "密钥长度字段与解出的长度不符：不收")
check(groups([reassoc_resp(kek_roam, gtk=None)]) == [], "没有 GTK 子元素：不收")
check(groups([reassoc_resp(kek_roam, prot=1)]) == [], "受保护的重关联响应：看不懂，忽略")
check(groups([reassoc_resp(kek_roam, bad_len=True)]) == [], "GTK 子元素被截断：解码失败，不收")
check(groups([reassoc_resp(kek_roam, ap=H("02aabbccdd99"))]) == [], "发送方不是做过握手的 AP：没有 KEK 可用，不收")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
