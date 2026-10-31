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
import eapol  # noqa: E402
import frames80211 as fr  # noqa: E402
import handshake80211 as hs  # noqa: E402
import ie  # noqa: E402
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
                   ((0, 32, 24), "hmac-sha512"), ((0, 20, 18), None)):
    check(hs.mic_algorithm(*args) == want, "描述符版本 %d、MIC %d 字节、AKM %s -> %s" % (args + (want,)))

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
check(done == [] and "快速切换（AKM 4）" in skipped[0][1], "FT 的 AKM：跳过，注明阶段 E")
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

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
