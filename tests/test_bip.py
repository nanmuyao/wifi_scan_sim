#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BIP（广播 / 组播管理帧的完整性）：用 pycryptodome 的 CMAC / GCM 当独立实现，AAD 与消息在这里手写。
四种套件：BIP-CMAC-128（MIC 8 字节）、BIP-CMAC-256、BIP-GMAC-128、BIP-GMAC-256（MIC 16 字节）。
真实帧：wpa3-suiteb-192 里的一个 BIP-GMAC-256 解除认证帧由 tests/oracle/test_bip_oracle.py 验证。"""
import os
import struct
import sys

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import decrypt80211 as dec  # noqa: E402
import frames80211 as fr  # noqa: E402
import groupkeys80211 as gk  # noqa: E402
import wifi_frame_parser as w  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


BC = b"\xff" * 6
AP = bytes([2, 0, 0, 0, 0, 9])
APS = ":".join("%02x" % x for x in AP)
IPN = bytes([1, 2, 3, 4, 5, 6])
SUITES = {"BIP-CMAC-128": (16, 8), "BIP-CMAC-256": (32, 16), "BIP-GMAC-128": (16, 16), "BIP-GMAC-256": (32, 16)}


def deauth(cipher, igtk, *, key_id=4, ipn=IPN, flags=0, reason=3, ap=AP, subtype=12, extra=b""):
    """独立构造：广播的解除认证帧（类型 0，不加密，受保护位 0），MME 在帧体末尾。"""
    _kl, mic_len = SUITES[cipher]
    hdr = bytes([subtype << 4, flags]) + struct.pack("<H", 0) + BC + ap + ap + struct.pack("<H", 0x0010)
    body = struct.pack("<H", reason) + extra
    mme_head = bytes([76, 8 + mic_len]) + struct.pack("<H", key_id) + ipn
    aad = bytes([subtype << 4, 0]) + BC + ap + ap                         # 帧控制第 2 字节：重试 / 省电 / 更多数据清零，其余位都是 0
    msg = aad + body + mme_head + bytes(mic_len)
    if cipher.startswith("BIP-CMAC"):
        mic = CMAC.new(igtk, ciphermod=AES, msg=msg).digest()[:mic_len]
    else:
        g = AES.new(igtk, AES.MODE_GCM, nonce=ap + ipn[::-1], mac_len=16)
        g.update(msg)
        mic = g.digest()
    d = hdr + body + mme_head + mic
    return fr.Frame(1, 0.0, d, w.parse_mac_header(d), d[24:], None)


for cipher, (klen, mlen) in SUITES.items():
    print("== %s ==" % cipher)
    igtk = bytes(range(50, 50 + klen))
    f = deauth(cipher, igtk)
    r = dec.verify_bip(igtk, cipher, f)
    check(r == (True, 4, IPN), "MIC 吻合，密钥序号 4，IPN")
    check(dec.verify_bip(bytes(klen), cipher, f)[0] is False, "错的 IGTK：不吻合")
    check(dec.verify_bip(igtk + b"\0", cipher, f)[0] is False and dec.verify_bip(igtk[:-1], cipher, f)[0] is False, "IGTK 长度不对：不吻合（不崩溃）")
    check(dec.verify_bip(igtk, cipher, deauth(cipher, igtk, flags=0x08 | 0x10 | 0x20))[0], "重试 / 省电 / 更多数据位被屏蔽")
    check(dec.verify_bip(igtk, cipher, deauth(cipher, igtk, subtype=10))[0], "分手帧（子类型 10）同样适用")
    check(dec.verify_bip(igtk, cipher, deauth(cipher, igtk, extra=bytes(range(40))))[0], "帧体更长（MME 仍在末尾）")
    for nm, off, xor in (("原因码", 24, 0x01), ("地址 2", 10, 0x01), ("地址 3", 16, 0x01), ("地址 1", 4, 0x01), ("帧控制第 1 字节", 0, 0x10), ("帧控制第 2 字节的受保护位", 1, 0x40), ("MIC 末字节", len(f.dot11) - 1, 0x01)):
        b = bytearray(f.dot11)
        b[off] ^= xor
        g2 = fr.Frame(1, 0.0, bytes(b), w.parse_mac_header(bytes(b)), bytes(b[24:]), None)
        check(dec.verify_bip(igtk, cipher, g2)[0] is False, "%s变了：不吻合" % nm)
    b = bytearray(f.dot11)
    b[24 + 4 + 3] ^= 0x01                                                  # IPN 的一个字节
    g3 = fr.Frame(1, 0.0, bytes(b), w.parse_mac_header(bytes(b)), bytes(b[24:]), None)
    check(dec.verify_bip(igtk, cipher, g3)[0] is False, "IPN 变了：不吻合（GMAC 的 IV 和 MME 都带着它）")

print("== find_mme ==")
f = deauth("BIP-CMAC-128", bytes(16))
check(dec.find_mme(f.body)[:3] == (4, IPN, f.body[-8:]) and dec.find_mme(f.body)[3] == len(f.body) - 8, "MIC 8 字节：密钥序号、IPN、MIC、MIC 的偏移")
f = deauth("BIP-GMAC-256", bytes(32))
check(dec.find_mme(f.body)[3] == len(f.body) - 16 and len(dec.find_mme(f.body)[2]) == 16, "MIC 16 字节")
check(dec.find_mme(struct.pack("<H", 3)) is None and dec.find_mme(b"") is None, "没有 MME：None")
check(dec.verify_bip(bytes(16), "BIP-CMAC-128", fr.Frame(1, 0.0, f.dot11[:24] + b"\x03\x00", f.h, b"\x03\x00", None)) is None, "帧里没有 MME：verify_bip 返回 None")
check(dec.find_mme(f.body + b"\x00") is None, "MME 不在末尾：不认")
bad_len = bytearray(f.body)
bad_len[-(2 + 24) + 1] = 17
check(dec.find_mme(bytes(bad_len)) is None, "元素长度字段对不上：不认")

print("== groupkeys.verify_bip：选 IGTK ==")
igtk = bytes(range(32))
fm = deauth("BIP-GMAC-256", igtk)._replace(n=50)
K = lambda n, kid, key, ap=APS: gk.GroupKey(n, ap, 1, True, bytes(16), (kid, bytes(6), key), "M3")      # noqa: E731
MC = {APS: "BIP-GMAC-256"}
check(gk.verify_bip([K(10, 4, igtk)], MC, fm) == "ok", "密钥序号对、装上时间在前：ok")
check(gk.verify_bip([K(10, 4, bytes(32)), K(20, 4, igtk)], MC, fm) == "ok" and gk.verify_bip([K(10, 4, igtk), K(20, 4, bytes(32))], MC, fm) == "ok", "多把同序号的 IGTK：试到吻合的")
check(gk.verify_bip([K(10, 4, bytes(32))], MC, fm) == "bad", "有 IGTK 但不吻合：bad")
check(gk.verify_bip([K(10, 5, igtk)], MC, fm) == "no_igtk", "密钥序号不对：no_igtk")
check(gk.verify_bip([K(60, 4, igtk)], MC, fm) == "ok" and gk.verify_bip([K(60, 4, bytes(32))], MC, fm) == "bad", "IGTK 装上得比帧晚（信标比关联早抓到）：照样试，吻合就是 ok，不吻合是 bad")
check(gk.verify_bip([K(60, 4, bytes(32)), K(10, 4, igtk)], MC, fm) == "ok" and gk.verify_bip([K(20, 4, bytes(32)), K(60, 4, igtk)], MC, fm) == "ok", "先试早装上的、再试晚装上的：两类密钥里有一把吻合就行")
check(gk.verify_bip([K(10, 4, igtk, ap="aa:bb:cc:dd:ee:ff")], MC, fm) == "no_igtk", "IGTK 属于别的 AP：no_igtk")
check(gk.verify_bip([K(10, 4, igtk)], {}, fm) == "ok", "不知道组管理套件：按 MIC 16 字节 + 密钥 32 字节推出 GMAC-256 / CMAC-256 两个，GMAC-256 吻合")
check(gk.verify_bip([K(10, 4, bytes(20))], {}, fm) == "no_igtk", "不知道套件而且密钥长度对不上任何一个套件：没有可试的，no_igtk")
check(gk.verify_bip([gk.GroupKey(10, APS, 1, True, bytes(16), None, "M3")], MC, fm) == "no_igtk", "这把组密钥没带 IGTK：no_igtk")
check(gk.verify_bip([K(10, 4, igtk)], MC, fm._replace(n=10)) == "ok", "帧号等于密钥帧号：算「不早于」，排在后一类里试，吻合就是 ok")
prot = fm.dot11[:1] + bytes([fm.dot11[1] | 0x40]) + fm.dot11[2:]
check(gk.verify_bip([K(10, 4, igtk)], MC, fm._replace(h=w.parse_mac_header(prot))) is None, "受保护位置位的管理帧（CCMP 加密的）不走 BIP：None")
check(gk.verify_bip([K(10, 4, igtk)], MC, fm._replace(h=dict(fm.h, type=2))) is None, "不是管理帧：None")

print("== BIGTK（密钥序号 6 / 7）：不判 ==")
fb = deauth("BIP-GMAC-256", igtk)
for kid in (6, 7):
    f6 = deauth("BIP-GMAC-256", igtk, key_id=kid)._replace(n=50)
    check(gk.verify_bip([K(10, kid, igtk)], MC, f6) == "unsupported", "MME 的密钥序号 %d 是 BIGTK：unsupported（信标保护的规则没确定，不下结论）" % kid)
check(gk.verify_bip([K(10, 5, igtk)], MC, deauth("BIP-GMAC-256", igtk, key_id=5)._replace(n=50)) == "ok", "密钥序号 5（IGTK）照常判")

print("== group_mgmt_ciphers ==")
WFA = b"\x00\x0f\xac"


def rsn(gm):
    return (bytes([0x30, 26, 1, 0]) + WFA + b"\x04" + b"\x01\x00" + WFA + b"\x04" + b"\x01\x00" + WFA + b"\x08" + b"\xc0\x00" + b"\x00\x00" + WFA + bytes([gm]))


def beacon(bssid, gm):
    d = bytes([0x80, 0, 0, 0]) + BC + bssid + bssid + bytes(2) + bytes(12) + rsn(gm)
    return fr.Frame(1, 0.0, d, w.parse_mac_header(d), d[24:], None)


B2 = bytes([2, 0, 0, 0, 0, 2])
res = gk.group_mgmt_ciphers([beacon(AP, 12), beacon(B2, 6)])
check(res == {APS: "BIP-GMAC-256", ":".join("%02x" % x for x in B2): "BIP-CMAC-128"}, "信标 RSN 里的组管理套件：12 = BIP-GMAC-256、6 = BIP-CMAC-128")
check(gk.group_mgmt_ciphers([beacon(AP, 13)])[APS] == "BIP-CMAC-256" and gk.group_mgmt_ciphers([beacon(AP, 11)])[APS] == "BIP-GMAC-128", "13 = BIP-CMAC-256、11 = BIP-GMAC-128")
check(gk.group_mgmt_ciphers([beacon(AP, 99)]) == {}, "不认识的套件不收")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
