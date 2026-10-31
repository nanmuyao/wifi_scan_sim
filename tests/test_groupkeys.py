#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""groupkeys80211：KDE 解析、Key Data 解包、GTK / IGTK 提取、组播帧解密（独立加密方）。真实抓包的对照在 tests/oracle/test_groupkeys_oracle.py。"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import crypto80211  # noqa: E402
import groupkeys80211 as gk  # noqa: E402
import kdf80211  # noqa: E402
from aead_build import A2, build, frame  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


WFA = b"\x00\x0f\xac"
GTK = bytes(range(16))
IGTK = bytes(range(100, 116))


def kde(typ, body):
    return bytes([0xDD, 4 + len(body)]) + WFA + bytes([typ]) + body


GTK_KDE = kde(1, bytes([0x05, 0]) + GTK)                      # 密钥序号 1，Tx 位
IGTK_KDE = kde(9, bytes([4, 0]) + bytes([1, 2, 3, 4, 5, 6]) + IGTK)   # 密钥序号 4，IPN 01..06 小端放着原样
RSN_IE = bytes([0x30, 4]) + bytes(4)
PAD = bytes([0xDD, 0]) + bytes(2)

print("== parse_kdes ==")
k = gk.parse_kdes(RSN_IE + GTK_KDE + IGTK_KDE + PAD)
check([t for t, _ in k] == [1, 9], "跳过 RSN 元素，取出 GTK（类型 1）和 IGTK（类型 9）两个 KDE，填充之后不再读")
check(k[0][1] == bytes([0x05, 0]) + GTK, "KDE 数据 = 类型字节之后的内容")
check(gk.parse_kdes(kde(1, b"abc")[:-1]) == [], "长度声明超出数据：丢弃，不报错")
other = bytes([0xDD, 8]) + b"\x00\x50\xf2\x01" + bytes(4)
check(gk.parse_kdes(other + GTK_KDE) == [(1, bytes([0x05, 0]) + GTK)], "别的 OUI（微软）的 KDE 跳过")
check(gk.parse_kdes(GTK_KDE + PAD + IGTK_KDE) == [(1, bytes([0x05, 0]) + GTK)], "填充（0xDD 0x00）之后的内容不再读")
check(gk.parse_kdes(b"") == [] and gk.parse_kdes(b"\xdd") == [], "空数据 / 只有一个字节")

print("== keys_from_data ==")
E2 = {"descriptor": 2, "key_info": {"index": 0, "install": False}, "key_length": 16}
g = gk.keys_from_data(GTK_KDE + IGTK_KDE, E2, "aa", 7, "M3")
check((g.key_id, g.tx, g.gtk, g.n, g.ap, g.source) == (1, True, GTK, 7, "aa", "M3"), "GTK：密钥序号取低 2 位、Tx 是 bit 2，GTK 从第 3 字节起")
check(g.igtk == (4, bytes([1, 2, 3, 4, 5, 6]), IGTK), "IGTK：序号 2 字节小端，IPN 6 字节，然后是密钥")
g2 = gk.keys_from_data(kde(1, bytes([0x03, 0]) + GTK), E2, "aa", 1, "G1")
g4 = gk.keys_from_data(kde(1, bytes([0x02, 0]) + bytes(16)) + GTK_KDE, E2, "aa", 1, "M3")
check(g4.key_id == 2, "有两个 GTK KDE：取第一个")
check(g2.key_id == 3 and not g2.tx and g2.igtk is None, "密钥序号 3、无 Tx 位、没有 IGTK")
check(gk.keys_from_data(RSN_IE + IGTK_KDE, E2, "aa", 1, "M3") is None, "没有 GTK KDE：None")
g3 = gk.keys_from_data(b"\x11" * 32 + b"\x22" * 4, {"descriptor": 254, "key_info": {"index": 2, "install": True}, "key_length": 32}, "aa", 1, "G1")
check(g3.gtk == b"\x11" * 32 and g3.key_id == 2 and g3.tx, "WPA1：Key Data 前 Key Length 字节就是 GTK，序号在 Key Info，Tx 是 Install 位")

print("== unwrap_key_data ==")
KEK = bytes(range(32, 48))
plain = GTK_KDE + PAD
plain += bytes((-len(plain)) % 8)
wrapped = kdf80211.aes_key_wrap(KEK, plain)
e = {"descriptor": 2, "key_info": {"version": 2}, "data": wrapped, "iv": bytes(16)}
check(gk.unwrap_key_data(KEK, e) == plain, "版本 2：AES 密钥包装")
check(gk.unwrap_key_data(bytes(16), e) is None, "KEK 不对：完整性校验失败返回 None")
check(gk.unwrap_key_data(KEK, dict(e, key_info={"version": 0})) == plain, "版本 0（AKM 决定）：同样是 AES 密钥包装")
check(gk.unwrap_key_data(KEK, dict(e, data=wrapped[:-1])) is None and gk.unwrap_key_data(KEK, dict(e, data=b"")) is None, "长度不是 8 的倍数 / 为空：None")
iv = bytes(range(16))
rc4_ct = crypto80211.rc4(iv + KEK, bytes(256) + plain)[256:]
check(gk.unwrap_key_data(KEK, {"descriptor": 2, "key_info": {"version": 1}, "data": rc4_ct, "iv": iv}) == plain, "版本 1：RC4，密钥 IV ‖ KEK，丢弃前 256 字节密钥流")
check(gk.unwrap_key_data(KEK, {"descriptor": 254, "key_info": {"version": 2}, "data": rc4_ct, "iv": iv}) == plain, "描述符 254（WPA1）：不看版本，一律 RC4")

print("== group_ciphers ==")
import frames80211 as fr  # noqa: E402
import wifi_frame_parser as w  # noqa: E402


def rsn(group):
    return bytes([0x30, 20, 1, 0]) + WFA + bytes([group]) + b"\x01\x00" + WFA + b"\x04" + b"\x01\x00" + WFA + b"\x02" + b"\x00\x00"


def mgmt(subtype, bssid, ies, fixed):
    d = bytes([subtype << 4, 0, 0, 0]) + bytes(6) + bssid + bssid + bytes(2) + bytes(fixed) + ies
    return fr.Frame(1, 0.0, d, w.parse_mac_header(d), d[24:], None)


B1, B2, B3 = (bytes([2, 0, 0, 0, 0, i]) for i in (1, 2, 3))
M = lambda b: ":".join("%02x" % x for x in b)  # noqa: E731
FIX = {8: 12, 5: 12, 0: 4, 2: 10}
beacon = mgmt(8, B1, rsn(2), FIX[8])                     # 组套件 2 = TKIP
assoc = mgmt(0, B2, rsn(4), FIX[0])                      # 关联请求：CCMP
beacon_b2 = mgmt(8, B2, rsn(8), FIX[8])                  # 同一个 BSSID 有信标时信标优先
check(gk.group_ciphers([beacon, assoc]) == {M(B1): "TKIP", M(B2): "CCMP-128"}, "信标给出组套件；没有信标的 BSSID 用关联请求里的")
check(gk.group_ciphers([assoc, beacon_b2])[M(B2)] == "GCMP-128", "有信标时信标优先于关联请求（不论先后）")
check(gk.group_ciphers([mgmt(8, B3, rsn(1), FIX[8])]) == {}, "WEP 等不处理的套件不收")
HS = type("H", (), {"ap": M(B3), "cipher": "CCMP-256"})
check(gk.group_ciphers([beacon], [HS]) == {M(B1): "TKIP", M(B3): "CCMP-256"}, "什么都没抓到的 AP：猜成对套件")
check(gk.group_ciphers([mgmt(8, B3, rsn(4), FIX[8])], [HS])[M(B3)] == "CCMP-128", "有信标时不用猜测")

print("== 多链路的组密钥 KDE（mlo_keys）==")
L0, L1 = bytes([2, 0, 0, 0, 0, 0xa0]), bytes([2, 0, 0, 0, 0, 0xb1])
M0, M1 = ":".join("%02x" % x for x in L0), ":".join("%02x" % x for x in L1)
link_kde = lambda lid, mac: kde(0x13, bytes([0x30 | lid]) + mac + b"\x30\x02\x01\x00")                  # noqa: E731  链路 ID + 标志(RSNE / RSNXE 在)、MAC、其后的 RSNE
gtk_kde = lambda kid, tx, link, gtk: kde(0x10, bytes([kid | tx << 2 | link << 4]) + bytes(6) + gtk)        # noqa: E731
igtk_kde = lambda typ, kid, link, key: kde(typ, struct.pack("<H", kid) + bytes([1, 2, 3, 4, 5, 6]) + bytes([link << 4]) + key)     # noqa: E731
G0, G1_, I0, B1 = bytes(range(16)), bytes(range(16, 32)), bytes(range(32, 48)), bytes(range(48, 64))
blob = link_kde(0, L0) + link_kde(1, L1) + gtk_kde(1, 1, 0, G0) + gtk_kde(2, 0, 1, G1_) + igtk_kde(0x11, 4, 0, I0) + igtk_kde(0x12, 6, 1, B1) + RSN_IE
got = gk.mlo_keys(blob, 11, "M3")
by = {(k.ap, k.key_id): k for k in got}
check(len(got) == 4, "两个 GTK + 一个 IGTK + 一个 BIGTK = 4 条")
k0, k1 = by[(M0, 1)], by[(M1, 2)]
check((k0.gtk, k0.tx, k0.source, k0.n, k0.igtk) == (G0, True, "M3", 11, None) and (k1.gtk, k1.tx) == (G1_, False), "MLO GTK KDE：第 1 字节 bit0-1 序号、bit2 Tx、高 4 位链路 ID；跳过 6 字节 RSC；链路 ID 经链路 KDE 换成链路 MAC")
mg = [k for k in got if k.igtk]
check(sorted((k.ap, k.igtk[0], k.igtk[2]) for k in mg) == sorted([(M0, 4, I0), (M1, 6, B1)]) and all(k.gtk == b"" and k.key_id == -1 and not k.tx for k in mg), "IGTK（0x11）/ BIGTK（0x12）：密钥序号 2 字节小端、IPN 6、链路 ID 在高 4 位、然后是密钥；放在单独的条目里（gtk 为空、key_id = -1）")
check(all(k.igtk[1] == bytes([1, 2, 3, 4, 5, 6]) for k in mg), "IPN 6 字节")
only_g1 = gtk_kde(3, 1, 1, G0) + igtk_kde(0x11, 5, 1, I0)
links = {}
gk.mlo_keys(blob, 11, "M3", links)
check(links == {0: M0, 1: M1}, "链路表由调用方保存：M3 的链路 KDE 并进去")
g1 = gk.mlo_keys(only_g1, 16, "G1", links)
check(sorted((k.ap, k.key_id) for k in g1) == sorted([(M1, 3), (M1, -1)]) and all(k.source == "G1" for k in g1), "G1 里没有链路 KDE：用 M3 记下的表")
check(gk.mlo_keys(only_g1, 16, "G1") == [], "没有链路表、消息里也没有链路 KDE：链路 ID 对不上，全部丢掉")
check(gk.mlo_keys(gtk_kde(1, 1, 5, G0) + link_kde(0, L0), 1, "M3") == [], "链路 ID 5 不在链路 KDE 里：丢掉")
check(gk.mlo_keys(link_kde(0, L0) + kde(0x10, bytes([1]) + bytes(6) + bytes(14)) + kde(0x11, bytes(20)), 1, "M3") == [], "GTK 不足 16 字节 / IGTK 不足 25 字节的 KDE：丢掉")
check(gk.mlo_keys(link_kde(0, L0)[:-3], 1, "M3") == [] and gk.mlo_keys(b"", 1, "M3") == [], "残缺的 KDE / 空数据：没有键，不崩溃")
check(gk.mlo_keys(kde(0x13, bytes([0x30]) + bytes(3)) + gtk_kde(1, 1, 0, G0), 1, "M3") == [], "链路 KDE 短于 7 字节：不收，GTK 找不到链路")
check(gk.mlo_keys(kde(0x13, bytes([0x30]) + bytes(5)) + gtk_kde(1, 1, 0, G0), 1, "M3") == [], "链路 KDE 恰好 6 字节（MAC 少一个字节）：不收")
k9 = gk.mlo_keys(link_kde(9, L1) + gtk_kde(1, 1, 9, G0), 1, "M3")
check(len(k9) == 1 and k9[0].ap == M1, "链路 ID 9（超过 7）：链路 ID 占 4 位，不是 3 位")

print("== decrypt_group ==")
BSSID = ":".join("%02x" % x for x in A2)
MC = bytes([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb])
MC_S = ":".join("%02x" % x for x in MC)
TK = bytes(range(16))
PL = b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + bytes(30)
keys = [gk.GroupKey(10, BSSID, 1, True, TK, None, "M3"), gk.GroupKey(20, BSSID, 1, True, bytes(16), None, "G1"),
        gk.GroupKey(5, BSSID, 2, True, bytes(range(1, 17)), None, "M3")]
CI = {BSSID: "CCMP-128"}
f = frame(build("CCMP-128", TK, 99, PL, a1=MC, qos=0x0000, to_ds=0, from_ds=1, key_id=1))
f = f._replace(n=30)
got = gk.decrypt_group(keys, CI, f)
check(got is not None and got[1] == PL and got[0].n == 10, "组播帧：按密钥序号找 GTK，新的（n=20）MIC 不过就退到旧的（n=10）")
check(gk.decrypt_group(keys, CI, f._replace(n=15)) is not None, "帧在第二把密钥装上（n=20）之前：只剩第一把可用")
check(gk.decrypt_group(keys, CI, f._replace(n=10)) is None, "帧号不晚于密钥装上的帧：不用这把密钥")
check(gk.decrypt_group(keys, {}, f) is None, "不知道组密码套件：None")
check(gk.decrypt_group(keys, {BSSID: "TKIP"}, f) is None, "组套件猜成 TKIP 但 GTK 只有 16 字节：长度不对，None（不崩溃）")
check(gk.decrypt_group([k for k in keys if k.key_id != 1], CI, f) is None, "没有这个密钥序号的 GTK：None")
uni = frame(build("CCMP-128", TK, 99, PL, a1=bytes([0x12] * 6), qos=0x0000, to_ds=0, from_ds=1, key_id=1))._replace(n=30)
check(gk.decrypt_group(keys, CI, uni) is None, "A1 不是组地址：不是组播帧，None")
check(gk.decrypt_group(keys, CI, frame(build("CCMP-128", TK, 99, PL, a1=MC, qos=0x0000, to_ds=1, from_ds=0, key_id=1))._replace(n=30)) is None, "ToDS（STA 发出的）：不是 AP 的组播，None")
check(gk.decrypt_group([gk.GroupKey(5, BSSID, 2, True, TK, None, "M3")], CI, f) is None, "密钥序号对不上（帧是 1，GTK 是 2）：即使密钥值对也不用")
check(gk.decrypt_group([gk.GroupKey(5, "00:00:00:00:00:99", 1, True, TK, None, "M3")], CI, f) is None, "GTK 属于别的 AP：不用")
wds = frame(build("CCMP-128", TK, 99, PL, a1=MC, qos=0x0000, to_ds=1, from_ds=1, four=True, key_id=1))._replace(n=30)
check(gk.decrypt_group([gk.GroupKey(5, BSSID, 1, True, TK, None, "M3")], CI, wds) is None, "ToDS 和 FromDS 都置位（四地址）：不是 AP 的组播，None")
g8 = frame(build("GCMP-256", bytes(range(32)), 5, PL, a1=MC, qos=0x0000, to_ds=0, from_ds=1, key_id=2))._replace(n=30)
got = gk.decrypt_group([gk.GroupKey(5, BSSID, 2, True, bytes(range(32)), None, "M3")], {BSSID: "GCMP-256"}, g8)
check(got is not None and got[1] == PL, "GCMP-256 组播帧")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
