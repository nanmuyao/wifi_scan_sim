#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ie.walk：元素遍历（顺序、重复、扩展元素、被截断）。各子类型的固定部分长度由 tests/oracle 对照 tshark。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ie  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


els, trunc = ie.walk(b"")
check(els == [] and trunc is False, "空")
els, trunc = ie.walk(b"\x00\x04test\x03\x01\x06")
check([(e.id, e.data, e.offset) for e in els] == [(0, b"test", 0), (3, b"\x06", 6)] and trunc is False, "两个元素：ID、数据、偏移")
els, _ = ie.walk(b"\xdd\x02ab\x00\x00\xdd\x01c")
check([(e.id, e.data) for e in els] == [(221, b"ab"), (0, b""), (221, b"c")], "同一 ID 出现多次都保留；长度 0 的元素也保留")
els, _ = ie.walk(b"\xff\x03\x23xy\x30\x00")
check([(e.id, e.ext, e.data) for e in els] == [(255, 0x23, b"xy"), (48, None, b"")], "扩展元素：扩展 ID 取数据第 1 字节，其余是数据")
els, _ = ie.walk(b"\xff\x00")
check([(e.id, e.ext, e.data) for e in els] == [(255, None, b"")], "扩展元素长度 0：没有扩展 ID")

els, trunc = ie.walk(b"\x00\x01a\x30\x14\x01\x00")
check([e.id for e in els] == [0] and trunc is True, "最后一个元素声明的长度超过剩余字节：前面的保留，truncated")
els, trunc = ie.walk(b"\x00\x01a\x30")
check([e.id for e in els] == [0] and trunc is True, "只剩 1 个字节（没有长度）：truncated")
els, trunc = ie.walk(b"\x00\x01a\x30\x00")
check([e.id for e in els] == [0, 48] and trunc is False, "恰好用完：不算 truncated")
els, trunc = ie.walk(b"\x00\x02a")
check(els == [] and trunc is True, "第一个元素就超长")

print("== ids() ==")
els, _ = ie.walk(b"\x00\x00\xff\x01\x6b\x30\x00\xff\x01\x24\x00\x00")
check(ie.ids(els) == ([0, 48, 0], [107, 36]), "普通元素 ID 与扩展 ID 分开，各自保持出现顺序")
els, _ = ie.walk(b"\xff\x00")
check(ie.ids(els) == ([], []), "没有扩展 ID 的扩展元素不计入")

print("== 元素内容 ==")
check(ie.decode_ssid(b"") == {"ssid": b""} and ie.decode_ssid(b"x" * 33) is None, "SSID：空（隐藏）可以，超过 32 字节不合规")
check(ie.decode_ssid(bytes(range(0x80, 0xa0)))["ssid"] == bytes(range(0x80, 0xa0)), "SSID 是字节串，不要求 UTF-8")
r = ie.decode_rates(bytes([0x82, 0x84, 0x0b, 0x16, 0xff]))
check(r["rates"] == [0x82, 0x84, 0x0b, 0x16, 0xff] and r["mbps"] == [1.0, 2.0, 5.5, 11.0, 63.5] and r["basic"] == [True, True, False, False, True],
      "速率：原字节、Mbps（低 7 位 / 2）、基本速率位（最高位）")
check(ie.decode_ds(b"\x0b") == {"channel": 11} and ie.decode_ds(b"") is None, "DS：信道；空数据不合规")
t = ie.decode_tim(bytes([1, 3, 0x05, 0xAA, 0xBB]))
check(t == {"dtim_count": 1, "dtim_period": 3, "multicast": True, "offset": 2, "bitmap": b"\xaa\xbb"}, "TIM：位图控制 bit0 = 组播，bit1-7 = 偏移（0x05 -> 偏移 2）")
check(ie.decode_tim(bytes([0, 1, 0])) is None, "TIM：不足 4 字节不合规")
check(ie.decode_tim(bytes([0, 1, 0xFE, 0]))["offset"] == 127 and not ie.decode_tim(bytes([0, 1, 0xFE, 0]))["multicast"], "TIM：偏移是高 7 位的数值（最大 127），bit0 为 0 时无组播")
c = ie.decode_country(b"US \x01\x0b\x1e\x24\x04\x17")
check(c["code"] == "US" and c["environment"] == 0x20 and c["triplets"] == [
    {"first_channel": 1, "num_channels": 11, "max_power": 30}, {"first_channel": 36, "num_channels": 4, "max_power": 23}], "国家：两个信道三元组")
c = ie.decode_country(b"DEO" + bytes([201, 13, 4]) + bytes([36, 4, 23]) + b"\x00")
check(c["environment"] == ord("O") and c["triplets"] == [
    {"operating_ext": 201, "operating_class": 13, "coverage_class": 4}, {"first_channel": 36, "num_channels": 4, "max_power": 23}],
    "国家：运行类别三元组（首字节 >= 201），末尾 1 字节填充被忽略")
check(ie.decode_country(b"JP " + bytes([1, 13, 0xf6]))["triplets"][0]["max_power"] == -10, "国家：最大功率是有符号数")
check(ie.decode_country(b"US \x01\x0b") is None, "国家：不足 6 字节不合规")
check(ie.decode_erp(b"\x05") == {"value": 5, "non_erp_present": True, "use_protection": False, "barker_preamble": True}, "ERP：三个位")
check(ie.decode_erp(b"") is None, "ERP：空数据不合规")

print("== RSN ==")
S = lambda t, oui=b"\x00\x0f\xac": oui + bytes([t])      # noqa: E731
LE = lambda n: bytes([n & 255, n >> 8])                    # noqa: E731
wpa2 = LE(1) + S(4) + LE(1) + S(4) + LE(1) + S(2) + LE(0x000c)
check(len(wpa2) == 20, "WPA2-PSK 的 RSN 元素共 20 字节（手算）")
r = ie.decode_rsn(wpa2)
check((r["version"], r["group"], r["pairwise"], r["akm"], r["caps"]) == (1, (0x000fac, 4), [(0x000fac, 4)], [(0x000fac, 2)], 0x000c),
      "WPA2-PSK：版本 1、组密码 CCMP(4)、成对 CCMP、AKM PSK(2)、能力 0x000c")
check(r["ptksa_replay"] == 3 and r["gtksa_replay"] == 0 and not r["mfpr"] and not r["mfpc"] and not r["preauth"], "能力位 0x000c：PTKSA 重放计数器 3，其余为 0")
check(r["pmkids"] is None and r["group_mgmt"] is None, "元素在能力之后结束：PMKID 与组管理套件缺省（None）")
wpa3 = LE(1) + S(4) + LE(1) + S(4) + LE(1) + S(8) + LE(0x00c0) + LE(1) + bytes(range(16)) + S(6)
r = ie.decode_rsn(wpa3)
check(r["akm"] == [(0x000fac, 8)] and r["mfpr"] and r["mfpc"], "WPA3-SAE：AKM 8，MFPR 与 MFPC 都置位")
check(r["pmkids"] == [bytes(range(16))] and r["group_mgmt"] == (0x000fac, 6), "PMKID 一个（16 字节），组管理套件 BIP-CMAC(6)")
r = ie.decode_rsn(LE(1) + S(2) + LE(2) + S(2) + S(4) + LE(1) + S(2))
check(r["pairwise"] == [(0x000fac, 2), (0x000fac, 4)] and r["caps"] is None, "两个成对套件（TKIP + CCMP），没有能力字段")
check(ie.decode_rsn(LE(1) + S(2, oui=b"\x00\x50\xf2"))["group"] == (0x0050f2, 2), "厂商 OUI（WPA 的 00-50-f2）的套件")
r = ie.decode_rsn(LE(1))
check(r["version"] == 1 and r["group"] is None and r["pairwise"] is None, "只有版本号")
check(all(r[k] is None for k in ("caps", "mfpr", "mfpc", "preauth", "ptksa_replay", "pmkids", "group_mgmt")), "缺的字段都是 None，键总是齐的（调用方不用判断键在不在）")
r = ie.decode_rsn(LE(1) + S(4) + b"\x01")
check(r is not None and r["group"] == (0x000fac, 4) and r["pairwise"] is None and r["akm"] is None, "成对套件计数只有 1 个字节：读不出来，到此为止")
r = ie.decode_rsn(LE(1) + S(4) + LE(0) + LE(0))
check(r["pairwise"] == [] and r["akm"] == [], "计数为 0：空列表（不是 None）")
check(ie.decode_rsn(b"\x01") is None, "不足版本号 2 字节：不合规")
r = ie.decode_rsn(LE(1) + S(4) + LE(3) + S(4))
check(r["malformed"] and r["version"] == 1 and r["group"] == (0x000fac, 4) and r["pairwise"] is None and r["akm"] is None,
      "成对套件计数 3 而数据只有 1 个：畸形，已读到的版本和组密码保留，这个列表及之后的是 None")
r = ie.decode_rsn(LE(1) + S(4) + LE(1) + S(4) + LE(1) + S(2)[:3])
check(r["malformed"] and r["pairwise"] == [(0x000fac, 4)] and r["akm"] is None, "AKM 计数 1 而只剩 3 字节（demo.pcap 里 scapy 生成的就是这样）：成对套件保留")
r = ie.decode_rsn(LE(1) + S(4) + LE(1) + S(4) + LE(1) + S(2) + LE(0) + LE(2) + bytes(16))
check(r["malformed"] and r["akm"] == [(0x000fac, 2)] and r["caps"] == 0 and r["pmkids"] is None, "PMKID 计数 2 而只有 1 个：畸形，能力之前的保留")
check(ie.decode_rsn(wpa2)["malformed"] is False, "正常的元素 malformed 为 False")
BASE = LE(1) + S(4) + LE(0) + LE(0)
for name, word in (("preauth", 0x0001), ("no_pairwise", 0x0002), ("mfpr", 0x0040), ("mfpc", 0x0080),
                   ("joint_multi_band", 0x0100), ("peerkey", 0x0200), ("ocvc", 0x1000), ("extended_key_id", 0x2000)):
    r = ie.decode_rsn(BASE + LE(word))
    others = [k for k in ie.RSN_CAPS if k != name and r[k]]
    check(r[name] is True and not others, "能力位 0x%04x 只置 %s" % (word, name))
r = ie.decode_rsn(BASE + LE(0x0030))
check((r["ptksa_replay"], r["gtksa_replay"]) == (0, 3), "bit4-5 是 GTKSA 重放计数器（0x0030 -> 3），PTKSA 为 0")
r = ie.decode_rsn(BASE + LE(0x0004))
check((r["ptksa_replay"], r["gtksa_replay"]) == (1, 0), "bit2-3 是 PTKSA 重放计数器（0x0004 -> 1）")
r = ie.decode_rsn(BASE + LE(0) + LE(0) + b"\x00\x0f\xac")
check(r["pmkids"] == [] and r["group_mgmt"] is None, "组管理套件只剩 3 字节：读不出来（None），不是畸形")
r = ie.decode_rsn(LE(1) + S(4) + LE(256) + S(4))
check(r["malformed"] and r["pairwise"] is None, "计数是 16 位小端（0x0100 = 256），不能只看低字节")

print("== HT 能力（45）==")


def htcap(caps=0, ampdu=0, mcs=bytes(16), ext=0, txbf=0, asel=0):
    return struct.pack("<HB", caps, ampdu) + mcs + struct.pack("<HIB", ext, txbf, asel)


check(len(htcap()) == ie.HT_CAP_LEN == 26, "HT 能力元素 26 字节（2 + 1 + 16 + 2 + 4 + 1）")
# 位号写成字面值（802.11n 的 HT Capabilities Info），不引用模块自己的表
for name, bit in (("ldpc", 0), ("width40", 1), ("greenfield", 4), ("short_gi20", 5), ("short_gi40", 6), ("tx_stbc", 7),
                  ("delayed_ba", 10), ("max_amsdu_7935", 11), ("dsss_cck_40", 12), ("psmp", 13), ("forty_intolerant", 14),
                  ("lsig_txop", 15)):
    r = ie.decode_ht_cap(htcap(caps=1 << bit))
    others = [k for k in ie.HT_CAP_BITS if k != name and r[k]]
    check(r[name] is True and not others, "能力位 %d 只置 %s" % (bit, name))
check(set(ie.HT_CAP_BITS) == {"ldpc", "width40", "greenfield", "short_gi20", "short_gi40", "tx_stbc", "delayed_ba", "max_amsdu_7935",
                              "dsss_cck_40", "psmp", "forty_intolerant", "lsig_txop"}, "单个位的能力共 12 项（SM 省电、RX STBC 是多位字段）")
r = ie.decode_ht_cap(htcap(caps=0x0203))
check((r["sm_ps"], r["rx_stbc"], r["ldpc"], r["width40"]) == (0, 2, True, True), "RX STBC 是 bit8-9（0x0200 -> 2）")
r = ie.decode_ht_cap(htcap(caps=0x000c))
check((r["sm_ps"], r["rx_stbc"]) == (3, 0), "SM 省电是 bit2-3（0x000c -> 3，即关闭）")
r = ie.decode_ht_cap(htcap(ampdu=0x1b))
check((r["ampdu_max_exp"], r["ampdu_density"], r["ampdu_param"]) == (3, 6, 0x1b), "A-MPDU 参数 0x1b：最大长度指数 3，最小间隔 6")
mcs = b"\xff\xff" + bytes(8) + struct.pack("<H", 300) + bytes([0x1d, 0, 0, 0])
r = ie.decode_ht_cap(htcap(mcs=mcs))
check(r["rx_mcs"][:2] == b"\xff\xff" and len(r["rx_mcs"]) == 10 and r["highest_rate"] == 300, "MCS 集：接收位图 10 字节、最高速率 300")
check((r["tx_defined"], r["tx_rx_unequal"], r["tx_max_streams"], r["tx_unequal_mod"]) == (True, False, 4, True), "发送 MCS 集 0x1d：已定义、收发相同、最多 4 个流、允许不均匀调制")
r = ie.decode_ht_cap(htcap(mcs=bytes(10) + struct.pack("<H", 0xFFFF) + bytes([0x02, 0, 0, 0])))
check(r["highest_rate"] == 0x3FF and r["tx_rx_unequal"] and not r["tx_defined"], "最高速率只有低 10 位；0x02 = 收发不同")
r = ie.decode_ht_cap(htcap(ext=0x1234, txbf=0xAABBCCDD, asel=0x7e))
check((r["ext_caps"], r["txbf"], r["asel"]) == (0x1234, 0xAABBCCDD, 0x7e), "扩展能力、波束成形、天线选择按小端")
check(ie.decode_ht_cap(htcap()[:25]) is None and ie.decode_ht_cap(htcap() + b"\x00") is None, "长度不是 26：不合规")

print("== HT 操作（61）==")


def htop(primary=0, i1=0, i2=0, i3=0, basic=bytes(16)):
    return bytes([primary, i1]) + struct.pack("<HH", i2, i3) + basic


check(len(htop()) == ie.HT_OP_LEN == 22, "HT 操作元素 22 字节（1 + 5 + 16）")
r = ie.decode_ht_op(htop(primary=36, i1=0x0d))
check((r["primary_channel"], r["secondary_offset"], r["width_any"], r["rifs"]) == (36, 1, True, True), "主信道 36，次信道在上(1)，可用 40 MHz，RIFS")
check(ie.decode_ht_op(htop(i1=0x03))["secondary_offset"] == 3 and not ie.decode_ht_op(htop(i1=0x03))["width_any"], "次信道偏移 3 = 在主信道之下；bit2 不置则不是任意宽度")
r = ie.decode_ht_op(htop(i1=0x04))
check(r["width_any"] and not r["rifs"] and r["secondary_offset"] == 0, "信息 1 的 bit2 只是「任意信道宽度」")
r = ie.decode_ht_op(htop(i1=0x08))
check(r["rifs"] and not r["width_any"] and r["secondary_offset"] == 0, "信息 1 的 bit3 只是 RIFS")
r = ie.decode_ht_op(htop(i2=0x0017))
check((r["ht_protection"], r["nongreenfield_present"], r["obss_nonht"]) == (3, True, True), "信息 2 = 0x0017：保护 3、存在非 greenfield、OBSS 非 HT")
r = ie.decode_ht_op(htop(i2=0x0008))
check((r["ht_protection"], r["nongreenfield_present"], r["obss_nonht"]) == (0, False, False), "信息 2 的 bit3 不属于这三项")
for name, bit in (("dual_beacon", 6), ("dual_cts", 7), ("secondary_beacon", 8), ("lsig_protection", 9), ("pco_active", 10), ("pco_phase", 11)):
    r = ie.decode_ht_op(htop(i3=1 << bit))
    others = [k for k in ("dual_beacon", "dual_cts", "secondary_beacon", "lsig_protection", "pco_active", "pco_phase") if k != name and r[k]]
    check(r[name] is True and not others, "信息 3 的 bit%d 只置 %s" % (bit, name))
check(ie.decode_ht_op(htop(basic=bytes(range(16))))["basic_mcs"] == bytes(range(16)), "基本 MCS 集 16 字节")
check(ie.decode_ht_op(htop()[:21]) is None and ie.decode_ht_op(htop() + b"\x00") is None, "长度不是 22：不合规")

print("== 扩展能力（127）==")
check(ie.decode_ext_caps(b"\x04\x00\x4a") == {"octets": [4, 0, 74]}, "扩展能力：原样的字节列表")
check(ie.ext_cap_bit([1], 0) and not ie.ext_cap_bit([1], 1), "bit0 是第 0 字节的最低位")
check(ie.ext_cap_bit([0, 0x08], 11) and not ie.ext_cap_bit([0, 0x08], 3), "bit11 = 第 1 字节的 bit3")
check(ie.ext_cap_bit([0] * 7 + [0x40], 62), "bit62 = 第 7 字节的 bit6（操作模式通知）")
check(ie.ext_cap_bit([0] * 9 + [0x10], 76) and not ie.ext_cap_bit([0] * 9 + [0x10], 75), "bit76 = 第 9 字节的 bit4")
check(ie.ext_cap_bit([0] * 9 + [0x01], 72) and not ie.ext_cap_bit([0] * 9 + [0x01], 73), "bit72 = 第 9 字节的 bit0")
check(not ie.ext_cap_bit([0xff], 8) and not ie.ext_cap_bit([], 0), "超出元素长度的位视为 0")

print("== decode_all ==")
els, _ = ie.walk(b"\x00\x01a\x00\x01b\x03\x01\x06\x05\x01\x00\xff\x02\x23\x00")
d = ie.decode_all(els)
check(d["ssid"] == {"ssid": b"a"} and d["ds"] == {"channel": 6}, "同一种元素只取第一次出现的")
check("tim" not in d, "数据不合规的元素不出现在结果里")
check(set(d) == {"ssid", "ds"}, "扩展元素（ID 255）不按普通元素 ID 解码")

print("== 固定部分长度表 ==")
check(ie.FIXED_LEN == {0: 4, 1: 6, 2: 10, 3: 6, 4: 0, 5: 12, 8: 12, 10: 2, 11: 6, 12: 2}, "各管理帧子类型（已由合成帧对照 tshark）")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
