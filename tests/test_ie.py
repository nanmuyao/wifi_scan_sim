#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ie.walk：元素遍历（顺序、重复、扩展元素、被截断）。各子类型的固定部分长度由 tests/oracle 对照 tshark。"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wifi80211 import ie  # noqa: E402

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

print("== 厂商元素 / WMM / WPA ==")
v = ie.decode_vendor(b"\x00\x11\x22\x33\x44\x55")
check((v["oui"], v["type"], v["data"], v["wmm"], v["wpa"]) == (0x001122, 0x33, b"\x44\x55", None, None), "通用：OUI 3 字节、类型 1 字节、其余是数据")
check(ie.decode_vendor(b"\x00\x11\x22")["type"] is None and ie.decode_vendor(b"\x00\x11") is None, "只有 OUI：类型 None；不足 3 字节：不合规")
check(ie.decode_vendor(b"\x50\x6f\x9a\x09")["oui"] == 0x506F9A, "OUI 按大端拼成整数（50:6f:9a -> 0x506f9a）")
info = ie.decode_vendor(b"\x00\x50\xf2\x02\x00\x01\x0f")["wmm"]
check((info["subtype"], info["version"], info["qos_info"], info["ac"], info["uapsd"], info["param_set_count"]) == (0, 1, 0x0f, None, None, None),
      "WMM 信息元素：子类型 0、版本 1、QoS 信息 0x0f；没有访问类别参数，键仍然齐全")
param = (b"\x00\x50\xf2\x02\x01\x01" + bytes([0x85, 0]) + bytes([0x03, 0xa4]) + struct.pack("<H", 0)
         + bytes([0x27, 0xb5]) + struct.pack("<H", 1) + bytes([0x52, 0x43]) + struct.pack("<H", 3008) + bytes([0x62, 0x32]) + struct.pack("<H", 47))
check(len(param) == 24, "WMM 参数元素共 24 字节：OUI 3 + 类型 1 + 子类型 1 + 版本 1 + QoS 1 + 保留 1 + 4 个类别各 4（手算）")
w = ie.decode_vendor(param)["wmm"]
check((w["subtype"], w["qos_info"], w["uapsd"], w["param_set_count"]) == (1, 0x85, True, 5), "参数元素：QoS 信息 0x85 -> U-APSD 开、参数集计数 5")
check(w["ac"]["be"] == {"aci_aifsn": 0x03, "aifsn": 3, "acm": False, "aci": 0, "ecw": 0xa4, "ecw_min": 4, "ecw_max": 10, "txop": 0}, "BE：AIFSN 3、ECWmin 4、ECWmax 10")
check(w["ac"]["bk"]["aifsn"] == 7 and w["ac"]["bk"]["aci"] == 1 and w["ac"]["bk"]["ecw_min"] == 5 and w["ac"]["bk"]["ecw_max"] == 11 and w["ac"]["bk"]["txop"] == 1,
      "BK：ACI 1（0x27 的 bit5-6）、AIFSN 7")
check(w["ac"]["vi"]["acm"] is True and w["ac"]["vi"]["aifsn"] == 2 and w["ac"]["vi"]["aci"] == 2 and w["ac"]["vi"]["txop"] == 3008, "VI：ACM 置位（0x52 的 bit4）、AIFSN 2、TXOP 3008")
check(w["ac"]["vo"]["aci"] == 3 and w["ac"]["vo"]["ecw_min"] == 2 and w["ac"]["vo"]["ecw_max"] == 3 and w["ac"]["vo"]["txop"] == 47, "VO：ACI 3、ECWmin 2、ECWmax 3、TXOP 47（小端）")
short = ie.decode_vendor(param[:-1])["wmm"]
check(short["subtype"] == 1 and short["ac"] is None and short["uapsd"] is True, "参数元素缺 1 字节：访问类别不解（None），QoS 信息照常")
check(ie.decode_vendor(b"\x00\x50\xf2\x02\x01")["wmm"] is None, "WMM 不足子类型 + 版本：None")
wpa = b"\x00\x50\xf2\x01" + LE(1) + S(2, b"\x00\x50\xf2") + LE(2) + S(4, b"\x00\x50\xf2") + S(2, b"\x00\x50\xf2") + LE(1) + S(2, b"\x00\x50\xf2")
p = ie.decode_vendor(wpa)["wpa"]
check(p["version"] == 1 and p["group"] == (0x0050f2, 2) and p["pairwise"] == [(0x0050f2, 4), (0x0050f2, 2)] and p["akm"] == [(0x0050f2, 2)] and not p["malformed"],
      "WPA：版本 1、组密码 TKIP、成对 CCMP + TKIP、AKM PSK，套件 OUI 是 0x0050f2")
p = ie.decode_vendor(b"\x00\x50\xf2\x01" + LE(1) + S(2, b"\x00\x50\xf2") + LE(5) + S(4, b"\x00\x50\xf2"))["wpa"]
check(p["malformed"] and p["group"] == (0x0050f2, 2) and p["pairwise"] is None, "WPA 成对套件计数 5 而只有 1 个：畸形，组密码保留")
check(ie.decode_vendor(b"\x00\x50\xf2\x01\x01")["wpa"] is None, "WPA 不足版本号：None")
check(ie.decode_vendor(b"\x00\x50\xf2\x04\x10\x4a")["wmm"] is None and ie.decode_vendor(b"\x00\x50\xf2\x04\x10\x4a")["wpa"] is None, "类型 4（WPS）不挂专用解码")
check(ie.decode_vendor(b"\x00\x10\x18\x02\x01")["wmm"] is None, "同样的类型 2 但 OUI 不是 0x0050f2（Broadcom）：不当 WMM 解")
els, _ = ie.walk(b"\xdd\x04\x00\x11\x22\x33" + b"\xdd\x02\x00\x11" + b"\xdd\x07\x00\x50\xf2\x02\x00\x01\x0f")
vs = ie.vendor_elements(els)
check([v["oui"] if v else None for v in vs] == [0x001122, None, 0x0050f2], "vendor_elements：按出现顺序，不合规的位置是 None")
d = ie.decode_all(els)
check(len(d["vendors"]) == 3 and d["wmm"]["subtype"] == 0 and "wpa" not in d, "decode_all：vendors 是全部，wmm 取第一个，没有 WPA 就没有这个键")

print("== 厂商元素的边界 ==")
check(ie.decode_vendor(b"\x00\x11\x22\x33")["type"] == 0x33 and ie.decode_vendor(b"\x00\x11\x22\x33")["data"] == b"", "OUI + 类型正好 4 字节：类型有，数据为空")
check(ie.decode_vendor(b"\x00\x10\x18\x02\x00\x01\x0f")["wmm"] is None, "Broadcom（0x001018）的类型 2 + 与 WMM 信息元素一样的数据：不当 WMM")
check(ie.decode_vendor(b"\x00\x50\xf3\x02\x00\x01\x0f")["wmm"] is None, "OUI 差 1（0x0050f3）：不当 WMM")
two = ie.decode_vendor(b"\x00\x50\xf2\x02\x00\x01")["wmm"]
check(two is not None and two["subtype"] == 0 and two["version"] == 1 and two["qos_info"] is None, "WMM 数据正好 2 字节（子类型 + 版本）：解得出来，QoS 信息 None")
p_ = ie.decode_vendor(b"\x00\x50\xf2\x02\x01\x01\x8f\x00" + bytes([0x0f, 0xff, 0, 0]) + bytes(12))["wmm"]
check(p_["param_set_count"] == 15 and p_["uapsd"] is True and p_["ac"]["be"]["aifsn"] == 15 and p_["ac"]["be"]["ecw_min"] == 15 and p_["ac"]["be"]["ecw_max"] == 15,
      "参数集计数、AIFSN、ECW 都是满 4 位（15），不是 3 位")
tspec = ie.decode_vendor(b"\x00\x50\xf2\x02\x02\x01\x8f\x00" + bytes(16))["wmm"]
check(tspec["subtype"] == 2 and tspec["uapsd"] is None and tspec["param_set_count"] is None and tspec["ac"] is None, "子类型 2（TSPEC）：不按参数元素解")
els, _ = ie.walk(b"\xdd\x07\x00\x50\xf2\x02\x00\x01\x01" + b"\xdd\x07\x00\x50\xf2\x02\x00\x01\x02")
check(ie.decode_all(els)["wmm"]["qos_info"] == 1 and len(ie.decode_all(els)["vendors"]) == 2, "两个 WMM 元素：wmm 取第一个，vendors 里有两个")

print("== 移动域 / BSS 最大空闲周期 / RSNXE ==")
m = ie.decode_mobility_domain(b"\x01\x02\x01")
check(m == {"mdid": 0x0201, "ft_capab": 1, "ft_over_ds": True, "resource_request": False}, "移动域：ID 按小端（01 02 -> 0x0201），bit0 通过 DS 的 FT")
m = ie.decode_mobility_domain(b"\xa1\xb2\x02")
check(m["mdid"] == 0xb2a1 and not m["ft_over_ds"] and m["resource_request"], "移动域：bit1 资源请求协议；两个位不混")
check(ie.decode_mobility_domain(b"\x01\x02") is None and ie.decode_mobility_domain(b"\x01\x02\x00\x00") is None, "移动域：长度必须是 3")
print("== 快速切换元素（FTE）==")
AN, SN = bytes(range(32)), bytes(range(100, 132))
sub = bytes([1, 6]) + bytes([2, 0, 0, 0, 0, 1]) + bytes([3, 4]) + b"r0kh"
f16 = ie.decode_ft(bytes([0x00, 0x03]) + bytes(range(200, 216)) + AN + SN + sub)
check((f16["mic_length"], f16["element_count"], f16["rsnxe_used"], f16["mic_control"]) == (16, 3, False, 0x0300), "MIC Control：编码 0 = 16 字节，第 2 字节是元素个数")
check(f16["mic"] == bytes(range(200, 216)) and f16["anonce"] == AN and f16["snonce"] == SN, "MIC / ANonce / SNonce 的位置")
check(f16["r1kh_id"] == bytes([2, 0, 0, 0, 0, 1]) and f16["r0kh_id"] == b"r0kh" and f16["subelements"] == [(1, bytes([2, 0, 0, 0, 0, 1])), (3, b"r0kh")], "子元素：R1KH-ID、R0KH-ID，原样保留")
f24 = ie.decode_ft(bytes([0x03, 0x04]) + bytes(24) + AN + SN + sub)
check(f24["mic_length"] == 24 and f24["rsnxe_used"] and f24["element_count"] == 4 and f24["anonce"] == AN and f24["r0kh_id"] == b"r0kh", "编码 1 = 24 字节 MIC，bit0 = RSNXE 已用；后面的字段整体后移")
check(ie.decode_ft(bytes([0x01, 0]) + bytes(16) + AN + SN)["rsnxe_used"] is True and ie.decode_ft(bytes([0x02, 0]) + bytes(24) + AN + SN)["rsnxe_used"] is False, "RSNXE 已用只看 bit0（不是 bit1，那是 MIC 长度编码的最低位）")
check(ie.decode_ft(bytes([0x04, 0]) + bytes(32) + AN + SN)["mic_length"] == 32, "编码 2 = 32 字节 MIC")
check(ie.decode_ft(bytes([0x06, 0]) + bytes(40) + AN + SN) is None, "编码 3 不认识：None")
check(ie.decode_ft(bytes(2 + 16 + 63)) is None and ie.decode_ft(b"\x00") is None and ie.decode_ft(b"") is None, "数据不够长：None")
check(ie.decode_ft(bytes(2 + 16 + 64) + bytes([1, 6, 0, 0])) is None and ie.decode_ft(bytes(2 + 16 + 64) + bytes([1])) is None, "子元素长度越界 / 只剩一个字节：None")
g = ie.decode_ft(bytes(2 + 16 + 64) + bytes([2, 3, 9, 9, 9]) + bytes([1, 6]) + bytes(6) + bytes([1, 6]) + bytes([7] * 6))
check(g["r1kh_id"] == bytes(6) and g["r0kh_id"] is None and g["gtk"] == bytes([9, 9, 9]) and len(g["subelements"]) == 3, "同一种子元素出现两次：字段取第一个；没有的 R0KH-ID 为 None；GTK 子元素")
els, _ = ie.walk(bytes([55, 2 + 16 + 64]) + bytes(2 + 16 + 64))
check(ie.decode_all(els)["fte"]["mic_length"] == 16, "decode_all 认 55 号元素")
b_ = ie.decode_bss_max_idle(struct.pack("<HB", 292, 1))
check(b_ == {"period": 292, "options": 1, "protected_keepalive": True}, "BSS 最大空闲：周期 292（小端）、选项 bit0 受保护保活")
check(ie.decode_bss_max_idle(struct.pack("<HB", 256, 0))["period"] == 256 and not ie.decode_bss_max_idle(struct.pack("<HB", 1, 2))["protected_keepalive"],
      "周期 256（高字节为 1）；选项 bit1 不是保活位")
check(ie.decode_bss_max_idle(b"\x01\x00") is None and ie.decode_bss_max_idle(b"\x01\x00\x00\x00") is None, "BSS 最大空闲：长度必须正好是 3（短了、长了都不合规）")
r = ie.decode_rsnxe(b"\x20")
check((r["length_field"], r["sae_h2e"], r["sae_pk"], r["protected_twt"]) == (0, True, False, False) and r["octets"] == [0x20], "RSNXE 0x20：只有 H2E（bit5）")
for name, val in (("protected_twt", 0x10), ("sae_h2e", 0x20), ("sae_pk", 0x40)):
    r = ie.decode_rsnxe(bytes([val]))
    others = [k for k in ie.RSNX_BITS if k != name and r[k]]
    check(r[name] is True and not others, "RSNXE 0x%02x 只置 %s" % (val, name))
r = ie.decode_rsnxe(b"\x21\x03")
check(r["length_field"] == 1 and r["value"] == 0x0321 and r["sae_h2e"] and not r["sae_pk"], "两个字节：长度字段 bit0-3 = 1，整个元素按小端拼成 0x0321")
check(ie.decode_rsnxe(b"\x0f")["length_field"] == 15, "长度字段是 4 位（0x0f -> 15）")
check(ie.decode_rsnxe(b"") is None, "RSNXE：空元素不合规")

print("== Multi-Link（扩展 ID 107）==")
MAC1, MAC2 = b"\x02\x00\x00\x00\x0a\x00", b"\xe6\xcc\x7b\x74\xe1\x42"


def per_sta(link, mac, fixed, elements):
    info = (bytes([7]) + mac) if mac else bytes([1])
    data = struct.pack("<H", link | 0x10 | (0x20 if mac else 0)) + info + fixed + elements
    return bytes([0, len(data)]) + data


def ml(control, common, *subelts):
    return struct.pack("<H", control) + bytes([len(common) + 1]) + common + b"".join(subelts)


nest = b"\x01\x02\x82\x84" + b"\x32\x01\x30"
m = ie.decode_multi_link(ml(0x0000, MAC1, per_sta(1, MAC2, b"\x11\x04", nest)), fixed=2)
check((m["type"], m["type_name"], m["common_len"], m["mld_mac"], m["link_id"], m["malformed"]) == (0, "basic", 7, "02:00:00:00:0a:00", None, False),
      "basic：类型 0、公共信息长度 7、MLD MAC 地址")
s0 = m["stas"][0]
check((s0["link_id"], s0["complete"], s0["mac"], s0["info_len"], s0["fixed_fields"]) == (1, True, "e6:cc:7b:74:e1:42", 7, b"\x11\x04"),
      "每站点配置：链路 ID 1、完整配置、STA MAC、STA 信息长度 7、外层帧的固定字段 2 字节")
check([(e.id, e.data) for e in s0["elements"]] == [(1, b"\x82\x84"), (50, b"\x30")], "固定字段之后才是嵌套元素")
m = ie.decode_multi_link(ml(0x0010, MAC1 + b"\x25"), fixed=0)
check(m["link_id"] == 5 and m["common_len"] == 8, "存在位图 bit4：公共信息里 MAC 之后有链路 ID（只取低 4 位：0x25 -> 5）")
m = ie.decode_multi_link(ml(0x0000, MAC1 + b"\x25"), fixed=0)
check(m["link_id"] is None and m["common_len"] == 8, "存在位图 bit4 没置位：不读链路 ID")
for typ, name in ((0, "basic"), (1, "probe_request"), (2, "reconfiguration"), (3, "tdls"), (4, "priority_access")):
    check(ie.decode_multi_link(ml(typ, b"\x00"))["type_name"] == name and ie.decode_multi_link(ml(typ, b"\x00"))["type"] == typ, "类型 %d = %s" % (typ, name))
m = ie.decode_multi_link(ml(0x0800 | 0x0100, MAC1))
check(m["type"] == 0 and m["control"] == 0x0900, "类型只取 bit0-2；存在位图的位不影响类型")
m = ie.decode_multi_link(ml(0x0001, MAC1))
check(m["type"] == 1 and m["mld_mac"] is None and m["common_len"] == 7 and m["stas"] == [], "非 basic 类型（probe request）：公共信息够长也不当 MLD MAC 读")
m = ie.decode_multi_link(struct.pack("<H", 0) + bytes([len(MAC1) + 2]) + MAC1)
check(m["malformed"] and m["mld_mac"] is None, "公共信息声明的长度比实际多 1 字节：畸形（差一也要抓住）")
m = ie.decode_multi_link(struct.pack("<H", 0) + bytes([len(MAC1) + 1]) + MAC1)
check(not m["malformed"] and m["mld_mac"] == "02:00:00:00:0a:00", "公共信息声明的长度正好等于实际：不是畸形")
m = ie.decode_multi_link(ml(0, MAC1, per_sta(12, MAC2, b"", b"")))
check(m["stas"][0]["link_id"] == 12, "链路 ID 是 STA 控制的低 4 位（12），不是 3 位")
d_ = struct.pack("<H", 0x0011) + bytes([7]) + MAC2          # 完整配置位置位、「有 MAC」位没置位，但 STA 信息有 7 字节
m = ie.decode_multi_link(ml(0, MAC1, bytes([0, len(d_)]) + d_))
check(m["stas"][0]["complete"] and m["stas"][0]["mac"] is None, "「有 MAC 地址」是 STA 控制的 bit5，不是 bit4（完整配置）")
d_ = struct.pack("<H", 0x0021) + bytes([7]) + MAC2          # 「有 MAC」置位、完整配置没置位
m = ie.decode_multi_link(ml(0, MAC1, bytes([0, len(d_)]) + d_))
check(not m["stas"][0]["complete"] and m["stas"][0]["mac"] == "e6:cc:7b:74:e1:42", "反过来：只有「有 MAC」位")
m = ie.decode_multi_link(ml(0, MAC1, per_sta(1, None, b"", b""), per_sta(2, MAC2, b"", b"\x03\x01\x06")))
check([(s["link_id"], s["mac"], s["info_len"]) for s in m["stas"]] == [(1, None, 1), (2, "e6:cc:7b:74:e1:42", 7)], "两个站点配置；没有 MAC 时 STA 信息长度是 1")
check(m["stas"][1]["elements"][0].id == 3, "第二个站点的嵌套元素")
m = ie.decode_multi_link(ml(0, MAC1, bytes([1, 3]) + b"abc", per_sta(1, MAC2, b"", b"")))
check(len(m["stas"]) == 1 and not m["malformed"], "ID 不是 0 的子元素被跳过")
m = ie.decode_multi_link(ml(0, MAC1) + bytes([0, 50]) + b"\x01\x00")
check(m["malformed"] and m["stas"] == [] and m["mld_mac"] == "02:00:00:00:0a:00", "子元素长度超出数据：畸形，公共信息保留")
m = ie.decode_multi_link(struct.pack("<H", 0) + bytes([40]) + MAC1)
check(m["malformed"] and m["mld_mac"] is None, "公共信息长度超出数据：畸形")
m = ie.decode_multi_link(struct.pack("<H", 0) + bytes([0]))
check(m["malformed"], "公共信息长度 0（连长度字节自己都不算）：畸形")
check(ie.decode_multi_link(b"\x00\x00") is None, "不足 3 字节：None")
data = ml(0, MAC1, bytes([0, 3]) + struct.pack("<H", 0x31) + bytes([9]))
check(ie.decode_multi_link(data)["malformed"], "STA 信息长度 9 超出子元素：畸形，不崩溃")

print("== flatten ==")
inner = ml(0, MAC1, per_sta(1, MAC2, b"\x11\x04", b"\x01\x01\x82\xff\x02\x23\x00"))     # 嵌套：速率元素 + 一个扩展元素 0x23
raw = b"\x00\x01a" + bytes([255, len(inner) + 1, 107]) + inner + b"\x30\x00"
els, _ = ie.walk(raw)
check([(e.id, e.ext) for e in els] == [(0, None), (255, 107), (48, None)], "遍历：主体 3 个元素")
flat = ie.flatten(els, fixed=2)
check([(e.id, e.ext) for e in flat] == [(0, None), (255, 107), (1, None), (255, 0x23), (48, None)],
      "展开：嵌套的元素紧跟在 Multi-Link 元素之后，后面的主体元素顺序不变")
check(ie.ids(flat) == ([0, 1, 48], [107, 35]), "ids()：普通元素 [0, 1, 48]，扩展元素 [107, 35]")
check([(e.id, e.ext) for e in ie.flatten(els, fixed=0)] != [(e.id, e.ext) for e in flat], "固定字段长度不同，嵌套元素的起点就不同")
check(ie.flatten(ie.walk(b"\x00\x01a\x30\x00")[0], 2) == ie.walk(b"\x00\x01a\x30\x00")[0], "没有 Multi-Link：原样")
check(ie.flatten(ie.walk(bytes([255, 3, 107, 0, 0]))[0], 2)[0].ext == 107 and len(ie.flatten(ie.walk(bytes([255, 3, 107, 0, 0]))[0], 2)) == 1, "Multi-Link 太短（None）：只留它自己")
check(ie.ML_PROFILE_FIXED == {0: 2, 1: 4, 2: 2, 3: 4, 5: 2, 8: 2}, "固定字段长度表（已由 tshark 对照合成帧确认）")

print("== HE（802.11ax）能力 / 操作 ==")
check(ie.he_mcs_map(0xfffa) == [2, 2, 3, 3, 3, 3, 3, 3], "HE-MCS 表 0xfffa：NSS1、NSS2 支持 MCS 0-11，其余不支持（样例里的真实值）")
check(ie.he_mcs_map(0x001b) == [3, 2, 1, 0, 0, 0, 0, 0] and ie.he_mcs_map(0xaaaa) == [2] * 8 and ie.he_mcs_map(0) == [0] * 8, "每个空间流 2 位，NSS1 在最低位")


def hecap(mac=b"\x01\x78\xc8\x12\x40\x00", phy0=0x02, maps=((0xfffa, 0xfffa),), tail=b""):
    body = mac + bytes([phy0]) + bytes(range(1, 11))
    for rx, tx in maps:
        body += struct.pack("<HH", rx, tx)
    return body + tail


h = ie.decode_he_cap(hecap())
check(h["mac_caps"] == 0x0000004012c87801 and h["phy0"] == 0x02 and len(h["phy_caps"]) == 11, "MAC 能力 6 字节按小端 -> 0x4012c87801（样例里的真实值）；PHY 能力 11 字节")
check((h["rx_lte80"], h["tx_lte80"], h["rx_160"], h["tx_160"], h["rx_80p80"], h["tx_80p80"], h["ppe"]) == (0xfffa, 0xfffa, None, None, None, None, b""),
      "没有 160 / 80+80 位：只有 80MHz 及以下的一对表")
h = ie.decode_he_cap(hecap(phy0=0x08, maps=((0xfffa, 0xfffb), (0xfffe, 0xfffc))))
check((h["rx_lte80"], h["tx_lte80"], h["rx_160"], h["tx_160"], h["rx_80p80"]) == (0xfffa, 0xfffb, 0xfffe, 0xfffc, None), "PHY 第 0 字节的 0x08：多一对 160MHz 表（接收在前）")
h = ie.decode_he_cap(hecap(phy0=0x10, maps=((0xfffa, 0xfffa), (0xfff0, 0xffc0))))
check((h["rx_160"], h["rx_80p80"], h["tx_80p80"]) == (None, 0xfff0, 0xffc0), "0x10：多一对 80+80MHz 表，160 没有")
h = ie.decode_he_cap(hecap(phy0=0x18, maps=((0xfffa, 0xfffa), (0xfffe, 0xfffc), (0xfff0, 0xffc0))))
check((h["rx_160"], h["tx_160"], h["rx_80p80"], h["tx_80p80"]) == (0xfffe, 0xfffc, 0xfff0, 0xffc0), "两位都置：先 160 后 80+80")
h = ie.decode_he_cap(hecap(phy0=0x60, maps=((1, 2),)))
check(h["rx_160"] is None and h["rx_80p80"] is None, "0x60（242 音 RU 位）不引出额外的表")
h = ie.decode_he_cap(hecap(phy0=0x08, maps=((0xfffa, 0xfffa),)))
check(h["rx_160"] is None and h["tx_160"] is None, "声明有 160MHz 表但数据不够：读不出来（None），不越界")
h = ie.decode_he_cap(hecap(tail=b"\xde\xad"))
check(h["ppe"] == b"\xde\xad", "其余字节放进 ppe（PPE 门限，不解）")
h = ie.decode_he_cap(hecap(phy0=0x08, maps=((1, 2), (3, 4)), tail=b"\x99"))
check(h["ppe"] == b"\x99", "有 160 表时 ppe 从 160 表之后算起")
check(len(hecap()) == 21 and ie.decode_he_cap(hecap()[:20]) is None and ie.decode_he_cap(hecap()) is not None, "最少 21 字节（6 + 11 + 4）；少 1 字节：None")
check(ie.decode_he_cap(hecap(mac=b"\xff" * 6))["mac_caps"] == 0xFFFFFFFFFFFF, "MAC 能力满 48 位")


def heop(params=0, color=0, basic=0xfffc, extra=b""):
    return bytes([params & 255, params >> 8 & 255, params >> 16 & 255, color]) + struct.pack("<H", basic) + extra


o = ie.decode_he_op(heop())
check((o["params"], o["default_pe_duration"], o["twt_required"], o["vht_op"], o["max_cohosted_bssid"], o["six_ghz"], o["basic_mcs_nss"]) == (0, 0, False, None, None, None, 0xfffc),
      "全 0 参数：没有可选部分")
check(ie.decode_he_op(heop(params=0x05))["default_pe_duration"] == 5 and not ie.decode_he_op(heop(params=0x05))["twt_required"], "bit0-2 默认 PE 时长")
check(ie.decode_he_op(heop(params=0x08))["twt_required"] and ie.decode_he_op(heop(params=0x08))["default_pe_duration"] == 0, "bit3 要求 TWT")
check(ie.decode_he_op(heop(params=0x003ff0))["txop_rts_threshold"] == 0x3ff and not ie.decode_he_op(heop(params=0x003ff0))["twt_required"], "bit4-13 TXOP 时长 RTS 门限（10 位）")
for name, bit in (("vht_op_present", 14), ("co_hosted_bss", 15), ("er_su_disable", 16), ("six_ghz_present", 17)):
    r = ie.decode_he_op(heop(params=1 << bit))
    others = [k for k in ("vht_op_present", "co_hosted_bss", "er_su_disable", "six_ghz_present") if k != name and r[k]]
    check(r[name] is True and not others, "参数 bit%d 只置 %s" % (bit, name))
o = ie.decode_he_op(heop(color=0xea))
check((o["bss_color"], o["partial_bss_color"], o["bss_color_disabled"], o["bss_color_info"]) == (0x2a, True, True, 0xea), "BSS 颜色信息 0xea：颜色 42、部分颜色、已禁用")
o = ie.decode_he_op(heop(color=0x40))
check(o["partial_bss_color"] and not o["bss_color_disabled"] and o["bss_color"] == 0, "bit6 只是部分颜色")
o = ie.decode_he_op(heop(color=0x80))
check(o["bss_color_disabled"] and not o["partial_bss_color"] and o["bss_color"] == 0, "bit7 只是颜色禁用")
o = ie.decode_he_op(heop(params=0x00c000 | 0x020000, extra=b"\x02\x2a\x00" + b"\x03" + b"\x25\x82\x27\x00\x00"))
check(o["vht_op"] == {"channel_width": 2, "seg0": 0x2a, "seg1": 0} and o["max_cohosted_bssid"] == 3
      and o["six_ghz"] == {"primary_channel": 0x25, "control": 0x82, "seg0": 0x27, "seg1": 0, "min_rate": 0}, "三个可选部分按 VHT、共址、6GHz 的顺序")
o = ie.decode_he_op(heop(params=0x020000, extra=b"\x25\x82\x27\x00\x00"))
check(o["vht_op"] is None and o["max_cohosted_bssid"] is None and o["six_ghz"]["primary_channel"] == 0x25, "只有 6GHz：前两个可选部分不占字节")
o = ie.decode_he_op(heop(params=0x00c000 | 0x020000, extra=b"\x02\x2a\x00\x03\x25"))
check(o["vht_op"] is not None and o["max_cohosted_bssid"] == 3 and o["six_ghz"] is None, "6GHz 部分不够 5 字节：读不出来（None），前面的保留")
check(len(heop()) == 6 and ie.decode_he_op(heop()[:5]) is None and ie.decode_he_op(heop()) is not None, "最少 6 字节（3 + 1 + 2）；少 1 字节：None")

els, _ = ie.walk(bytes([255, 1 + len(hecap()), 35]) + hecap() + bytes([255, 7, 36]) + heop() + bytes([255, 1 + len(hecap(phy0=0x04)), 35]) + hecap(phy0=0x04))
d = ie.decode_all(els)
check(d["he_cap"]["phy0"] == 0x02 and d["he_op"]["basic_mcs_nss"] == 0xfffc, "decode_all：扩展元素按扩展 ID 解码，同种取第一个（0x02 而不是后面的 0x04）")

print("== decode_all ==")
els, _ = ie.walk(b"\x00\x01a\x00\x01b\x03\x01\x06\x05\x01\x00\xff\x02\x23\x00")
d = ie.decode_all(els)
check(d["ssid"] == {"ssid": b"a"} and d["ds"] == {"channel": 6}, "同一种元素只取第一次出现的")
check("tim" not in d, "数据不合规的元素不出现在结果里")
check(set(d) - {"vendors"} == {"ssid", "ds"} and d["vendors"] == [], "扩展元素（ID 255）不按普通元素 ID 解码；没有厂商元素时 vendors 是空列表")

print("== 固定部分长度表 ==")
check(ie.FIXED_LEN == {0: 4, 1: 6, 2: 10, 3: 6, 4: 0, 5: 12, 8: 12, 10: 2, 11: 6, 12: 2}, "各管理帧子类型（已由合成帧对照 tshark）")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
