# -*- coding: utf-8 -*-
"""
手工拼 802.11 帧头，写成 pcap（链路类型 105，无 radiotap），给差分测试用。

公开样例里几乎没有 4 地址帧、HT 控制字段、分片等头部变体，这里按标准的字段布局自己造，
再让 tshark（独立实现）去解析、与我们的结果对比。这里只管帧头，帧体是随便的几个字节。
"""
import struct

A1, A2, A3, A4 = (bytes.fromhex(x) for x in ("021100000001", "021100000002", "021100000003", "021100000004"))


def fc_word(ftype, subtype, tods=0, fromds=0, morefrag=0, retry=0, pwr=0, moredata=0, prot=0, order=0):
    flags = tods | fromds << 1 | morefrag << 2 | retry << 3 | pwr << 4 | moredata << 5 | prot << 6 | order << 7
    return ftype << 2 | subtype << 4 | flags << 8


def frame(ftype, subtype, tods=0, fromds=0, order=0, seq=7, frag=0, morefrag=0, qos=None, htc=None,
          addr4=None, body=b"\xaa\xaa\x03\x00\x00\x00\x08\x00", duration=44, prot=0):
    """qos: QoS Control 的 16 位值；htc: HT Control 的 32 位值；addr4：只在 ToDS=FromDS=1 的帧里有。"""
    h = struct.pack("<HH", fc_word(ftype, subtype, tods, fromds, morefrag=morefrag, order=order, prot=prot), duration)
    h += A1 + A2 + A3 + struct.pack("<H", seq << 4 | frag)
    if tods and fromds:
        h += addr4 if addr4 is not None else A4
    if qos is not None:
        h += struct.pack("<H", qos)
    if htc is not None:
        h += struct.pack("<I", htc)
    return h + body


def qos_word(tid=0, eosp=0, ack_policy=0, amsdu=0, txop=0):
    return tid | eosp << 4 | ack_policy << 5 | amsdu << 7 | txop << 8


def ie(eid, data=b"", ext=None):
    """一个信息元素；ext 不为 None 时是扩展元素（ID 255 + 扩展 ID）。"""
    if ext is not None:
        data = bytes([ext]) + data
        eid = 255
    return bytes([eid, len(data)]) + data


IES = ie(0, b"synth") + ie(1, b"\x82\x84\x8b\x96") + ie(3, b"\x06") + ie(221, b"\x00\x11\x22\x01\x02") + \
    ie(221, b"\x00\x11\x23\x02") + ie(50, b"\x0c\x12") + ie(7, b"US \x01\x0b\x14")


def mgmt(subtype, fixed, ies=IES, **kw):
    return frame(0, subtype, body=b"\x00" * fixed + ies, **kw)


def cases():
    """[(说明, 帧字节)]"""
    out = []
    # 管理帧：固定部分之后是信息元素；同一 ID 出现两次（221）、扩展元素、各子类型的固定部分长度
    for name, sub, fixed in (("Association Request", 0, 4), ("Association Response", 1, 6),
                             ("Reassociation Request", 2, 10), ("Reassociation Response", 3, 6),
                             ("Probe Request", 4, 0), ("Probe Response", 5, 12), ("Beacon", 8, 12),
                             ("Disassociation", 10, 2), ("Authentication (open)", 11, 6), ("Deauthentication", 12, 2)):
        out.append(("%s + elements" % name, mgmt(sub, fixed)))
    # 元素内容：隐藏 SSID、满长度的非 UTF-8 SSID、带基本速率位的速率表、TIM、国家（含运行类别三元组 + 填充）、ERP
    rates8 = bytes([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])
    out.append(("Beacon hidden SSID", mgmt(8, 12, ie(0, b"") + ie(1, rates8) + ie(3, b"\x0b"))))
    out.append(("Beacon 32-byte non-UTF8 SSID", mgmt(8, 12, ie(0, bytes(range(0x80, 0xa0)) ) + ie(1, rates8))))
    out.append(("Beacon rates + extended rates", mgmt(8, 12, ie(0, b"r") + ie(1, rates8) + ie(50, bytes([0x30, 0x48, 0x60, 0x6c])))))
    out.append(("Beacon TIM multicast + offset + bitmap", mgmt(8, 12, ie(0, b"t") + ie(5, bytes([1, 3, 0x05, 0x10, 0x20, 0x30])))))
    out.append(("Beacon TIM no multicast, offset 0, 1-byte bitmap", mgmt(8, 12, ie(0, b"t") + ie(5, bytes([0, 2, 0x00, 0x00])))))
    out.append(("Beacon country: channel triplet", mgmt(8, 12, ie(0, b"c") + ie(7, b"US \x01\x0b\x1e\x24\x04\x17"))))
    out.append(("Beacon country: operating-class triplet + padding", mgmt(8, 12, ie(0, b"c") + ie(7, b"DEO" + bytes([0xc9, 0x0d, 0x04]) + bytes([36, 4, 23]) + b"\x00"))))
    out.append(("Beacon country: negative max power", mgmt(8, 12, ie(0, b"c") + ie(7, b"JP\x20" + bytes([1, 13, 0xf6])))))
    for v in (0x00, 0x01, 0x02, 0x04, 0x07):
        out.append(("Beacon ERP 0x%02x" % v, mgmt(8, 12, ie(0, b"e") + ie(42, bytes([v])))))
    # RSN：各种套件组合，以及元素在不同位置结束
    def s(t, oui=b"\x00\x0f\xac"):
        return oui + bytes([t])
    le = lambda n: bytes([n & 255, n >> 8])        # noqa: E731
    rsn_wpa2 = le(1) + s(4) + le(1) + s(4) + le(1) + s(2) + le(0x000c)
    out.append(("Beacon RSN WPA2-PSK CCMP", mgmt(8, 12, ie(0, b"r") + ie(48, rsn_wpa2))))
    out.append(("Beacon RSN WPA3-SAE PMF required", mgmt(8, 12, ie(0, b"r") + ie(48, le(1) + s(4) + le(1) + s(4) + le(1) + s(8) + le(0x00c0) + le(0) + s(6)))))
    out.append(("Assoc Request RSN with PMKID", mgmt(0, 4, ie(0, b"r") + ie(48, le(1) + s(4) + le(1) + s(4) + le(1) + s(8) + le(0x00c0) + le(1) + bytes(range(16)) + s(6)))))
    out.append(("Beacon RSN TKIP + CCMP pairwise, PSK + PSK-SHA256", mgmt(8, 12, ie(0, b"r") + ie(48, le(1) + s(2) + le(2) + s(2) + s(4) + le(2) + s(2) + s(6) + le(0x0000)))))
    out.append(("Beacon RSN Suite-B 192 (GCMP-256, BIP-GMAC-256)", mgmt(8, 12, ie(0, b"r") + ie(48, le(1) + s(9) + le(1) + s(9) + le(1) + s(12) + le(0x00cc) + le(0) + s(12)))))
    out.append(("Beacon RSN OWE + extended key id", mgmt(8, 12, ie(0, b"r") + ie(48, le(1) + s(4) + le(1) + s(4) + le(1) + s(18) + le(0x200c)))))
    out.append(("Beacon RSN FT-PSK", mgmt(8, 12, ie(0, b"r") + ie(48, le(1) + s(4) + le(1) + s(4) + le(1) + s(4) + le(0x000c)))))
    out.append(("Beacon RSN vendor OUI group cipher", mgmt(8, 12, ie(0, b"r") + ie(48, le(1) + s(2, oui=b"\x00\x50\xf2") + le(1) + s(2, oui=b"\x00\x50\xf2") + le(1) + s(2, oui=b"\x00\x50\xf2")))))
    out.append(("Beacon RSN version and group cipher only", mgmt(8, 12, ie(0, b"r") + ie(48, le(1) + s(4)))))
    out.append(("Beacon RSN ends after AKM list", mgmt(8, 12, ie(0, b"r") + ie(48, le(1) + s(4) + le(1) + s(4) + le(1) + s(2)))))
    out.append(("Beacon RSN ends after capabilities", mgmt(8, 12, ie(0, b"r") + ie(48, le(1) + s(4) + le(1) + s(4) + le(1) + s(2) + le(0x0080)))))
    # HT 能力 / 操作 / 扩展能力
    def htcap(caps=0, ampdu=0x1b, rx=b"\xff\xff\x00\x00\x00", rate=0, mcs12=0, extcaps=0, txbf=0, asel=0):
        mcs = (rx + bytes(10 - len(rx))) + struct.pack("<H", rate) + bytes([mcs12, 0, 0, 0])
        return struct.pack("<HB", caps, ampdu) + mcs + struct.pack("<HIB", extcaps, txbf, asel)

    def htop(primary=6, i1=0, i2=0, i3=0, basic=b"\xff"):
        return bytes([primary, i1]) + struct.pack("<HH", i2, i3) + basic + bytes(15)

    for bit in (0, 1, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15):
        out.append(("Beacon HT cap bit %d" % bit, mgmt(8, 12, ie(0, b"h") + ie(45, htcap(caps=1 << bit)))))
    for v in (1, 2, 3):
        out.append(("Beacon HT cap SM power save %d / RX STBC %d" % (v, v), mgmt(8, 12, ie(0, b"h") + ie(45, htcap(caps=v << 2 | v << 8)))))
    out.append(("Beacon HT cap A-MPDU 0x1f, MCS 0-15, 300 Mbps, tx unequal", mgmt(8, 12, ie(0, b"h") + ie(45, htcap(ampdu=0x1f, rx=b"\xff\xff", rate=300, mcs12=0x1d)))))
    out.append(("Beacon HT cap tx streams 4", mgmt(8, 12, ie(0, b"h") + ie(45, htcap(mcs12=0x0d)))))
    for name, kw in (("secondary above, 40MHz, RIFS", dict(i1=0x0d, primary=36)), ("any width only", dict(i1=0x04)),
                     ("RIFS only", dict(i1=0x08)), ("secondary below", dict(i1=0x03, primary=40)),
                     ("protection 3 + non-greenfield + OBSS", dict(i2=0x0017)), ("dual beacon, dual CTS, PCO", dict(i3=0x0cc0)),
                     ("channel 13", dict(primary=13))):
        out.append(("Beacon HT operation: %s" % name, mgmt(8, 12, ie(0, b"o") + ie(45, htcap()) + ie(61, htop(**kw)))))
    for n in (1, 3, 8, 10, 11):
        for bit in sorted({0, 19, 62, 70, 84} & set(range(n * 8))):
            octets = bytearray(n)
            octets[bit // 8] |= 1 << (bit % 8)
            out.append(("Beacon ext caps, %d bytes, only bit %d" % (n, bit), mgmt(8, 12, ie(0, b"x") + ie(127, bytes(octets)))))
    # 厂商元素：WMM 信息 / 参数、WPA、WPS、未知厂商、多个厂商元素
    def wmm_param(qos=0x01, acs=((0x03, 0xa4, 0x0000), (0x27, 0xa4, 0x0000), (0x42, 0x43, 0x005e), (0x62, 0x32, 0x002f))):
        body = b"\x00\x50\xf2\x02\x01\x01" + bytes([qos, 0])
        for aci, ecw, txop in acs:
            body += bytes([aci, ecw]) + struct.pack("<H", txop)
        return body

    out.append(("Beacon WMM parameter element", mgmt(8, 12, ie(0, b"w") + ie(221, wmm_param()))))
    out.append(("Beacon WMM parameter: U-APSD, set count 5, ACM on VI, TXOP 3008", mgmt(8, 12, ie(0, b"w") + ie(221, wmm_param(qos=0x85, acs=((0x03, 0xa4, 0x0000), (0x27, 0xa4, 0x0000), (0x52, 0x43, 0x0bc0), (0x62, 0x32, 0x002f)))))))
    out.append(("Assoc Request WMM information element", mgmt(0, 4, ie(0, b"w") + ie(221, b"\x00\x50\xf2\x02\x00\x01\x0f"))))
    out.append(("Assoc Request WMM information: U-APSD for VO, max SP 2", mgmt(0, 4, ie(0, b"w") + ie(221, b"\x00\x50\xf2\x02\x00\x01\x41"))))
    wpa = b"\x00\x50\xf2\x01" + le(1) + s(2, oui=b"\x00\x50\xf2") + le(2) + s(4, oui=b"\x00\x50\xf2") + s(2, oui=b"\x00\x50\xf2") + le(1) + s(2, oui=b"\x00\x50\xf2")
    out.append(("Beacon WPA element TKIP + CCMP, PSK", mgmt(8, 12, ie(0, b"w") + ie(221, wpa))))
    out.append(("Beacon WPA element, 802.1X", mgmt(8, 12, ie(0, b"w") + ie(221, b"\x00\x50\xf2\x01" + le(1) + s(4, oui=b"\x00\x50\xf2") + le(1) + s(4, oui=b"\x00\x50\xf2") + le(1) + s(1, oui=b"\x00\x50\xf2")))))
    out.append(("Beacon WPS + unknown vendors in order", mgmt(8, 12, ie(0, b"v") + ie(221, b"\x00\x50\xf2\x04\x10\x4a\x00\x01\x10") + ie(221, b"\x00\x11\x22\x33\x44") + ie(221, wmm_param()) + ie(221, b"\xaa\xbb\xcc"))))
    out.append(("Beacon WPA, WMM, vendor, RSN together", mgmt(8, 12, ie(0, b"v") + ie(48, rsn_wpa2) + ie(221, wpa) + ie(221, wmm_param()))))
    # 移动域 / BSS 最大空闲周期 / RSNXE
    for capab in (0x00, 0x01, 0x02, 0x03):
        out.append(("Beacon mobility domain, FT capab 0x%02x" % capab, mgmt(8, 12, ie(0, b"m") + ie(54, b"\x01\x02" + bytes([capab])))))
    out.append(("Beacon mobility domain id 0xb2a1", mgmt(8, 12, ie(0, b"m") + ie(54, b"\xa1\xb2\x00"))))
    for period, opt in ((292, 0), (65535, 1), (1, 1), (256, 0)):
        out.append(("Beacon BSS max idle %d options %d" % (period, opt), mgmt(8, 12, ie(0, b"i") + ie(90, struct.pack("<HB", period, opt)))))
    for octets in ((0x00,), (0x10,), (0x20,), (0x40,), (0x70,), (0x21, 0x03), (0xff, 0xff)):
        out.append(("Beacon RSNXE %s" % ",".join("%02x" % o for o in octets), mgmt(8, 12, ie(0, b"x") + ie(244, bytes(octets)))))
    # Multi-Link（802.11be）：公共信息 + 每站点配置（STA 信息 + 外层帧的固定字段 + 嵌套元素）。
    # 固定字段的长度取决于外层帧类型，逐个子类型让 tshark 验证
    def ml_basic(stas, fixed, mld=b"\x02\x00\x00\x00\x0a\x00", link_id=None, presence=0):
        control = 0 | presence | (0x10 if link_id is not None else 0)
        common = bytes([1 + len(mld) + (1 if link_id is not None else 0)]) + mld + (bytes([link_id]) if link_id is not None else b"")
        body = struct.pack("<H", control) + common
        for sta_link, mac, elements in stas:
            sta_info = (bytes([7]) + mac) if mac else bytes([1])
            ctl = sta_link | 0x10 | (0x20 if mac else 0)
            data = struct.pack("<H", ctl) + sta_info + bytes(fixed) + elements
            body += bytes([0, len(data)]) + data
        return ie(0, body, ext=107)

    # 主体自己的 DS / HT 能力：tshark 取「第一次出现」时会把嵌套里的也算上，真实帧的主体总是有自己的
    MAIN = ie(3, b"\x06") + ie(45, htcap())
    nested = ie(1, b"\x82\x84\x8b\x96") + ie(50, b"\x30\x48") + ie(45, htcap()) + ie(221, b"\x00\x11\x22\x01")
    mac1, mac2 = b"\xe6\xcc\x7b\x74\xe1\x42", b"\x02\x00\x00\xdc\x7a\x19"
    for name, sub, fixed_len, fixed_bytes in (("Association Request", 0, 4, b"\x31\x04"), ("Association Response", 1, 6, b"\x11\x04\x00\x00"),
                                              ("Reassociation Request", 2, 10, b"\x31\x04"), ("Reassociation Response", 3, 6, b"\x11\x04\x00\x00"),
                                              ("Probe Response", 5, 12, b"\x11\x04"), ("Beacon", 8, 12, b"\x11\x04")):
        out.append(("%s Multi-Link, 1 link, nested elements" % name, mgmt(sub, fixed_len, ie(0, b"ml") + MAIN + ml_basic([(1, mac1, nested)], fixed_bytes, link_id=0) + ie(221, b"\x00\x33\x44\x05"))))
    out.append(("Beacon Multi-Link, 2 links", mgmt(8, 12, ie(0, b"ml") + MAIN + ml_basic([(1, mac1, ie(0, b"a") + ie(1, b"\x82")), (2, mac2, ie(3, b"\x0b"))], b"\x11\x04"))))
    out.append(("Beacon Multi-Link, no per-STA profile", mgmt(8, 12, ie(0, b"ml") + MAIN + ml_basic([], b""))))
    out.append(("Beacon Multi-Link, STA without MAC address", mgmt(8, 12, ie(0, b"ml") + MAIN + ml_basic([(3, None, ie(1, b"\x8c"))], b"\x11\x04"))))
    out.append(("Beacon Multi-Link, link ID in common info, elements before and after", mgmt(8, 12, ie(0, b"ml") + MAIN + ie(3, b"\x06") + ml_basic([(1, mac1, ie(1, b"\x82"))], b"\x11\x04", link_id=5) + ie(7, b"US \x01\x0b\x14"))))
    # HE（802.11ax）能力 / 操作
    def hecap(phy0=0x02, mac=bytes([1, 0x78, 0xc8, 0x12, 0x40, 0]), maps=((0xfffa, 0xfffa),)):
        body = mac + bytes([phy0]) + bytes(range(1, 11))
        for rx, tx in maps:
            body += struct.pack("<HH", rx, tx)
        return ie(0, body, ext=35)

    for name, phy0, maps in (("40MHz in 2.4GHz", 0x02, ((0xfffa, 0xfffa),)), ("40/80MHz in 5GHz", 0x04, ((0xfffa, 0xfffa),)),
                             ("160MHz in 5GHz: extra 160 map", 0x08, ((0xfffa, 0xfffa), (0xfffe, 0xfffc))),
                             ("160/80+80MHz in 5GHz", 0x10, ((0xfffa, 0xfffa), (0xfffe, 0xfffc))),
                             ("160 and 160/80+80: both extra maps", 0x18, ((0xfffa, 0xfffa), (0xfffe, 0xfffc), (0xfff0, 0xffc0))),
                             ("242 tone RU bits only", 0x60, ((0xaaaa, 0x5555),))):
        out.append(("Beacon HE capabilities, %s" % name, mgmt(8, 12, ie(0, b"he") + hecap(phy0, maps=maps))))
    out.append(("Beacon HE capabilities, other MAC capability bits", mgmt(8, 12, ie(0, b"he") + hecap(mac=bytes([0xff, 0x00, 0xa5, 0x5a, 0x01, 0x80])))))

    def heop(params=0, color=0x2a, basic=0xfffc, extra=b""):
        return ie(0, bytes([params & 255, params >> 8 & 255, params >> 16]) + bytes([color]) + struct.pack("<H", basic) + extra, ext=36)

    for name, kw in (("defaults", {}), ("default PE 5, TWT required", dict(params=0x00000d)), ("RTS threshold 0x3ff", dict(params=0x003ff0)),
                     ("ER SU disable", dict(params=0x010000)), ("VHT operation info", dict(params=0x004000, extra=b"\x01\x2a\x00")),
                     ("co-hosted BSS", dict(params=0x008000, extra=b"\x04")),
                     ("6GHz operation info", dict(params=0x020000, extra=b"\x25\x82\x27\x00\x00")),
                     ("VHT + co-hosted + 6GHz", dict(params=0x00c000 | 0x020000, extra=b"\x02\x2a\x00" + b"\x03" + b"\x25\x82\x27\x00\x00")),
                     ("basic MCS/NSS map", dict(basic=0xfff0))):
        out.append(("Beacon HE operation, %s" % name, mgmt(8, 12, ie(0, b"he") + heop(**kw))))
    # Action 帧：块确认 / HT 动作 / 其它类别 / 错误响应 / 受保护
    def addba_params(amsdu=0, immediate=1, tid=0, buffers=64):
        return struct.pack("<H", amsdu | immediate << 1 | tid << 2 | buffers << 6)

    for name, tok, params, timeout, frag, seq in (("A-MSDU, immediate, TID 0, 64 buffers", 1, addba_params(1, 1, 0, 64), 0, 0, 1),
                                                ("delayed, TID 5, 1023 buffers", 0xff, addba_params(0, 0, 5, 1023), 0xffff, 3, 4095),
                                                ("TID 15, 1 buffer", 7, addba_params(0, 1, 15, 1), 100, 15, 0)):
        out.append(("Action ADDBA request, %s" % name, frame(0, 13, body=bytes([3, 0, tok]) + params + struct.pack("<HH", timeout, seq << 4 | frag))))
    for name, status, params in (("success", 0, addba_params(0, 1, 0, 64)), ("failure 37, A-MSDU, TID 9", 37, addba_params(1, 0, 9, 8))):
        out.append(("Action ADDBA response, %s" % name, frame(0, 13, body=bytes([3, 1, 2]) + struct.pack("<H", status) + params + struct.pack("<H", 0))))
    for init, tid, reason in ((1, 0, 37), (0, 15, 0xffff), (1, 7, 1)):
        out.append(("Action DELBA initiator=%d TID %d" % (init, tid), frame(0, 13, body=bytes([3, 2]) + struct.pack("<HH", init << 11 | tid << 12, reason))))
    out.append(("Action ADDBA request, error response category", frame(0, 13, body=bytes([0x83, 0, 1]) + addba_params() + struct.pack("<HH", 0, 16))))
    for ctl in (0x00, 0x01, 0x02, 0x03):
        out.append(("Action HT SM power save, control 0x%02x" % ctl, frame(0, 13, body=bytes([7, 1, ctl]))))
    for w in (0, 1):
        out.append(("Action HT notify channel width %d" % w, frame(0, 13, body=bytes([7, 0, w]))))
    out.append(("Action No Ack, HT SM power save", frame(0, 14, body=bytes([7, 1, 3]))))
    out.append(("Action SA Query request", frame(0, 13, body=bytes([8, 0, 0x34, 0x12]))))
    out.append(("Action Radio Measurement request", frame(0, 13, body=bytes([5, 0, 1, 0, 0]))))
    out.append(("Action Public Action", frame(0, 13, body=bytes([4, 4, 1]))))
    out.append(("Action protected (body is ciphertext)", frame(0, 13, prot=1, body=bytes([3, 0, 1]) + bytes(range(20)))))
    # A-MSDU：QoS 数据帧的帧体是一串子帧（DA 6 + SA 6 + 长度 2 大端 + 数据 + 填充到 4 字节）
    def sub(da, sa, payload, pad=True):
        sf = da + sa + struct.pack(">H", len(payload)) + payload
        return sf + (b"\x00" * (-len(sf) % 4) if pad else b"")

    # 以太类型用 0x88b5（本地实验用），避免 tshark 去解析子帧里我随手填的 IP / ARP 数据
    llc = lambda t: b"\xaa\xaa\x03\x00\x00\x00" + struct.pack(">H", t)       # noqa: E731
    ma, mb, mc = (bytes.fromhex(x) for x in ("020000000001", "020000000002", "020000000003"))

    def amsdu_frame(body, **kw):
        return frame(2, 8, 1, 0, qos=qos_word(amsdu=1), body=body, **kw)

    out.append(("A-MSDU one subframe", amsdu_frame(sub(ma, mb, llc(0x88b5) + b"abc", pad=False))))
    out.append(("A-MSDU two subframes, padded", amsdu_frame(sub(ma, mb, llc(0x88b5) + b"abc") + sub(mb, ma, llc(0x88b5) + b"defgh", pad=False))))
    for n in range(1, 5):
        out.append(("A-MSDU payload sizes need %d bytes of padding" % ((-(14 + 8 + n)) % 4),
                    amsdu_frame(sub(ma, mb, llc(0x88b5) + b"x" * n) + sub(mc, ma, llc(0x88b5) + b"y", pad=False))))
    out.append(("A-MSDU three subframes", amsdu_frame(sub(ma, mb, llc(0x88b5) + b"1" * 20) + sub(mb, mc, llc(0x88b5) + b"2" * 28) + sub(mc, ma, llc(0x88b5) + b"3" * 9, pad=False))))
    out.append(("A-MSDU last subframe padded too", amsdu_frame(sub(ma, mb, llc(0x88b5) + b"abc") + sub(mb, ma, llc(0x88b5) + b"de"))))
    # （长度 0 的子帧不放进对照：tshark 在它那里停止解析，我们继续，见 amsdu.py 的说明和 tests/test_amsdu.py）
    out.append(("A-MSDU last subframe cut short", amsdu_frame(sub(ma, mb, llc(0x88b5) + b"abc") + sub(mb, ma, llc(0x88b5) + b"defghij", pad=False)[:-3])))
    out.append(("A-MSDU LLC with different DSAP and SSAP", amsdu_frame(sub(ma, mb, b"\xf0\xf1\x03" + b"abcd", pad=False))))
    out.append(("A-MSDU FromDS", frame(2, 8, 0, 1, qos=qos_word(amsdu=1), body=sub(ma, mb, llc(0x88b5) + b"q", pad=False))))
    out.append(("A-MSDU protected (ciphertext)", frame(2, 8, 1, 0, prot=1, qos=qos_word(amsdu=1), body=bytes(range(40)))))
    out.append(("Beacon + extension elements", mgmt(8, 12, IES + ie(0, b"\x13\x00", ext=92) + ie(0, b"\x01\x02\x03\x04", ext=200))))
    out.append(("Deauthentication, protected (body is ciphertext)", frame(0, 12, prot=1, body=b"\x07\x00" + b"\x00\x03abc\x30\x02\x01\x00" * 2)))
    out.append(("Beacon, last element cut short", mgmt(8, 12, ie(0, b"abc") + b"\x30\x14\x01\x00")))
    for tods, fromds in ((0, 0), (0, 1), (1, 0), (1, 1)):
        out.append(("Data ToDS=%d FromDS=%d" % (tods, fromds), frame(2, 0, tods, fromds)))
        out.append(("QoS Data ToDS=%d FromDS=%d" % (tods, fromds), frame(2, 8, tods, fromds, qos=qos_word(tid=5))))
    for tid in range(8):
        out.append(("QoS TID=%d" % tid, frame(2, 8, 1, 0, qos=qos_word(tid=tid))))
    for ap in range(4):
        out.append(("QoS ack policy %d" % ap, frame(2, 8, 1, 0, qos=qos_word(ack_policy=ap))))
    out.append(("QoS EOSP", frame(2, 8, 0, 1, qos=qos_word(eosp=1))))
    out.append(("QoS A-MSDU present", frame(2, 8, 1, 0, qos=qos_word(amsdu=1))))
    out.append(("QoS Null", frame(2, 12, 1, 0, qos=qos_word(tid=3), body=b"")))
    out.append(("Null", frame(2, 4, 1, 0, body=b"")))
    out.append(("QoS Data + HT Control", frame(2, 8, 1, 0, order=1, qos=qos_word(tid=2), htc=0x00000001)))
    out.append(("QoS Data 4-address + HT Control", frame(2, 8, 1, 1, order=1, qos=qos_word(), htc=0x00000003)))
    out.append(("Data order bit (no HT Control)", frame(2, 0, 1, 0, order=1)))
    out.append(("Action No Ack + HT Control", frame(0, 14, order=1, htc=0x00000001, body=b"\x00\x00")))
    out.append(("Beacon (no order)", frame(0, 8, body=b"\x00" * 12 + b"\x00\x04test")))
    out.append(("Fragment 12 of 3000", frame(2, 0, 1, 0, seq=3000, frag=12, morefrag=1)))
    out.append(("Last fragment 13", frame(2, 0, 1, 0, seq=3000, frag=13)))
    return out


def write_pcap(path, frames, linktype=105):
    with open(path, "wb") as f:
        f.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, linktype))
        for i, data in enumerate(frames):
            f.write(struct.pack("<IIII", 1000 + i, 0, len(data), len(data)) + data)
