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
