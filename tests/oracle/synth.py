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
    out.append(("Beacon + extension elements", mgmt(8, 12, IES + ie(0, b"\x13\x00", ext=92) + ie(0, b"\x01\x02\x03\x04", ext=114))))
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
