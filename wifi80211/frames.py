# -*- coding: utf-8 -*-
"""
把一个抓包文件按帧读出来：去掉链路层头（radiotap）和末尾的 FCS，给出 802.11 帧、解析好的 MAC 头和帧体。
解密流程和差分测试都用它。纯标准库。
"""
import struct
import zlib
from collections import namedtuple

from . import capture
from . import radiotap
from . import parser as w

# n：帧号（从 1 起，和 tshark 的 frame.number 一致）；dot11：完整的 802.11 帧（FCS 已去掉）；
# h：parse_mac_header 的结果；body：MAC 头之后的字节；fcs_ok：有 FCS 时校验是否通过，没有 FCS 为 None
Frame = namedtuple("Frame", "n ts dot11 h body fcs_ok")


def iter_frames(path):
    cap = capture.read_capture(path)
    for n, pkt in enumerate(cap.packets, 1):
        data, fcs_ok = pkt.data, None
        if pkt.linktype == 127:
            try:
                rt = radiotap.parse(data)
            except ValueError:
                continue
            data = data[rt["length"]:]
            if rt["fcs_included"] and len(data) >= 4:
                data, fcs = data[:-4], struct.unpack("<I", data[-4:])[0]
                fcs_ok = zlib.crc32(data) == fcs
        elif pkt.linktype != 105:
            continue
        if len(data) < 2:
            continue
        fc = struct.unpack("<H", data[:2])[0]
        if (fc >> 2) & 3 == 1:                  # 控制帧：没有数据可解
            continue
        try:
            h = w.parse_mac_header(data)
        except ValueError:
            continue
        yield Frame(n, pkt.ts, data, h, data[h["header_len"]:], fcs_ok)


LLC_SNAP = b"\xaa\xaa\x03\x00\x00\x00"
ETHERTYPE_EAPOL = b"\x88\x8e"


def eapol_payload(frame):
    """未加密数据帧里的 EAPOL 报文（LLC/SNAP 之后的字节），不是 EAPOL 返回 None。"""
    h = frame.h
    if h["type"] != 2 or h["protected"] or len(frame.body) < 8:
        return None
    if frame.body[:6] != LLC_SNAP or frame.body[6:8] != ETHERTYPE_EAPOL:
        return None
    return frame.body[8:]
