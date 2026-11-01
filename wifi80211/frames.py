# -*- coding: utf-8 -*-
"""
把一个抓包文件按帧读出来：去掉链路层头（radiotap）和末尾的 FCS，给出 802.11 帧、解析好的 MAC 头和帧体。
解密流程和差分测试都用它。纯标准库。
"""
import datetime
import logging
import struct
import zlib
from collections import Counter, namedtuple

from . import capture
from . import ie
from . import radiotap
from . import parser as w

log = logging.getLogger(__name__)

# n：帧号（从 1 起，和 tshark 的 frame.number 一致）；dot11：完整的 802.11 帧（FCS 已去掉）；
# h：parse_mac_header 的结果；body：MAC 头之后的字节；fcs_ok：有 FCS 时校验是否通过，没有 FCS 为 None
Frame = namedtuple("Frame", "n ts dot11 h body fcs_ok")


def iter_frames(path):
    cap = capture.read_capture(path)
    # 汇总只在日志级别 INFO 或更细时收集；日志关掉（库默认）时循环里只多一次 None 判断
    st = _Stats() if log.isEnabledFor(logging.INFO) else None
    for n, pkt in enumerate(cap.packets, 1):
        data, fcs_ok = pkt.data, None
        if pkt.linktype == 127:
            try:
                rt = radiotap.parse(data)
            except ValueError as e:
                if st:
                    st.rt.error(e)
                    st.skipped["radiotap 头不合法"] += 1
                continue
            if st:
                st.rt.add(rt)
            data = data[rt["length"]:]
            if rt["fcs_included"] and len(data) >= 4:
                data, fcs = data[:-4], struct.unpack("<I", data[-4:])[0]
                fcs_ok = zlib.crc32(data) == fcs
        elif pkt.linktype != 105:
            if st:
                st.other_linktypes[pkt.linktype] += 1
            continue
        if len(data) < 2:
            if st:
                st.skipped["帧不足 2 字节"] += 1
            continue
        fc = struct.unpack("<H", data[:2])[0]
        if (fc >> 2) & 3 == 1:                  # 控制帧：没有数据可解
            if st:
                st.control[w.CTRL_SUBTYPE.get((fc >> 4) & 15, "Unknown(%d)" % ((fc >> 4) & 15))] += 1
            continue
        try:
            h = w.parse_mac_header(data)
        except ValueError as e:
            if st:
                st.skipped["MAC 头不合法（" + str(e).split(":")[0] + "）"] += 1
            continue
        f = Frame(n, pkt.ts, data, h, data[h["header_len"]:], fcs_ok)
        if st:
            st.add(f)
        yield f
    if st:
        st.log_summary(cap)


class _Stats:
    """iter_frames 读完后写一次汇总日志用的计数；逐帧只累加，不写日志。"""

    def __init__(self):
        self.rt = radiotap.Summary()
        self.skipped, self.control, self.other_linktypes = Counter(), Counter(), Counter()
        self.kinds = Counter()                   # (类型名, 子类型名) -> 个数
        self.frames = self.data = self.protected = self.wep_like = self.eapol = self.fcs_ok = self.fcs_bad = 0
        self.first_ts = self.last_ts = None
        self.nets = {}                           # bssid -> 从第一个信标 / 探测响应读到的网络信息

    def add(self, f):
        h = f.h
        self.frames += 1
        self.kinds[w.type_name(h)] += 1
        self.first_ts = f.ts if self.first_ts is None else min(self.first_ts, f.ts)
        self.last_ts = f.ts if self.last_ts is None else max(self.last_ts, f.ts)
        if f.fcs_ok is True:
            self.fcs_ok += 1
        elif f.fcs_ok is False:
            self.fcs_bad += 1
        if h["type"] == 2:
            self.data += 1
            if h["protected"]:
                self.protected += 1
                self.wep_like += len(f.body) >= 4 and not f.body[3] & 0x20      # 没有 ExtIV 位：WEP（CCMP / TKIP 的头里这一位是 1）
            self.eapol += eapol_payload(f) is not None
        elif h["type"] == 0 and h["subtype"] in (5, 8) and h["bssid"] not in self.nets and len(self.nets) < 50:
            self.nets[h["bssid"]] = _network_info(f)

    def log_summary(self, cap):
        self.rt.log_to(radiotap.log)
        n = len(cap.packets)
        if self.other_linktypes:
            log.warning("%d 个包的链路类型不是 802.11（%s），已跳过", sum(self.other_linktypes.values()),
                        "，".join("%s %d 个" % (capture.linktype_name(k), v) for k, v in self.other_linktypes.items()))
        if not self.frames and n:
            log.error("%d 个包里一个 802.11 帧也没读到。%s。这个抓包的链路类型是：%s", n, capture.SUPPORTED_HINT,
                      "，".join(capture.linktype_name(k) for k in sorted(set(cap.linktypes))) or "未知")
            return
        mgmt = sum(v for k, v in self.kinds.items() if k[0] == "Management")
        log.info("802.11 帧：%d 个包得到 %d 个帧（管理 %d、数据 %d）；控制帧 %d 个按设计跳过", n, self.frames, mgmt, self.data, sum(self.control.values()))
        log.debug("帧类型：%s", "，".join("%s/%s %d" % (k[0], k[1], v) for k, v in self.kinds.most_common(12)))
        if self.control:
            log.debug("控制帧：%s", "，".join("%s %d" % kv for kv in self.control.most_common()))
        if self.skipped:
            log.debug("被丢掉的包（原因 个数）：%s", "，".join("%s %d" % kv for kv in self.skipped.most_common()))
            if sum(self.skipped.values()) > 0.05 * max(n, 1):
                log.warning("%d 个包（%.0f%%）因格式不合法被丢掉：%s", sum(self.skipped.values()), 100.0 * sum(self.skipped.values()) / n, dict(self.skipped))
        for bssid, info in sorted(self.nets.items()):
            log.info("网络 %s：SSID %s，信道 %s，%s", bssid, info["ssid"], info["channel"], info["security"])
        log.info("数据帧 %d 个，其中受保护 %d 个；未加密的 EAPOL 帧 %d 个（四次握手靠它们，设备每连入一次应有 4 个）", self.data, self.protected, self.eapol)
        if self.wep_like:
            log.info("%d 个受保护的数据帧头里没有 ExtIV 位，是 WEP：不需要握手，用密钥表里的 wep 密钥解", self.wep_like)
        if self.protected > self.wep_like and not self.eapol:
            log.warning("有 %d 个 CCMP / TKIP 加密的数据帧，但抓包里没有 EAPOL 握手帧：用口令解不了密（要抓到设备连入的那一刻；已经连着的设备请让它断开重连后再抓）；直接给 TK 的不受影响",
                        self.protected - self.wep_like)
        if self.fcs_bad:
            log.warning("%d 个帧的 FCS 校验不通过（帧在空中被破坏，多半是信号弱或干扰），%d 个通过；校验不通过的帧解密也会失败", self.fcs_bad, self.fcs_ok)
        elif self.fcs_ok:
            log.info("FCS：%d 个帧校验通过", self.fcs_ok)
        if self.first_ts is not None:
            log.info("时间跨度：%.1f 秒（UTC %s 到 %s）", self.last_ts - self.first_ts, _utc(self.first_ts), _utc(self.last_ts))


def _utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _network_info(f):
    """信标 / 探测响应里的 SSID、信道、认证方式（AKM 名字）；读不出来的字段写「?」，不抛异常。"""
    try:
        b = w.parse_beacon(f.body)
        rsn = ie.decode_rsn(w.parse_tags(f.body[12:]).get(48, b""))
    except (struct.error, ValueError, IndexError):
        return {"ssid": "?", "channel": "?", "security": "信标读不出"}
    if rsn:
        sec = "RSN 认证方式 %s" % ("、".join(ie.akm_name(x) for x in rsn["akm"]) if rsn["akm"] else "（没写）")
    else:
        sec = "没有 RSN 元素（开放网络或 WEP / WPA1）" if not b["capability_privacy"] else "没有 RSN 元素（WEP 或 WPA1）"
    return {"ssid": b["ssid"], "channel": b["channel"], "security": sec}


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
