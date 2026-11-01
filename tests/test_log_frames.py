#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""帧层的日志（capture / radiotap / frames / parser / ie / action / amsdu）：哪个阶段在什么情况下写什么级别的什么话。
用手写的小抓包造各种情况（截断、不认识的格式、FCS 坏、多信道、没有握手……），再用真实样例核对汇总的数字；
另外检查：日志不改变行为、不逐帧写、不带 16 字节以上的十六进制。"""
import gzip
import io
import logging
import os
import struct
import sys
import tempfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "oracle"))
import fetch_samples  # noqa: E402
from wifi80211 import action, amsdu, capture, ie, logs, radiotap  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import parser as w  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


class Cap(logging.Handler):
    """收集 wifi80211 下的全部日志记录（含 TRACE）。"""

    def __init__(self, level=logs.TRACE):
        super().__init__(logs.TRACE)
        self.records = []
        self.lg = logging.getLogger("wifi80211")
        self.old = (self.lg.level, self.lg.propagate)
        self.lg.setLevel(level)
        self.lg.propagate = False
        self.lg.addHandler(self)

    def emit(self, r):
        self.records.append(r)

    def close(self):
        self.lg.removeHandler(self)
        self.lg.setLevel(self.old[0])
        self.lg.propagate = self.old[1]
        super().close()

    def msgs(self, level=None, logger=None):
        return [r.getMessage() for r in self.records if (level is None or r.levelno == level) and (logger is None or r.name == "wifi80211." + logger)]

    def has(self, level, *parts, logger=None):
        return any(all(p in m for p in parts) for m in self.msgs(level, logger))


def run(fn, level=logs.TRACE):
    c = Cap(level)
    try:
        try:
            out = fn()
        except Exception as e:                                    # noqa: BLE001
            out = e
    finally:
        c.close()
    return out, c


# ---- 手写抓包 ----
def pcap(packets, linktype=127, endian="<", nano=False, snaplen=65535, cut=0):
    magic = {("<", False): b"\xd4\xc3\xb2\xa1", ("<", True): b"\x4d\x3c\xb2\xa1", (">", False): b"\xa1\xb2\xc3\xd4", (">", True): b"\xa1\xb2\x3c\x4d"}[(endian, nano)]
    b = magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, snaplen, linktype)
    for i, p in enumerate(packets):
        data, orig = (p if isinstance(p, tuple) else (p, len(p)))
        b += struct.pack(endian + "IIII", 1700000000 + i, 500 + i, len(data), orig) + data
    return b[:len(b) - cut] if cut else b


def pad4(b):
    return b + b"\0" * (-len(b) % 4)


def opt(code, val):
    return struct.pack("<HH", code, len(val)) + pad4(val)


def block(btype, body):
    total = 12 + len(pad4(body))
    return struct.pack("<II", btype, total) + pad4(body) + struct.pack("<I", total)


def pcapng(packets, linktype=127, shb_opts=(), idb_opts=(), extra=b"", iface=0):
    shb = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + b"".join(opt(c, v) for c, v in shb_opts) + b"\0\0\0\0")
    idb = block(1, struct.pack("<HHI", linktype, 0, 65535) + b"".join(opt(c, v) for c, v in idb_opts) + b"\0\0\0\0")
    b = shb + idb + extra
    for i, p in enumerate(packets):
        b += block(6, struct.pack("<IIIII", iface, 0, 1000000 + i, len(p), len(p)) + p)
    return b


def radiotap_hdr(freq=2437, signal=-50, flags=0x10, version=0):
    # present: flags(1) | channel(3) | antsignal(5)；flags 1 字节，channel 2 字节对齐，antsignal 1 字节 -> 总长 15
    body = struct.pack("<BHHb", flags, freq, 0x00A0, signal)
    body = struct.pack("<B", flags) + b"\0" + struct.pack("<HH", freq, 0x00A0) + struct.pack("<b", signal)
    return struct.pack("<BBHI", version, 0, 8 + len(body), (1 << 1) | (1 << 3) | (1 << 5)) + body


def mac(b):
    return bytes([b] * 6)


def mgmt_hdr(subtype, a1=mac(0xff), a2=mac(0x11), a3=mac(0x11)):
    return struct.pack("<HH", subtype << 4, 0) + a1 + a2 + a3 + b"\0\0"


def beacon(ssid=b"HomeNet", channel=6, akm=None, privacy=True):
    tags = bytes([0, len(ssid)]) + ssid + bytes([3, 1, channel])
    if akm is not None:
        rsn = struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac" + bytes([akm]) + b"\0\0"
        tags += bytes([48, len(rsn)]) + rsn
    return mgmt_hdr(8) + struct.pack("<QHH", 1, 100, 0x0431 if privacy else 0x0401) + tags


def data_frame(protected=True, body=b"\x00" * 24, ext_iv=True, to_ds=1):
    fc1 = to_ds | (0x40 if protected else 0)
    hdr = struct.pack("<BBH", 0x08, fc1, 0) + mac(0x22) + mac(0x33) + mac(0x44) + b"\0\0"
    if protected:
        body = bytes([1, 0, 0, 0x20 if ext_iv else 0x00]) + b"\0" * 4 + body
    return hdr + body


def eapol_frame():
    return data_frame(False, b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + b"\x02\x03" + b"\0" * 20)


def with_fcs(dot11, good=True):
    crc = zlib.crc32(dot11)
    return dot11 + struct.pack("<I", crc if good else crc ^ 1)


def rt(dot11, **kw):
    return radiotap_hdr(**kw) + dot11


tmp = tempfile.mkdtemp()


def write(name, data):
    p = os.path.join(tmp, name)
    open(p, "wb").write(data)
    return p


print("== capture：pcap ==")
p = write("a.pcap", pcap([rt(with_fcs(beacon()))]))
cap, c = run(lambda: capture.read_capture(p))
check(c.has(logging.INFO, "打开抓包文件", "字节", logger="capture") and not c.has(logging.INFO, "gzip 压缩", logger="capture"), "打开文件：路径和大小；不是 gzip 就不说 gzip")
check(c.has(logging.INFO, "pcap 格式", "小端", "微秒", "127（IEEE802_11_RADIOTAP", "snaplen 65535"), "pcap 头：字节序、时间戳精度、链路类型的名字、snaplen")
check(c.has(logging.INFO, "读到 1 个包") and not c.msgs(logging.WARNING), "读到的包数；干净的文件没有 WARNING")
cap, c = run(lambda: capture.read_capture(write("b.pcap", pcap([rt(with_fcs(beacon()))], endian=">", nano=True, linktype=105))))
check(c.has(logging.INFO, "大端", "纳秒", "105（IEEE802_11，裸 802.11）"), "大端 + 纳秒 + 链路类型 105 的名字")
cap, c = run(lambda: capture.read_capture(write("c.pcap", pcap([b"\x01" * 40], linktype=1) + b"\0" * 7)))
check(c.has(logging.WARNING, "偏移", "被截断", "包头只剩 7 字节") and cap.truncated, "文件尾巴只剩 7 字节（不够一个包头）：WARNING 带偏移")
data = pcap([b"\x01" * 40, b"\x02" * 40])
cap, c = run(lambda: capture.read_capture(write("d.pcap", data[:-10])))
check(c.has(logging.WARNING, "偏移 %d" % (24 + 16 + 40), "第 2 个包声明 40 字节，只剩 30 字节") and c.has(logging.INFO, "读到 1 个包", "被截断"), "最后一个包被截断：WARNING 带偏移、声明长度和剩余长度；仍报告用了前面的包")
cap, c = run(lambda: capture.read_capture(write("e.pcap", pcap([(b"\x01" * 30, 100), (b"\x02" * 40, 40), (b"\x03" * 20, 60)]))))
check(c.has(logging.WARNING, "2 个包被 snaplen 截短", "-s 0"), "caplen 小于 origlen 的包数：WARNING，提示 tcpdump -s 0")
res, c = run(lambda: capture.read_capture(write("f.pcap", b"RIFF\x00\x00\x00\x00")))
check(isinstance(res, ValueError) and c.has(logging.ERROR, "不认识的抓包文件格式", "52494646", "pcapng", "gzip"), "不认识的格式：ERROR 写出开头 4 字节和能读的格式，并仍然抛 ValueError")
res, c = run(lambda: capture.read_capture(write("g.pcap", b"")))
check(isinstance(res, ValueError) and c.has(logging.ERROR, "空文件"), "空文件：ERROR 说是空文件")
res, c = run(lambda: capture.read_capture(write("h.pcap", pcap([])[:20])))
check(isinstance(res, ValueError) and c.has(logging.ERROR, "pcap 文件头不完整", "只有 20 字节"), "pcap 头不完整：ERROR 带字节数")
raw = pcap([b"\x01" * 100] * 50, linktype=1)
gz = gzip.compress(raw)
cap, c = run(lambda: capture.read_capture(write("i.pcap.gz", gz[:len(gz) // 2])))
check(c.has(logging.WARNING, "gzip 流被截断", "字节") and c.has(logging.INFO, "gzip 压缩"), "gzip 被截断：WARNING 说只解出多少字节")
cap, c = run(lambda: capture.read_capture(write("j.pcap.gz", gz)))
check(c.has(logging.INFO, "gzip 压缩") and c.has(logging.INFO, "解压后 %d 字节" % len(raw)), "gzip：说明压缩和解压后的大小")
cap, c = run(lambda: capture.read_capture(write("k.pcap", pcap([b"x" * 20], linktype=0x10000000 | 127))))
check(c.has(logging.DEBUG, "高位带标志") and c.has(logging.INFO, "127（"), "链路类型字段高位带标志：DEBUG 记一笔，链路类型照样认对")
check(capture.linktype_name(999) == "999（未知类型）" and capture.linktype_name(1).startswith("1（EN10MB"), "未知的链路类型编号写「未知类型」")

print("== capture：pcapng ==")
pkt = rt(with_fcs(beacon()))
p = write("a.pcapng", pcapng([pkt, pkt], shb_opts=[(4, b"tcpdump 4.99"), (3, "macOS 15.1".encode()), (2, b"arm64")], idb_opts=[(2, b"en0"), (9, bytes([9]))]))
cap, c = run(lambda: capture.read_capture(p))
check(c.has(logging.INFO, "Section 1", "版本 1.0", "tcpdump 4.99", "macOS 15.1", "arm64"), "SHB：抓包程序、操作系统、硬件（知道文件是谁抓的）")
check(c.has(logging.INFO, "接口 0", "127（IEEE802_11_RADIOTAP", "接口名 en0", "时间戳精度 纳秒", "snaplen 65535"), "IDB：链路类型、接口名、时间戳精度")
check(c.has(logging.INFO, "读到 2 个包（1 个接口，1 个 Section）") and c.has(logging.DEBUG, "块统计", "'EPB': 2"), "总数 + DEBUG 块统计")
cap, c = run(lambda: capture.read_capture(write("b.pcapng", pcapng([pkt], extra=block(0x12345678, b"abcd") + block(0x0BAD, b"abcd") + block(0x12345678, b"abcd")))))
check(c.has(logging.WARNING, "3 个块的类型不认识", "'0x12345678': 2", "'0xbad': 1") and c.has(logging.DEBUG, "不认识的块类型"), "不认识的块类型：WARNING 汇总个数（同类型合并），DEBUG 块统计也带上")
dsb = block(0x0A, struct.pack("<II", 0x544C534B, 8) + b"SECRET!!")
cap, c = run(lambda: capture.read_capture(write("c.pcapng", pcapng([pkt], extra=dsb))))
text = " ".join(c.msgs())
check(c.has(logging.INFO, "1 个解密密钥块", "内容不记入日志") and "SECRET" not in text and "534543524554" not in text, "DSB：只记个数和类型，密钥内容不进日志")
data = pcapng([pkt, pkt])
cap, c = run(lambda: capture.read_capture(write("d.pcapng", data[:-6])))
check(c.has(logging.WARNING, "被截断", "EPB 块声明") and cap.truncated and c.has(logging.INFO, "读到 1 个包", "被截断"), "pcapng 最后一个块被截断：WARNING 带偏移和块类型")
res, c = run(lambda: capture.read_capture(write("e.pcapng", pcapng([]) + struct.pack("<II", 6, 13) + b"\0" * 8)))
check(isinstance(res, ValueError) and c.has(logging.ERROR, "块长度不合法", "13", "文件可能损坏"), "块长度不合法：ERROR 带偏移和长度，仍然抛 ValueError")
bad = pcapng([pkt], iface=3)
res, c = run(lambda: capture.read_capture(write("f.pcapng", bad)))
check(isinstance(res, ValueError) and c.has(logging.ERROR, "引用了不存在的接口 3", "只有 1 个接口描述块"), "包引用不存在的接口：ERROR")
bom = pcapng([pkt])
res, c = run(lambda: capture.read_capture(write("bom.pcapng", bom[:8] + b"\xde\xad\xbe\xef" + bom[12:])))
check(isinstance(res, ValueError) and c.has(logging.ERROR, "字节序标记不对", "deadbeef", "偏移 0"), "pcapng 的字节序标记不对：ERROR 带偏移和标记")
res, c = run(lambda: capture._parse_pcapng(b"\x01\x00\x00\x00" + b"\x14\x00\x00\x00" + b"\0" * 12))
check(isinstance(res, ValueError) and c.has(logging.ERROR, "不是以 Section Header 开头", "偏移 0"), "不是以 Section Header 开头：ERROR")
short_epb = pcapng([], extra=block(6, struct.pack("<IIIII", 0, 0, 1000000, 20, 60) + b"\x01" * 20) + block(6, struct.pack("<IIIII", 0, 0, 1000001, 20, 20) + b"\x02" * 20))
cap, c = run(lambda: capture.read_capture(write("short.pcapng", short_epb)))
check(c.has(logging.WARNING, "1 个包被 snaplen 截短", "-s 0") and len(cap.packets) == 2, "pcapng 里 caplen 小于 origlen 的包：WARNING")
cap, c = run(lambda: capture.read_capture(write("g.pcapng", pcapng([pkt]) + b"\x00" * 5)))
check(c.has(logging.WARNING, "块头只剩 5 字节"), "文件尾巴不够一个块头：WARNING")
shb2 = data[:data.index(struct.pack("<I", 1), 8)]
cap, c = run(lambda: capture.read_capture(write("h.pcapng", pcapng([pkt]) + pcapng([pkt]))))
check(c.has(logging.INFO, "读到 2 个包", "2 个 Section"), "两个 Section 首尾相接：2 个 Section")

print("== radiotap 汇总 ==")
check(radiotap.channel_name(2437) == "2437 MHz（2.4G 6 信道）" and radiotap.channel_name(2484) == "2484 MHz（2.4G 14 信道）" and radiotap.channel_name(5180) == "5180 MHz（5G 36 信道）"
      and radiotap.channel_name(5955) == "5955 MHz（6G 1 信道）" and radiotap.channel_name(1234) == "1234 MHz" and radiotap.channel_name(2413) == "2413 MHz", "频率 -> 信道名（2.4G / 14 信道 / 5G / 6G / 不认识的）")
s = radiotap.Summary()
for freq, sig in ((2412, -40), (2412, -60), (5180, -80)):
    s.add(radiotap.parse(radiotap_hdr(freq=freq, signal=sig, flags=0x00)))
lg = logging.getLogger("wifi80211.radiotap")
c = Cap()
s.log_to(lg)
c.close()
check(c.has(logging.INFO, "3 个包的头可读", "flags 3", "channel 3", "antsignal 3") and c.has(logging.INFO, "信道分布", "2412 MHz（2.4G 1 信道） 2 个包", "5180 MHz（5G 36 信道） 1 个包"), "字段出现次数、信道分布")
check(c.has(logging.WARNING, "2 个信道", "单信道监听") and c.has(logging.INFO, "-80 到 -40 dBm", "平均 -60 dBm"), "多个信道：WARNING；信号范围和平均")
check(c.has(logging.INFO, "没有 FCS 位", "没法校验") and c.has(logging.INFO, "物理层", "legacy 3"), "flags 里没有 FCS 位：INFO 说明；物理层类型")
s = radiotap.Summary()
s.add(radiotap.parse(radiotap_hdr()))
c = Cap()
s.log_to(lg)
c.close()
check(not c.msgs(logging.WARNING) and c.has(logging.INFO, "1 / 1 个包带 FCS"), "一个信道、带 FCS：没有 WARNING")
s = radiotap.Summary()
s.add({"length": 8, "present": [1], "fcs_included": False, "stopped_at": "bit32"})
s.error(ValueError("radiotap 长度不合法: 99（包共 20 字节）"))
s.error(ValueError("radiotap 头过短: 3 字节"))
s.error(ValueError("radiotap 头过短: 5 字节"))
c = Cap()
s.log_to(lg)
c.close()
check(c.has(logging.WARNING, "1 个包的 radiotap 遇到不认识的字段位", "bit32") and c.has(logging.WARNING, "3 个包的 radiotap 头坏了", "'radiotap 头过短': 2", "'radiotap 长度不合法': 1")
      and c.has(logging.WARNING, "没有信道字段"), "radiotap 解析中途停下 / 头坏了 / 没有信道字段：WARNING，坏头按原因合并计数")
c = Cap()
radiotap.Summary().log_to(lg)
c.close()
check(c.records == [], "什么都没读到：不写空汇总")

print("== frames：合成抓包的汇总 ==")
b1, b2 = beacon(ssid=b"HomeNet", channel=6, akm=2), beacon(ssid=b"Guest", channel=36, akm=8)
b3 = with_fcs(b2)
pk = [rt(with_fcs(b1), freq=2437), rt(with_fcs(b1), freq=2437), rt(b3, freq=5180, flags=0x10), rt(with_fcs(b2, good=False), freq=5180),
      rt(with_fcs(struct.pack("<HH", 0x00d4, 0) + mac(0x11)), freq=2437),                         # ACK 控制帧
      rt(with_fcs(eapol_frame())), rt(with_fcs(data_frame())), radiotap_hdr(version=3) + b1, rt(b"\x80")]
p = write("m.pcap", pcap(pk))
res, c = run(lambda: list(fr.iter_frames(p)))
check(len(res) == 6, "合成抓包：9 个包得到 6 个帧（1 个控制帧、1 个 radiotap 坏、1 个太短被丢）")
check(c.has(logging.INFO, "9 个包得到 6 个帧", "管理 4", "数据 2", "控制帧 1 个按设计跳过", logger="frames"), "总数、管理 / 数据帧数、控制帧数")
check(c.has(logging.INFO, "网络 11:11:11:11:11:11", "SSID HomeNet", "信道 6", "PSK", logger="frames"), "网络信息：SSID、信道、AKM（PSK）")
check(c.has(logging.INFO, "SSID HomeNet") and not c.has(logging.INFO, "SSID Guest", "PSK"), "同一个 BSSID 只报告一次（第一个信标）")
check(c.has(logging.INFO, "数据帧 2 个", "受保护 1 个", "EAPOL 帧 1 个"), "数据帧数、受保护数、EAPOL 数")
check(not c.has(logging.WARNING, "EAPOL 握手帧", logger="frames"), "有 EAPOL：不报没有握手")
check(c.has(logging.WARNING, "1 个帧的 FCS 校验不通过", "5 个通过", logger="frames"), "FCS 坏了 1 个：WARNING，同时报通过数")
check(c.has(logging.DEBUG, "被丢掉的包", "radiotap 头不合法 1", "帧不足 2 字节 1", logger="frames") and c.has(logging.DEBUG, "控制帧：ACK 1", logger="frames"), "DEBUG：被丢掉的包按原因计数；控制帧按子类型计数")
check(c.has(logging.DEBUG, "帧类型：", "Management/Beacon 4", "Data/Data 2", logger="frames"), "DEBUG：帧类型按（类型/子类型）计数")
check(c.has(logging.WARNING, "2 个包（22%）因格式不合法被丢掉", "radiotap 头不合法", logger="frames"), "被丢掉的包超过 5%：WARNING 带比例和原因")
check(not c.has(logging.INFO, "FCS：", "校验通过", logger="frames"), "有 FCS 坏的帧时用 WARNING 报，不再另报「校验通过」")
check(c.has(logging.WARNING, "2 个信道", logger="radiotap") and c.has(logging.WARNING, "1 个包的 radiotap 头坏了", logger="radiotap"), "radiotap 汇总在 iter_frames 结束时一起写：多信道 WARNING、坏头 WARNING")
check(c.has(logging.INFO, "时间跨度", "6.0 秒", "UTC 2023-11-14 22:13:20", logger="frames"), "时间跨度：秒数和 UTC 起止")
p2 = write("m2.pcap", pcap([rt(with_fcs(b2), freq=5180), rt(with_fcs(data_frame()))]))
res, c = run(lambda: list(fr.iter_frames(p2)))
check(c.has(logging.INFO, "FCS：2 个帧校验通过", logger="frames") and c.has(logging.INFO, "SAE", "信道 36") and c.has(logging.WARNING, "1 个 CCMP / TKIP 加密的数据帧", "没有 EAPOL 握手帧", "断开重连", logger="frames"), "WPA3（SAE）网络标出 SAE；有加密数据帧但没有握手：WARNING，说明怎么办")
p3 = write("m3.pcap", pcap([rt(with_fcs(data_frame(ext_iv=False))), rt(with_fcs(data_frame(ext_iv=False)))]))
res, c = run(lambda: list(fr.iter_frames(p3)))
check(c.has(logging.INFO, "2 个受保护的数据帧头里没有 ExtIV 位，是 WEP") and not c.msgs(logging.WARNING), "WEP 帧（没有 ExtIV）：不要求握手，INFO 说明；没有 WARNING")
p4 = write("m4.pcap", pcap([rt(with_fcs(beacon(akm=None, privacy=False)))]))
res, c = run(lambda: list(fr.iter_frames(p4)))
check(c.has(logging.INFO, "没有 RSN 元素（开放网络或 WEP / WPA1）"), "没有 RSN 元素、没有隐私位：开放网络")
p5 = write("m5.pcap", pcap([rt(with_fcs(mgmt_hdr(8) + b"\x01\x02")), rt(with_fcs(beacon()))]))
res, c = run(lambda: list(fr.iter_frames(p5)))
check(c.has(logging.INFO, "信标读不出"), "信标太短读不出 SSID：写「信标读不出」，不抛异常")

print("== frames：链路类型不支持 ==")
p = write("e.pcap", pcap([b"\x01" * 60] * 3, linktype=1))
res, c = run(lambda: list(fr.iter_frames(p)))
check(res == [] and c.has(logging.WARNING, "3 个包的链路类型不是 802.11", "1（EN10MB，以太网） 3 个") and c.has(logging.ERROR, "一个 802.11 帧也没读到", "支持：105", "127", "以太网", "cooked"), "以太网抓包送进 802.11 读取：WARNING + ERROR，列出支持的链路类型")
p = write("e2.pcap", pcap([b"\x01" * 60], linktype=147))
res, c = run(lambda: list(fr.iter_frames(p)))
check(c.has(logging.ERROR, "147（未知类型）"), "未知链路类型：ERROR 里写编号")
p = write("e3.pcap", pcap([]))
res, c = run(lambda: list(fr.iter_frames(p)))
check(res == [] and not c.msgs(logging.ERROR) and not c.msgs(logging.WARNING), "空抓包（0 个包）：不报「一个帧也没读到」的 ERROR")

print("== 日志不改变行为 ==")
fetch_samples.fetch()
names = ["wpa-Induction.pcap.gz", "wpa2-psk-mfp.pcapng.gz", "wpa-test-decode.pcap.gz"]
for name in names:
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    a, ca = run(lambda: list(fr.iter_frames(path)), logs.TRACE)
    b, cb = run(lambda: list(fr.iter_frames(path)), logging.CRITICAL)
    check(a == b and len(a) > 0 and cb.records == [], "%s：日志开到 TRACE 和关掉，读出的帧完全相同（%d 帧）；关掉时没有任何记录" % (name, len(a)))

print("== 真实样例 ==")
path = os.path.join(fetch_samples.SAMPLE_DIR, "wpa-Induction.pcap.gz")
res, c = run(lambda: list(fr.iter_frames(path)), logging.DEBUG)
check(c.has(logging.INFO, "77052 字节，gzip 压缩") and c.has(logging.INFO, "解压后 179298 字节") and c.has(logging.INFO, "snaplen 65535") and c.has(logging.INFO, "读到 1093 个包"), "wpa-Induction：文件大小、解压后大小、snaplen、包数")
check(c.has(logging.INFO, "1093 个包得到 737 个帧（管理 448、数据 286）；控制帧 356 个按设计跳过"), "wpa-Induction：1093 个包 -> 737 个帧（管理 448、数据 286、控制 356）")
check(c.has(logging.INFO, "网络 00:0c:41:82:b2:55：SSID Coherer，信道 1，RSN 认证方式 PSK") and c.has(logging.INFO, "受保护 280 个", "EAPOL 帧 4 个"), "wpa-Induction：网络是 Coherer / PSK；280 个受保护帧；4 个 EAPOL")
check(c.has(logging.WARNING, "13 个帧的 FCS 校验不通过", "724 个通过") and len(c.msgs(logging.WARNING)) == 1, "wpa-Induction：FCS 坏 13 个、好 724 个；这是唯一的 WARNING")
check(c.has(logging.INFO, "信道分布", "2412 MHz（2.4G 1 信道） 1093 个包", logger="radiotap") and c.has(logging.INFO, "1093 / 1093 个包带 FCS", logger="radiotap") and c.has(logging.INFO, "时间跨度：40.8 秒"), "wpa-Induction：radiotap 汇总（信道 1、全部带 FCS）和 40.8 秒的时间跨度")
check(len(c.records) < 25, "wpa-Induction：737 个帧只写了 %d 条记录（不逐帧）" % len(c.records))
big = os.path.join(fetch_samples.SAMPLE_DIR, "wpa-test-decode.pcap.gz")
res, c = run(lambda: list(fr.iter_frames(big)), logging.DEBUG)
check(len(res) == 4274 and len(c.records) < 25, "wpa-test-decode：4274 个帧只写了 %d 条记录（DEBUG 级别也不逐帧）" % len(c.records))
for name, want in (("wpa2-psk-mfp.pcapng.gz", None), ("wpa-gcmp.pcapng.gz", None), ("wpa3-sae.pcapng.gz", None)):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    res, c = run(lambda: list(fr.iter_frames(path)), logging.DEBUG)
    check(not c.msgs(logging.WARNING) and not c.msgs(logging.ERROR), "%s：干净的样例没有 WARNING / ERROR" % name)
path = os.path.join(fetch_samples.SAMPLE_DIR, "wpa3-sae.pcapng.gz")
res, c = run(lambda: list(fr.iter_frames(path)), logging.DEBUG)
check(c.has(logging.INFO, "RSN 认证方式 SAE", logger="frames") and c.has(logging.INFO, "Section 1", logger="capture") and c.has(logging.INFO, "接口 0", "127（", logger="capture"), "wpa3-sae：网络标出 SAE；pcapng 的 Section / 接口信息")
path = os.path.join(fetch_samples.SAMPLE_DIR, "wpa3-mlo.pcapng.gz")
res, c = run(lambda: list(fr.iter_frames(path)), logging.DEBUG)
check(c.has(logging.WARNING, "2 个信道", logger="radiotap"), "wpa3-mlo：两个信道的帧：WARNING")
path = os.path.join(fetch_samples.SAMPLE_DIR, "wep.pcapng.gz")
res, c = run(lambda: list(fr.iter_frames(path)), logging.DEBUG)
check(c.has(logging.INFO, "是 WEP") and not c.msgs(logging.WARNING), "wep 样例：识别为 WEP，不报缺握手")

print("== 不泄露、不遗漏 ==")
import re  # noqa: E402
allmsg = []
for name in os.listdir(fetch_samples.SAMPLE_DIR):
    res, c = run(lambda: list(fr.iter_frames(os.path.join(fetch_samples.SAMPLE_DIR, name))), logs.TRACE)
    allmsg += c.msgs()
check(len(allmsg) > 300 and not any(re.search(r"[0-9a-fA-F]{32}", m) for m in allmsg), "24 个样例全部 TRACE 级别共 %d 条记录，没有一条带 16 字节以上的十六进制" % len(allmsg))

print("== parser / ie / action / amsdu 的 TRACE ==")
res, c = run(lambda: w.parse_mac_header(b"\x08\x00" * 5))
check(isinstance(res, ValueError) and c.has(logs.TRACE, "MAC 头过短：10 字节（至少 24）", logger="parser"), "MAC 头不足 24 字节：TRACE 说明，仍抛 ValueError")
res, c = run(lambda: w.parse_mac_header(struct.pack("<BBH", 0x88, 0x00, 0) + mac(1) * 3 + b"\0\0"))
check(isinstance(res, ValueError) and c.has(logs.TRACE, "这个帧的头需要 26", logger="parser"), "QoS 数据帧只有 24 字节：TRACE 说明头需要 26 字节")
res, c = run(lambda: ie.walk(b"\x00\x05ab"))
check(res[1] is True and c.has(logs.TRACE, "元素 0 在偏移 0 被截断", "声明 5 字节，只剩 2 字节", logger="ie"), "元素长度超过剩余：TRACE")
res, c = run(lambda: ie.walk(b"\x00\x01a\x07"))
check(res[1] is True and c.has(logs.TRACE, "偏移 3", "连长度都没有", logger="ie"), "只剩 1 个字节：TRACE")
res, c = run(lambda: ie.decode_rsn(b"\x01"))
check(res is None and c.has(logs.TRACE, "RSN 元素只有 1 字节", logger="ie"), "RSN 不足版本号：TRACE")
res, c = run(lambda: ie.decode_rsn(b"\x01\x00" + b"\x00\x0f\xac\x04" + b"\x09\x00" + b"\x00\x0f\xac\x04"))
check(res["malformed"] and c.has(logs.TRACE, "pairwise 列表声明 9 项", logger="ie"), "RSN 成对套件个数超出：TRACE")
res, c = run(lambda: ie.decode_rsn(b"\x01\x00" + b"\x00\x0f\xac\x04" + b"\x01\x00\x00\x0f\xac\x04" + b"\x01\x00\x00\x0f\xac\x02" + b"\x00\x00" + b"\x05\x00"))
check(res["malformed"] and c.has(logs.TRACE, "PMKID 列表声明 5 项", logger="ie"), "RSN 的 PMKID 个数超出：TRACE")
res, c = run(lambda: ie.decode_all([ie.Element(48, None, b"\x01", 0), ie.Element(255, ie.EXT_HE_CAP, b"\x01", 0)]))
check(c.has(logs.TRACE, "元素 48（", "数据不合规", logger="ie") and c.has(logs.TRACE, "扩展元素 35（he_cap）数据不合规", logger="ie"), "元素解码器拒绝数据：TRACE 点名元素（普通元素和扩展元素各一条）")
check(ie.akm_name((0x000FAC, 8)) == "SAE" and ie.akm_name((0x000FAC, 2)) == "PSK" and ie.akm_name((0x000FAC, 99)) == "类型99" and ie.akm_name((0x00505E, 3)) == "00505e-3", "AKM 名字：已知的、不认识的类型、别的 OUI")
res, c = run(lambda: action.decode_action(b"\x03"))
check(res is None and c.has(logs.TRACE, "Action 帧体只有 1 字节", logger="action"), "Action 帧体太短：TRACE")
res, c = run(lambda: action.decode_action(b"\x65\x01\x02"))
check(res["category_name"] is None and c.has(logs.TRACE, "不认识的 Action 类别 101", logger="action"), "不认识的 Action 类别：TRACE")
res, c = run(lambda: action.decode_action(b"\x03\x00\x01"))
check(res["details"] is None and c.has(logs.TRACE, "类别 3 动作码 0 的内容解不出", logger="action"), "Block Ack 内容太短解不出：TRACE")
first = b"\x01" * 6 + b"\x02" * 6 + b"\x00\x04" + b"abcd" + b"\0\0"          # 一个完整的子帧（14 + 4 字节，补 2 字节填充到 20）
res, c = run(lambda: amsdu.parse(first + b"\x01\x02\x03"))
check(res["truncated"] is True and len(res["subframes"]) == 1 and c.has(logs.TRACE, "A-MSDU 在偏移 20 处剩 3 字节不足子帧头", logger="amsdu"), "A-MSDU 尾巴不足一个子帧头且不全是 0：TRACE")
res, c = run(lambda: amsdu.parse(first + b"\0\0\0"))
check(res["truncated"] is False and c.records == [], "尾巴全是 0（填充）：不算问题，不写日志")
sub = b"\x01" * 6 + b"\x02" * 6 + b"\x00\x08" + b"abcd"
res, c = run(lambda: amsdu.parse(sub))
check(res["truncated"] and c.has(logs.TRACE, "子帧声明 8 字节，只剩 4 字节", logger="amsdu"), "A-MSDU 子帧声明长度超过剩余：TRACE")
res, c = run(lambda: amsdu.parse(b"\x01" * 6 + b"\x02" * 6 + b"\x00\x00"))
check(len(res["subframes"]) == 1 and c.has(logs.TRACE, "子帧长度为 0", logger="amsdu"), "A-MSDU 长度 0 的子帧：TRACE")
res, c = run(lambda: amsdu.parse(b"\x01" * 6 + b"\x02" * 6 + b"\x00\x00"), logging.DEBUG)
check(c.records == [], "这些 TRACE 在 DEBUG 级别不输出（逐帧的东西不会出现在日志文件里）")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
