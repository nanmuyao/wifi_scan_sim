# -*- coding: utf-8 -*-
"""
抓包文件读取：经典 pcap、pcapng，外面可以再套一层 gzip。纯标准库（struct + gzip）。

read_capture(path) 返回 Capture：
  .packets  每个包一个 Packet(ts, caplen, origlen, data, linktype, iface)
            ts 是秒（浮点），linktype 是这个包所在接口的链路类型
  .secrets  pcapng 的 Decryption Secrets Block：[(secrets_type, bytes)]；经典 pcap 为空
  .format   "pcap" 或 "pcapng"

遇到文件被截断时，返回截断点之前读到的包（和 tcpdump 被中断后留下的文件一致），
并把 .truncated 置为 True；格式本身不认识则抛 ValueError。
"""
import gzip
import struct
from collections import namedtuple

Packet = namedtuple("Packet", "ts caplen origlen data linktype iface")

GZIP_MAGIC = b"\x1f\x8b"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
# 经典 pcap 的 4 个 magic：(字节序, 时间戳是否纳秒)
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\xa1\xb2\x3c\x4d": (">", True),
}

# pcapng 块类型
BT_IDB, BT_PB, BT_SPB, BT_NRB, BT_ISB, BT_EPB, BT_DSB, BT_SHB = 1, 2, 3, 4, 5, 6, 0x0A, 0x0A0D0D0A
OPT_IF_TSRESOL = 9


class Capture:
    def __init__(self, fmt):
        self.format = fmt
        self.packets = []
        self.secrets = []
        self.truncated = False
        self.linktypes = []          # 每个接口的链路类型（经典 pcap 只有一个）


def _read_all(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] == GZIP_MAGIC:
        try:
            data = gzip.decompress(data)
        except EOFError:
            # gzip 流被截断：能解多少解多少
            import zlib
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            data = d.decompress(data)
    return data


def read_capture(path):
    data = _read_all(path)
    return parse_capture(data)


def parse_capture(data):
    magic = data[:4]
    if magic in PCAP_MAGICS:
        return _parse_pcap(data)
    if magic == PCAPNG_MAGIC:
        return _parse_pcapng(data)
    raise ValueError("不认识的抓包文件格式 (magic=%r)" % magic)


def _parse_pcap(data):
    endian, nano = PCAP_MAGICS[data[:4]]
    cap = Capture("pcap")
    if len(data) < 24:
        raise ValueError("pcap 文件过短")
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF   # 高位是 FCS 长度等标志
    cap.linktypes.append(linktype)
    div = 1e9 if nano else 1e6
    off, n = 24, len(data)
    while off < n:
        if off + 16 > n:
            cap.truncated = True
            break
        sec, frac, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl > n:
            cap.truncated = True
            break
        cap.packets.append(Packet(sec + frac / div, incl, orig, data[off:off + incl], linktype, 0))
        off += incl
    return cap


def _options(buf, endian):
    """解析 pcapng 选项列表，返回 {code: value}（同一个 code 出现多次只留第一个）。"""
    opts, off = {}, 0
    while off + 4 <= len(buf):
        code, length = struct.unpack(endian + "HH", buf[off:off + 4])
        off += 4
        if code == 0:
            break
        opts.setdefault(code, buf[off:off + length])
        off += (length + 3) & ~3
    return opts


def _tsresol_divisor(opts):
    v = opts.get(OPT_IF_TSRESOL)
    if not v:
        return 1e6                       # 默认微秒
    b = v[0]
    return float(2 ** (b & 0x7F)) if b & 0x80 else float(10 ** b)


def _parse_pcapng(data):
    cap = Capture("pcapng")
    off, n = 0, len(data)
    endian = None
    ifaces = []                          # [(linktype, 时间戳除数)]
    while off < n:
        if off + 12 > n:
            cap.truncated = True
            break
        if data[off:off + 4] == PCAPNG_MAGIC:
            # 新的 Section Header：字节序按它自己的 magic 重新确定，接口表清空
            bom = data[off + 8:off + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("pcapng Section Header 的字节序标记不对: %r" % bom)
            ifaces = []
        if endian is None:
            raise ValueError("pcapng 文件不是以 Section Header 开头")
        btype, blen = struct.unpack(endian + "II", data[off:off + 8])
        if blen < 12 or blen % 4:
            raise ValueError("pcapng 块长度不合法: %d（偏移 %d）" % (blen, off))
        if off + blen > n:
            cap.truncated = True
            break
        body = data[off + 8:off + blen - 4]
        if btype == BT_IDB:
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            ifaces.append((linktype, _tsresol_divisor(_options(body[8:], endian))))
            cap.linktypes.append(linktype)
        elif btype == BT_EPB:
            iface, th, tl, incl, orig = struct.unpack(endian + "IIIII", body[0:20])
            if iface >= len(ifaces):
                raise ValueError("EPB 引用了不存在的接口 %d" % iface)
            lt, div = ifaces[iface]
            ts = ((th << 32) | tl) / div
            cap.packets.append(Packet(ts, incl, orig, body[20:20 + incl], lt, iface))
        elif btype == BT_SPB:
            orig = struct.unpack(endian + "I", body[0:4])[0]
            lt = ifaces[0][0] if ifaces else 0
            incl = min(orig, len(body) - 4)
            cap.packets.append(Packet(0.0, incl, orig, body[4:4 + incl], lt, 0))
        elif btype == BT_PB:                          # 过时的 Packet Block
            iface, _drops, th, tl, incl, orig = struct.unpack(endian + "HHIIII", body[0:20])
            lt, div = ifaces[iface] if iface < len(ifaces) else (0, 1e6)
            cap.packets.append(Packet(((th << 32) | tl) / div, incl, orig, body[20:20 + incl], lt, iface))
        elif btype == BT_DSB:
            stype, slen = struct.unpack(endian + "II", body[0:8])
            cap.secrets.append((stype, body[8:8 + slen]))
        # SHB、NRB、ISB、自定义块等：跳过
        off += blen
    return cap
