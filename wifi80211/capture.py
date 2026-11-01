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
import logging
import struct
from collections import Counter, namedtuple

log = logging.getLogger(__name__)

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
OPT_IF_NAME, OPT_IF_TSRESOL = 2, 9
OPT_SHB_HARDWARE, OPT_SHB_OS, OPT_SHB_USERAPPL = 2, 3, 4
BLOCK_NAMES = {BT_IDB: "IDB", BT_PB: "PB", BT_SPB: "SPB", BT_NRB: "NRB", BT_ISB: "ISB", BT_EPB: "EPB", BT_DSB: "DSB", BT_SHB: "SHB"}
# 常见的链路类型（tcpdump / libpcap 的 DLT 编号）；日志里把编号翻成名字，错误提示里列出支持哪些
LINKTYPE_NAMES = {0: "NULL，回环", 1: "EN10MB，以太网", 101: "RAW，裸 IP", 105: "IEEE802_11，裸 802.11", 113: "LINUX_SLL，Linux cooked v1",
                  127: "IEEE802_11_RADIOTAP，802.11 + radiotap", 163: "IEEE802_11_AVS", 276: "LINUX_SLL2，Linux cooked v2"}
SUPPORTED_HINT = "支持：105（裸 802.11）、127（802.11 + radiotap）解密分析；1（以太网）、113 / 276（Linux cooked）当明文抓包分析"


def linktype_name(n):
    return "%d（%s）" % (n, LINKTYPE_NAMES.get(n, "未知类型"))


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
    gz = data[:2] == GZIP_MAGIC
    log.info("打开抓包文件 %s：%d 字节%s", path, len(data), "，gzip 压缩" if gz else "")
    if gz:
        try:
            data = gzip.decompress(data)
        except EOFError:
            # gzip 流被截断：能解多少解多少
            import zlib
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            data = d.decompress(data)
            log.warning("gzip 流被截断（文件没写完？），只解出 %d 字节", len(data))
        log.info("解压后 %d 字节", len(data))
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
    log.error("不认识的抓包文件格式：开头 4 字节是 %s。能读的是 pcap（含纳秒版）和 pcapng，可以再套一层 gzip；pcapng 以外的格式（如 snoop、Wi-Fi 厂商私有格式）请先用 tshark / editcap 转成 pcap", magic.hex() or "（空文件）")
    raise ValueError("不认识的抓包文件格式 (magic=%r)" % magic)


def _parse_pcap(data):
    endian, nano = PCAP_MAGICS[data[:4]]
    cap = Capture("pcap")
    if len(data) < 24:
        log.error("pcap 文件头不完整：只有 %d 字节（需要 24）", len(data))
        raise ValueError("pcap 文件过短")
    raw_lt = struct.unpack(endian + "I", data[20:24])[0]
    linktype = raw_lt & 0x0FFFFFFF   # 高位是 FCS 长度等标志
    snaplen = struct.unpack(endian + "I", data[16:20])[0]
    cap.linktypes.append(linktype)
    log.info("pcap 格式：%s 字节序，时间戳精度%s，链路类型 %s，snaplen %d", "小端" if endian == "<" else "大端", "纳秒" if nano else "微秒", linktype_name(linktype), snaplen)
    if raw_lt >> 28:
        log.debug("链路类型字段高位带标志 0x%x（FCS 长度等），已去掉", raw_lt >> 28)
    div = 1e9 if nano else 1e6
    off, n = 24, len(data)
    short = 0
    while off < n:
        if off + 16 > n:
            cap.truncated = True
            log.warning("文件在偏移 %d 处被截断：包头只剩 %d 字节（需要 16）", off, n - off)
            break
        sec, frac, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl > n:
            cap.truncated = True
            log.warning("文件在偏移 %d 处被截断：第 %d 个包声明 %d 字节，只剩 %d 字节", off - 16, len(cap.packets) + 1, incl, n - off)
            break
        cap.packets.append(Packet(sec + frac / div, incl, orig, data[off:off + incl], linktype, 0))
        short += incl < orig
        off += incl
    log.info("读到 %d 个包%s", len(cap.packets), "（被截断的文件，用了截断点之前的）" if cap.truncated else "")
    if short:
        log.warning("%d 个包被 snaplen 截短（捕获长度小于原始长度）；被截短的帧解不了密，tcpdump 请加 -s 0", short)
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


def _resol_name(div):
    return {1e3: "毫秒", 1e6: "微秒", 1e9: "纳秒"}.get(div, "1/%g 秒" % div)


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
    blocks, other, sections, short = Counter(), Counter(), 0, 0
    while off < n:
        if off + 12 > n:
            cap.truncated = True
            log.warning("文件在偏移 %d 处被截断：块头只剩 %d 字节（需要 12）", off, n - off)
            break
        if data[off:off + 4] == PCAPNG_MAGIC:
            # 新的 Section Header：字节序按它自己的 magic 重新确定，接口表清空
            bom = data[off + 8:off + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                log.error("pcapng Section Header（偏移 %d）的字节序标记不对：%s", off, bom.hex())
                raise ValueError("pcapng Section Header 的字节序标记不对: %r" % bom)
            ifaces = []
            sections += 1
        if endian is None:
            log.error("pcapng 文件不是以 Section Header 开头（偏移 %d）", off)
            raise ValueError("pcapng 文件不是以 Section Header 开头")
        btype, blen = struct.unpack(endian + "II", data[off:off + 8])
        if blen < 12 or blen % 4:
            log.error("pcapng 块长度不合法：%d（偏移 %d，块类型 0x%x）；文件可能损坏", blen, off, btype)
            raise ValueError("pcapng 块长度不合法: %d（偏移 %d）" % (blen, off))
        if off + blen > n:
            cap.truncated = True
            log.warning("文件在偏移 %d 处被截断：%s 块声明 %d 字节，只剩 %d 字节", off, BLOCK_NAMES.get(btype, "0x%x" % btype), blen, n - off)
            break
        body = data[off + 8:off + blen - 4]
        if btype in BLOCK_NAMES:
            blocks[BLOCK_NAMES[btype]] += 1
        else:
            other["0x%x" % btype] += 1
        if btype == BT_SHB:
            _log_section(body, endian, sections)
        if btype == BT_IDB:
            linktype = struct.unpack(endian + "H", body[0:2])[0]
            opts = _options(body[8:], endian)
            ifaces.append((linktype, _tsresol_divisor(opts)))
            cap.linktypes.append(linktype)
            log.info("pcapng 接口 %d：链路类型 %s，snaplen %d，接口名 %s，时间戳精度 %s", len(ifaces) - 1, linktype_name(linktype),
                     struct.unpack(endian + "I", body[4:8])[0], bytes(opts.get(OPT_IF_NAME, b"")).decode("utf-8", "replace") or "（没有）", _resol_name(ifaces[-1][1]))
        elif btype == BT_EPB:
            iface, th, tl, incl, orig = struct.unpack(endian + "IIIII", body[0:20])
            if iface >= len(ifaces):
                log.error("第 %d 个包（偏移 %d）引用了不存在的接口 %d（文件里只有 %d 个接口描述块）", len(cap.packets) + 1, off, iface, len(ifaces))
                raise ValueError("EPB 引用了不存在的接口 %d" % iface)
            lt, div = ifaces[iface]
            ts = ((th << 32) | tl) / div
            cap.packets.append(Packet(ts, incl, orig, body[20:20 + incl], lt, iface))
            short += incl < orig
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
    log.info("读到 %d 个包（%d 个接口，%d 个 Section）%s", len(cap.packets), len(cap.linktypes), sections, "（被截断的文件，用了截断点之前的）" if cap.truncated else "")
    log.debug("pcapng 块统计：%s%s", dict(blocks), "；不认识的块类型（已跳过）：%s" % dict(other) if other else "")
    if cap.secrets:
        log.info("文件里带 %d 个解密密钥块（DSB，类型 %s）；内容不记入日志，当前分析也不使用它们", len(cap.secrets), sorted({t for t, _ in cap.secrets}))
    if other:
        log.warning("有 %d 个块的类型不认识，已跳过：%s", sum(other.values()), dict(other))
    if short:
        log.warning("%d 个包被 snaplen 截短（捕获长度小于原始长度）；被截短的帧解不了密，抓包时请不要限制包长（tcpdump 加 -s 0）", short)
    return cap


def _log_section(body, endian, n):
    """Section Header 里的选项（硬件、操作系统、抓包程序）：知道文件是谁抓的，定位问题时很有用。"""
    if len(body) < 16:
        return
    major, minor = struct.unpack(endian + "HH", body[4:8])
    opts = _options(body[16:], endian)
    get = lambda c: bytes(opts.get(c, b"")).decode("utf-8", "replace") or "（没有）"       # noqa: E731
    log.info("pcapng Section %d：版本 %d.%d，抓包程序 %s，操作系统 %s，硬件 %s", n, major, minor, get(OPT_SHB_USERAPPL), get(OPT_SHB_OS), get(OPT_SHB_HARDWARE))
