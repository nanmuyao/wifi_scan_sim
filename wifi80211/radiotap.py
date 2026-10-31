# -*- coding: utf-8 -*-
"""
Radiotap 头解析（https://www.radiotap.org/ 的字段表）。纯标准库。

radiotap 是网卡给每个抓到的包前面加的元数据：信道、信号强度、速率、时间戳等。
布局：4 字节固定头（版本、填充、总长度）+ 若干 32 位 present 位图（最高位=后面还有一个位图）
+ 按位图顺序排列的字段，每个字段按自己的大小对齐（对齐从 radiotap 头起点算起）。

parse(buf) 返回 dict：
    length         radiotap 头的总长度，802.11 帧从 buf[length:] 开始
    present        present 位图列表
    fcs_included   flags 字段的 FCS 位：帧末尾带 4 字节 FCS
    其余键         按字段名（见 FIELDS）；有多个值的字段（多天线）放第一个，全部在 "<名字>_all"
遇到不认识的字段位时停止解析（后面的字段位置无法知道），已解析出的照常返回，"stopped_at" 说明停在哪一位。
"""
import struct

# 位号 -> (名字, 对齐, 大小, struct 格式, 子字段名)
FIELDS = {
    0: ("tsft", 8, 8, "<Q", None),
    1: ("flags", 1, 1, "<B", None),
    2: ("rate", 1, 1, "<B", None),                       # 单位 500 kbps
    3: ("channel", 2, 4, "<HH", ("freq", "flags")),
    4: ("fhss", 1, 2, "<BB", ("hop_set", "hop_pattern")),
    5: ("antsignal", 1, 1, "<b", None),                  # dBm
    6: ("antnoise", 1, 1, "<b", None),                   # dBm
    7: ("lock_quality", 2, 2, "<H", None),
    8: ("tx_attenuation", 2, 2, "<H", None),
    9: ("db_tx_attenuation", 2, 2, "<H", None),
    10: ("tx_power", 1, 1, "<b", None),                  # dBm
    11: ("antenna", 1, 1, "<B", None),
    12: ("db_antsignal", 1, 1, "<B", None),
    13: ("db_antnoise", 1, 1, "<B", None),
    14: ("rx_flags", 2, 2, "<H", None),
    15: ("tx_flags", 2, 2, "<H", None),
    16: ("rts_retries", 1, 1, "<B", None),
    17: ("data_retries", 1, 1, "<B", None),
    18: ("xchannel", 4, 8, "<IHBB", ("flags", "freq", "channel", "max_power")),
    19: ("mcs", 1, 3, "<BBB", ("known", "flags", "index")),
    20: ("ampdu", 4, 8, "<IHBB", ("reference", "flags", "delimiter_crc", "reserved")),
    21: ("vht", 2, 12, "<HBB4sBBH", ("known", "flags", "bandwidth", "mcs_nss", "coding", "group_id", "partial_aid")),
    22: ("timestamp", 8, 12, "<QHBB", ("ts", "accuracy", "unit_position", "flags")),
    23: ("he", 2, 12, "<6H", ("data1", "data2", "data3", "data4", "data5", "data6")),
    24: ("he_mu", 2, 12, "<HH4s4s", ("flags1", "flags2", "ru_channel1", "ru_channel2")),
    25: ("he_mu_other_user", 2, 6, "<HHBB", ("per_user_1", "per_user_2", "per_user_position", "per_user_known")),
    26: ("zero_len_psdu", 1, 1, "<B", None),
    27: ("lsig", 2, 4, "<HH", ("data1", "data2")),
}
BIT_TLV, BIT_RT_NS, BIT_VENDOR_NS, BIT_EXT = 28, 29, 30, 31
FLAG_FCS = 0x10


def _decode(name, fmt, keys, data):
    vals = struct.unpack(fmt, data)
    if keys is None:
        return vals[0]
    return dict(zip(keys, vals))


class _Out(dict):
    def put(self, name, value):
        if name in self:
            self.setdefault(name + "_all", [self[name]]).append(value)
        else:
            self[name] = value


def parse(buf):
    if len(buf) < 8:
        raise ValueError("radiotap 头过短: %d 字节" % len(buf))
    version, _pad, length = struct.unpack("<BBH", buf[:4])
    if version != 0:
        raise ValueError("不认识的 radiotap 版本 %d" % version)
    if length < 8 or length > len(buf):
        raise ValueError("radiotap 长度不合法: %d（包共 %d 字节）" % (length, len(buf)))

    present, off = [], 4
    while True:
        if off + 4 > length:
            raise ValueError("present 位图超出 radiotap 头")
        w = struct.unpack("<I", buf[off:off + 4])[0]
        present.append(w)
        off += 4
        if not (w >> BIT_EXT) & 1:
            break

    out = _Out(length=length, present=present, fcs_included=False)
    ns = "radiotap"                       # 当前位图所在的命名空间
    word_base = 0                         # 这个位图在命名空间里的第几个 32 位
    fresh = True                          # 这个位图是不是刚进入这个命名空间（厂商命名空间进入时才有 6 字节头）
    for i, w in enumerate(present):
        if ns == "vendor":
            if not fresh:
                continue_ns = True
            else:
                continue_ns = False
        if ns == "vendor" and not continue_ns:
            off = (off + 1) & ~1
            if off + 6 > length:
                out["stopped_at"] = "vendor"
                break
            skip = struct.unpack("<H", buf[off + 4:off + 6])[0]
            off += 6 + skip               # 厂商字段的内容不解析，按声明的长度跳过
        elif ns == "vendor":
            pass                          # 厂商命名空间的扩展位图：内容已随头里的长度跳过
        elif word_base > 0:
            out["stopped_at"] = "bit%d" % (32 * word_base)     # radiotap 命名空间只定义了 0-31 位
            break
        else:
            stop = False
            for bit in range(0, 28):
                if not (w >> bit) & 1:
                    continue
                if bit not in FIELDS:
                    out["stopped_at"] = "bit%d" % bit
                    stop = True
                    break
                name, align, size, fmt, keys = FIELDS[bit]
                off = (off + align - 1) & ~(align - 1)
                if off + size > length:
                    raise ValueError("radiotap 字段 %s 超出头长度" % name)
                out.put(name, _decode(name, fmt, keys, buf[off:off + size]))
                off += size
            if stop:
                break
            if (w >> BIT_TLV) & 1:
                _parse_tlvs(buf, (off + 3) & ~3, length, out)      # TLV 部分从 4 字节对齐处开始
                break
        # 下一个位图属于哪个命名空间
        if (w >> BIT_RT_NS) & 1:
            ns, word_base, fresh = "radiotap", 0, True
        elif (w >> BIT_VENDOR_NS) & 1:
            ns, word_base, fresh = "vendor", 0, True
        elif (w >> BIT_EXT) & 1:
            word_base, fresh = word_base + 1, False
    flags = out.get("flags")
    out["fcs_included"] = bool(flags is not None and flags & FLAG_FCS)
    return dict(out)


def _parse_tlvs(buf, off, length, out):
    """位 28：后面是 TLV 列表（类型 2 字节、长度 2 字节、数据补齐到 4 字节）。
    标准字段的 TLV 类型号与位号相同，按同一张表解码；其余跳过。"""
    while off + 4 <= length:
        ttype, tlen = struct.unpack("<HH", buf[off:off + 4])
        off += 4
        if off + tlen > length:
            raise ValueError("radiotap TLV 超出头长度")
        spec = FIELDS.get(ttype)
        if spec and tlen >= spec[2]:
            name, _a, size, fmt, keys = spec
            out.put(name, _decode(name, fmt, keys, buf[off:off + size]))
        off += (tlen + 3) & ~3


# ---- 由 MCS 算数据速率（HT，802.11n）----
# MCS 0-7 的 (每子载波比特数, 编码率)；MCS 8-31 是同样的调制乘以空间流数 (index // 8 + 1)
_HT_MOD = [(1, 1 / 2), (2, 1 / 2), (2, 3 / 4), (4, 1 / 2), (4, 3 / 4), (6, 2 / 3), (6, 3 / 4), (6, 5 / 6)]
MCS_KNOWN_BW, MCS_KNOWN_INDEX, MCS_KNOWN_GI = 0x01, 0x02, 0x04
MCS_FLAG_BW_MASK, MCS_BW_40, MCS_FLAG_SGI = 0x03, 1, 0x04


def ht_rate_mbps(known, flags, index):
    """HT 数据速率（Mbps）：数据子载波数 × 每子载波比特 × 编码率 × 空间流数 / 符号时长。
    20 MHz 52 个数据子载波，40 MHz 108 个；符号时长 4 us，短保护间隔 3.6 us。
    index 未知或超出 0-31 时返回 None；带宽 / 保护间隔未知按 20 MHz / 长间隔。"""
    if not known & MCS_KNOWN_INDEX or index > 31:
        return None
    bits, coding = _HT_MOD[index % 8]
    streams = index // 8 + 1
    wide = bool(known & MCS_KNOWN_BW) and (flags & MCS_FLAG_BW_MASK) == MCS_BW_40
    short_gi = bool(known & MCS_KNOWN_GI) and bool(flags & MCS_FLAG_SGI)
    return (108 if wide else 52) * bits * coding * streams / (3.6 if short_gi else 4.0)


def data_rate_mbps(rt):
    """parse() 结果里的数据速率（Mbps）：有 rate 字段用它，否则由 HT 的 MCS 算；都没有返回 None。"""
    if rt.get("rate") is not None:
        return rt["rate"] / 2.0
    m = rt.get("mcs")
    if m:
        return ht_rate_mbps(m["known"], m["flags"], m["index"])
    return None
