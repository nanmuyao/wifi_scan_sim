# -*- coding: utf-8 -*-
"""
信息元素（Information Element，tagged parameters）。纯标准库。

管理帧固定部分之后是一串元素：1 字节 ID、1 字节长度、数据。ID 255 是“扩展元素”：数据的第一个字节是扩展 ID。
walk() 按出现顺序返回全部元素（同一 ID 可以出现多次，例如多个厂商元素），不丢弃、不合并；
元素的长度超过剩余字节时，已读到的保留，并报告 truncated。
"""
from collections import namedtuple

Element = namedtuple("Element", "id ext data offset")      # ext：扩展元素的扩展 ID，否则 None

ID_EXTENSION = 255

# 管理帧子类型 -> 固定部分长度（元素从这之后开始）。没有列出的子类型（Action 等）帧体不是元素序列。
FIXED_LEN = {
    0: 4,      # Association Request：能力 2 + 监听间隔 2
    1: 6,      # Association Response：能力 2 + 状态 2 + AID 2
    2: 10,     # Reassociation Request：能力 2 + 监听间隔 2 + 当前 AP 6
    3: 6,      # Reassociation Response：同 Association Response
    4: 0,      # Probe Request
    5: 12,     # Probe Response：时间戳 8 + 信标间隔 2 + 能力 2
    8: 12,     # Beacon：同 Probe Response
    10: 2,     # Disassociation：原因码
    11: 6,     # Authentication：算法 2 + 序号 2 + 状态 2
    12: 2,     # Deauthentication：原因码
}


def walk(buf):
    """返回 ([Element], truncated)。"""
    els, p, n = [], 0, len(buf)
    while p < n:
        if p + 2 > n:
            return els, True                       # 只剩 1 个字节：连长度都没有
        eid, length = buf[p], buf[p + 1]
        if p + 2 + length > n:
            return els, True                       # 长度超过剩余字节
        data = buf[p + 2:p + 2 + length]
        ext = None
        if eid == ID_EXTENSION and length >= 1:
            ext, data = data[0], data[1:]
        els.append(Element(eid, ext, bytes(data), p))
        p += 2 + length
    return els, False


def ids(els):
    """(普通元素 ID 列表, 扩展元素的扩展 ID 列表)，保持出现顺序。"""
    return ([e.id for e in els if e.id != ID_EXTENSION],
            [e.ext for e in els if e.id == ID_EXTENSION and e.ext is not None])


# ---------------------------------------------------------------------------
# 元素内容解码。每个解码函数收元素的数据，返回 dict；数据不合规（太短等）返回 None。
# decode_all() 对每种元素取第一次出现的那个，返回 {名字: 解码结果}。
# ---------------------------------------------------------------------------
def decode_ssid(d):
    return {"ssid": bytes(d)} if len(d) <= 32 else None          # 长度 0 = 广播 / 隐藏 SSID


def decode_rates(d):
    """支持速率：每字节低 7 位是速率（单位 500 kbps），最高位 = 基本速率（BSS 必须支持）。"""
    return {"rates": list(d), "mbps": [(b & 0x7F) / 2.0 for b in d], "basic": [bool(b & 0x80) for b in d]}


def decode_ds(d):
    return {"channel": d[0]} if len(d) >= 1 else None


def decode_tim(d):
    """TIM：DTIM 计数、DTIM 周期、位图控制（bit0 = 组播有缓存，bit1-7 = 位图偏移，单位 2 字节）、部分虚拟位图。"""
    if len(d) < 4:
        return None
    return {"dtim_count": d[0], "dtim_period": d[1], "multicast": bool(d[2] & 1),
            "offset": d[2] >> 1, "bitmap": bytes(d[3:])}


def decode_country(d):
    """国家：2 个字母 + 环境（空格 = 室内外都行，'O' 室外，'I' 室内），之后是 3 字节一组的三元组。
    第一个字节 < 201 是（起始信道，信道数，最大发射功率 dBm）；>= 201 是（运行扩展 ID，运行类别，覆盖类别）。
    总长为奇数时末尾有 1 字节填充。"""
    if len(d) < 6:
        return None
    triplets, p = [], 3
    while p + 3 <= len(d):
        a, b, c = d[p], d[p + 1], d[p + 2]
        if a >= 201:
            triplets.append({"operating_ext": a, "operating_class": b, "coverage_class": c})
        else:
            triplets.append({"first_channel": a, "num_channels": b, "max_power": c - 256 if c > 127 else c})
        p += 3
    return {"code": bytes(d[:2]).decode("ascii", "replace"), "environment": d[2], "triplets": triplets}


def decode_erp(d):
    """ERP 信息：bit0 有 non-ERP 站点，bit1 使用保护，bit2 Barker 前导码。"""
    if len(d) < 1:
        return None
    b = d[0]
    return {"value": b, "non_erp_present": bool(b & 1), "use_protection": bool(b & 2), "barker_preamble": bool(b & 4)}


# 元素 ID -> (名字, 解码函数)
DECODERS = {
    0: ("ssid", decode_ssid),
    1: ("rates", decode_rates),
    3: ("ds", decode_ds),
    5: ("tim", decode_tim),
    7: ("country", decode_country),
    42: ("erp", decode_erp),
    50: ("ext_rates", decode_rates),
}


def decode_all(els):
    """{名字: 解码结果}，每种元素只取第一次出现的；数据不合规的元素不出现在结果里。"""
    out = {}
    for e in els:
        spec = DECODERS.get(e.id)            # 扩展元素的 ID 是 255，不在这张表里
        if spec and spec[0] not in out:
            r = spec[1](e.data)
            if r is not None:
                out[spec[0]] = r
    return out
