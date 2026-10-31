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
