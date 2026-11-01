# -*- coding: utf-8 -*-
"""
A-MSDU（聚合 MSDU）：一个 QoS 数据帧的帧体里装多个子帧。纯标准库。

QoS Control 的 bit7（A-MSDU Present）置位时，帧体是一串子帧：
    目的地址 6 + 源地址 6 + 长度 2（大端，不含填充）+ 数据（通常以 LLC/SNAP 开头）+ 填充到 4 字节的整数倍
最后一个子帧后面没有填充。
受保护的帧体是密文，要解密之后才能按这个格式读（阶段 D）。
"""
import logging

from . import logs

log = logging.getLogger(__name__)
SUBFRAME_HEADER = 14


def mac_str(b):
    return ":".join("%02x" % x for x in b)


def parse(body):
    """返回 {"subframes": [{"da", "sa", "length", "payload", "truncated"}], "truncated": bool}。
    某个子帧的 14 字节头完整、但声明的长度超过剩余字节时，这个子帧仍然列出（length 是声明的值，payload 是剩下的字节，
    子帧的 "truncated" 为 True，整体也是），之后没有子帧了——tshark 也是这样处理的。
    剩下不足 14 字节的尾巴：全是 0（填充）不算问题，否则整体 "truncated" 为 True（没有子帧可列）。
    长度 0 的子帧照常算一个子帧、继续往下读（tshark 在这里停止，我们不照抄：标准没有这样规定）。"""
    subs, p, n = [], 0, len(body)
    truncated = False
    while p < n:
        if p + SUBFRAME_HEADER > n:
            truncated = any(body[p:])
            if truncated:
                logs.trace(log, "A-MSDU 在偏移 %d 处剩 %d 字节不足子帧头，且不全是填充", p, n - p)
            break
        length = body[p + 12] << 8 | body[p + 13]
        end = p + SUBFRAME_HEADER + length
        cut = end > n
        subs.append({"da": mac_str(body[p:p + 6]), "sa": mac_str(body[p + 6:p + 12]), "length": length,
                     "payload": bytes(body[p + SUBFRAME_HEADER:min(end, n)]), "truncated": cut})
        if length == 0:
            logs.trace(log, "A-MSDU 偏移 %d 的子帧长度为 0，照常算一个子帧", p)
        if cut:
            logs.trace(log, "A-MSDU 偏移 %d 的子帧声明 %d 字节，只剩 %d 字节", p, length, n - p - SUBFRAME_HEADER)
            truncated = True
            break
        p = end + (-(SUBFRAME_HEADER + length)) % 4
    return {"subframes": subs, "truncated": truncated}
