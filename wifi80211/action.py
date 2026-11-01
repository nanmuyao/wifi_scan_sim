# -*- coding: utf-8 -*-
"""
Action 帧体（管理帧子类型 13 / 14）。纯标准库。

帧体：类别 1 字节 + 动作码 1 字节 + 与类别相关的内容。
类别的最高位（bit7）置位表示「错误响应」（对一个失败请求的回复），低 7 位仍是类别号，例如 0x83 = Block Ack 的错误响应。
受保护的 Action 帧（Frame Control 的 Protected 位）帧体是密文，不能按这里的格式读。

这里解码：Block Ack（类别 3：ADDBA 请求 / 响应、DELBA）和 High Throughput（类别 7：通知信道宽度、SM 省电）。
其余类别只给出类别名、动作码和原始内容。
"""
import logging

from . import logs

log = logging.getLogger(__name__)

# 类别名称沿用 Wireshark 的写法（tests/oracle/test_action_names.py 与 tshark 的值表逐项对照）
CATEGORY_NAMES = {
    0: "Spectrum Management (SM)", 1: "Quality of Service (QoS)", 2: "Direct-Link Setup (DLS)", 3: "Block Ack",
    4: "Public Action", 5: "Radio Measurement", 6: "Fast BSS Transition", 7: "High Throughput", 8: "SA Query",
    9: "Protected Dual of Public Action", 10: "WNM", 11: "Unprotected WNM", 12: "TDLS", 13: "MESH", 14: "Multihop",
    15: "Self-protected", 16: "DMG", 17: "Management Notification", 18: "Fast Session Transfer",
    19: "Robust AV Streaming", 20: "Unprotected DMG", 21: "VHT", 22: "S1G", 23: "Protected S1G", 24: "Flow Control",
    25: "Control Response MCS Negotiation", 26: "FILS", 30: "HE", 31: "Protected HE", 34: "Protected FTM", 36: "EHT",
    37: "Protected EHT", 126: "Vendor-specific Protected", 127: "Vendor Specific",
}
CAT_BLOCK_ACK, CAT_HT = 3, 7
BA_ADDBA_REQUEST, BA_ADDBA_RESPONSE, BA_DELBA = 0, 1, 2
HT_NOTIFY_CHANNEL_WIDTH, HT_SM_POWER_SAVE = 0, 1


def _u16(b, p):
    return b[p] | b[p + 1] << 8


def ba_params(v):
    """Block Ack 参数集（16 位）：bit0 允许 A-MSDU，bit1 立即块确认（0 = 延迟），bit2-5 TID，bit6-15 缓冲区数（每个 2304 字节）。"""
    return {"value": v, "amsdu": bool(v & 1), "immediate": bool(v >> 1 & 1), "tid": v >> 2 & 0xF, "buffers": v >> 6 & 0x3FF}


def decode_block_ack(code, d):
    """d 是动作码之后的内容。ADDBA 请求：对话令牌 1 + 参数 2 + 超时 2 + 起始序列控制 2（bit0-3 分片，bit4-15 起始序号）；
    ADDBA 响应：对话令牌 1 + 状态码 2 + 参数 2 + 超时 2；DELBA：参数 2（bit11 发起方，bit12-15 TID）+ 原因码 2。
    长度不够返回 None。"""
    if code == BA_ADDBA_REQUEST and len(d) >= 7:
        ssc = _u16(d, 5)
        return {"dialog_token": d[0], "params": ba_params(_u16(d, 1)), "timeout": _u16(d, 3),
                "ssc": ssc, "fragment": ssc & 0xF, "start_seq": ssc >> 4}
    if code == BA_ADDBA_RESPONSE and len(d) >= 7:
        return {"dialog_token": d[0], "status": _u16(d, 1), "params": ba_params(_u16(d, 3)), "timeout": _u16(d, 5)}
    if code == BA_DELBA and len(d) >= 4:
        p = _u16(d, 0)
        return {"params": p, "initiator": bool(p >> 11 & 1), "tid": p >> 12 & 0xF, "reason": _u16(d, 2)}
    return None


def decode_ht(code, d):
    """通知信道宽度（动作 0）：1 字节，0 = 仅 20MHz，1 = 任意宽度；
    SM 省电（动作 1）：1 字节，bit0 SM 省电开启，bit1 模式（0 静态，1 动态）。"""
    if code == HT_NOTIFY_CHANNEL_WIDTH and len(d) >= 1:
        return {"channel_width": d[0]}
    if code == HT_SM_POWER_SAVE and len(d) >= 1:
        return {"control": d[0], "sm_enabled": bool(d[0] & 1), "sm_dynamic": bool(d[0] >> 1 & 1)}
    return None


def decode_action(body):
    """Action 帧体 -> dict；不足 2 字节返回 None。键：category（低 7 位）、error_response、category_name、code、payload（动作码之后的原始字节）、
    details（已解码的内容，或 None）。"""
    if len(body) < 2:
        logs.trace(log, "Action 帧体只有 %d 字节（至少 2：类别 + 动作码）", len(body))
        return None
    raw = body[0]
    cat = raw & 0x7F
    code = body[1]
    payload = bytes(body[2:])
    details = None
    if cat == CAT_BLOCK_ACK:
        details = decode_block_ack(code, payload)
    elif cat == CAT_HT:
        details = decode_ht(code, payload)
    if cat not in CATEGORY_NAMES:
        logs.trace(log, "不认识的 Action 类别 %d（动作码 %d），只给原始内容", cat, code)
    elif details is None and cat in (CAT_BLOCK_ACK, CAT_HT):
        logs.trace(log, "Action 类别 %d 动作码 %d 的内容解不出（长度 %d），只给原始内容", cat, code, len(payload))
    return {"category_raw": raw, "category": cat, "error_response": bool(raw & 0x80),
            "category_name": CATEGORY_NAMES.get(cat), "code": code, "payload": payload, "details": details}
