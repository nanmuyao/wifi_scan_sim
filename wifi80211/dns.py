# -*- coding: utf-8 -*-
"""
DNS 报文（RFC 1035；mDNS 的报文格式相同）：解出提问和应答里的域名与地址，用来回答「这台设备查了什么、得到什么地址」。纯标准库。
parse 对结构不对（头不足 12 字节、提问被截断、指针成环）返回 None，不抛异常；应答区解到一半坏了，保留已解出的并标 truncated。
"""
import struct

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
MAX_JUMPS = 32


def _label(b):
    """标签字节 -> 文本。mDNS 的服务名常是 UTF-8（Karen’s iMac），不是合法 UTF-8 的按 latin-1 逐字节保留。"""
    try:
        return bytes(b).decode("utf-8")
    except UnicodeDecodeError:
        return bytes(b).decode("latin-1")


def read_name(msg, p):
    """从 msg[p] 读一个域名（含压缩指针）-> (名字, 下一个字段的位置)；不合法返回 None。名字不带结尾的点，根是 ""。"""
    labels, nxt, jumps, total = [], None, 0, 0
    while True:
        if p >= len(msg):
            return None
        n = msg[p]
        if n == 0:
            p += 1
            break
        if n & 0xC0 == 0xC0:                                             # 压缩指针：14 位偏移，指回报文里更早的位置
            if p + 2 > len(msg):
                return None
            target = ((n & 0x3F) << 8) | msg[p + 1]
            jumps += 1
            if jumps > MAX_JUMPS or target >= p:
                return None
            if nxt is None:
                nxt = p + 2
            p = target
            continue
        if n & 0xC0 or p + 1 + n > len(msg):                              # 0x40 / 0x80 是保留的标签类型
            return None
        total += n + 1
        if total > 255:
            return None
        labels.append(_label(msg[p + 1:p + 1 + n]))
        p += 1 + n
    return ".".join(labels), (nxt if nxt is not None else p)


def _rdata(msg, p, end, rtype):
    if rtype == 1 and end - p == 4:
        return ".".join(str(x) for x in msg[p:end])
    if rtype == 28 and end - p == 16:
        return ":".join("%x" % int.from_bytes(msg[i:i + 2], "big") for i in range(p, end, 2))
    if rtype in (2, 5, 12):
        r = read_name(msg, p)
        return r[0] if r and r[1] <= end else bytes(msg[p:end])
    return bytes(msg[p:end])


def _record(msg, p, question):
    r = read_name(msg, p)
    if r is None or r[1] + (4 if question else 10) > len(msg):
        return None
    name, p = r
    if question:
        rtype, cls = struct.unpack(">HH", msg[p:p + 4])
        return {"name": name, "type": rtype, "class": cls & 0x7FFF, "top_bit": cls >> 15}, p + 4
    rtype, cls, ttl, rdlen = struct.unpack(">HHIH", msg[p:p + 10])
    p += 10
    if p + rdlen > len(msg):
        return None
    rec = {"name": name, "type": rtype, "class": cls & 0x7FFF, "top_bit": cls >> 15, "ttl": ttl, "data": _rdata(msg, p, p + rdlen, rtype)}
    return rec, p + rdlen


def parse(msg):
    """-> {"id", "response", "opcode", "rcode", "flags", "questions": [{name, type, class, top_bit}], "answers"/"authority"/"additional": [{..., ttl, data}], "truncated"}。
    data：A / AAAA / NS / CNAME / PTR 是字符串，其余类型是原始字节。"""
    if len(msg) < 12:
        return None
    ident, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12])
    out = {"id": ident, "flags": flags, "response": bool(flags >> 15), "opcode": (flags >> 11) & 15, "rcode": flags & 15,
           "questions": [], "answers": [], "authority": [], "additional": [], "truncated": False}
    p = 12
    for _ in range(qd):
        r = _record(msg, p, True)
        if r is None:
            return None
        out["questions"].append(r[0])
        p = r[1]
    for key, count in (("answers", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            r = _record(msg, p, False)
            if r is None:
                out["truncated"] = True
                return out
            out[key].append(r[0])
            p = r[1]
    return out


def type_name(t):
    return TYPES.get(t, "TYPE%d" % t)
