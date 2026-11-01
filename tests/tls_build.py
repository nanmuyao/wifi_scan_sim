# -*- coding: utf-8 -*-
"""独立的 ClientHello 构造器（和 wifi80211/tls.py 不共用代码）：测试用它造各种形状的 ClientHello，再包成 TLS 记录。"""
import struct


def u16(n):
    return struct.pack(">H", n)


def ext(etype, body):
    return u16(etype) + u16(len(body)) + body


def sni_ext(*names):
    entries = b"".join(b"\x00" + u16(len(n.encode())) + n.encode() for n in names)
    return ext(0, u16(len(entries)) + entries)


def alpn_ext(*protos):
    entries = b"".join(bytes([len(p)]) + p.encode() for p in protos)
    return ext(16, u16(len(entries)) + entries)


def versions_ext(*vs):
    return ext(43, bytes([2 * len(vs)]) + b"".join(u16(v) for v in vs))


def hello(extensions=(), ciphers=(0x1301, 0xc02f), version=0x0303, session=b"", compression=b"\x00", raw_extensions=None, raw_ciphers=None, claim_extra=0):
    """ClientHello 握手消息（含 4 字节握手头）。extensions 是已编码的扩展列表；raw_extensions 给了就原样当扩展区（含它自己的长度字段）；
    raw_ciphers 原样当密码套件字节；claim_extra 让握手头声明的长度比实际多这么多字节（造「数据没到齐」）。"""
    body = u16(version) + bytes(range(32)) + bytes([len(session)]) + session
    cs = raw_ciphers if raw_ciphers is not None else b"".join(u16(c) for c in ciphers)
    body += u16(len(cs)) + cs + bytes([len(compression)]) + compression
    if raw_extensions is not None:
        body += raw_extensions
    elif extensions:
        e = b"".join(extensions)
        body += u16(len(e)) + e
    return b"\x01" + (len(body) + claim_extra).to_bytes(3, "big") + body


def records(handshake, cuts=(), version=0x0301):
    """把握手字节包成 TLS 握手记录；cuts 是在握手字节里切开的位置（每段一个记录）。"""
    pos = [0] + list(cuts) + [len(handshake)]
    return b"".join(b"\x16" + u16(version) + u16(b - a) + handshake[a:b] for a, b in zip(pos, pos[1:]))
