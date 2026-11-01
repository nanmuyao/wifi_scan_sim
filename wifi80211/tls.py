# -*- coding: utf-8 -*-
"""
TLS ClientHello（RFC 8446 / 5246）：从一条 TCP 连接里客户端发出的最前面那段字节，读出它要连哪台服务器（SNI）和协商的参数。纯标准库。
不解密、不看服务器回复；只回答「这个客户端想访问什么域名」。握手消息可以被拆在多个 TLS 记录里。
parse_client_hello 对不是 ClientHello、结构不对返回 None，不抛异常；数据在 ClientHello 中途结束时，只有已经读到 SNI 才返回（带 truncated）。
"""
import struct

HANDSHAKE = 22
CLIENT_HELLO = 1
EXT_SNI, EXT_ALPN, EXT_SUPPORTED_VERSIONS, EXT_ECH, EXT_ESNI = 0, 16, 43, 0xFE0D, 0xFFCE
TLS13 = 0x0304


class _Bad(Exception):
    pass


def _handshake_bytes(stream):
    """把开头连续的握手记录拼起来 -> (握手字节, 第一个记录的版本)；第一个记录就不是握手记录返回 None。
    拼到第一条握手消息完整为止；记录自己被截断就拼到哪算哪。"""
    p, out, first = 0, bytearray(), None
    while len(stream) - p >= 5:
        rtype, major, minor, n = stream[p], stream[p + 1], stream[p + 2], struct.unpack(">H", stream[p + 3:p + 5])[0]
        if rtype != HANDSHAKE or major != 3:
            break
        if first is None:
            first = (major << 8) | minor
        frag = stream[p + 5:p + 5 + n]
        out += frag
        if len(frag) < n:
            break
        p += 5 + n
        if len(out) >= 4 and len(out) >= 4 + int.from_bytes(out[1:4], "big"):
            break
    if first is None:
        return None
    return bytes(out), first


class _Reader:
    def __init__(self, b):
        self.b, self.p, self.end = b, 0, len(b)

    def take(self, n):
        if self.p + n > self.end:
            raise _Bad()
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return int.from_bytes(self.take(2), "big")


def _name(b):
    try:
        return bytes(b).decode("utf-8")
    except UnicodeDecodeError:
        return bytes(b).decode("latin-1")


def _extension(res, etype, body):
    r = _Reader(body)
    if etype == EXT_SNI:
        if r.u16() != len(body) - 2:
            raise _Bad()
        while r.p < len(body):
            kind, name = r.u8(), r.take(r.u16())
            if kind == 0:
                res["sni"].append(_name(name))
    elif etype == EXT_ALPN:
        if r.u16() != len(body) - 2:
            raise _Bad()
        while r.p < len(body):
            res["alpn"].append(_name(r.take(r.u8())))
    elif etype == EXT_SUPPORTED_VERSIONS:
        n = r.u8()
        if n != len(body) - 1 or n % 2:
            raise _Bad()
        res["supported_versions"] = [r.u16() for _ in range(n // 2)]


def parse_client_hello(stream):
    """-> {"record_version", "version"（legacy_version）, "supported_versions", "tls13", "sni"[...], "alpn"[...], "cipher_suites"（个数）,
    "extensions"[类型...], "ech", "esni", "truncated"}，或 None。sni 是 host_name 条目（通常 1 个，没有则空表）。"""
    h = _handshake_bytes(stream)
    if h is None or len(h[0]) < 4 or h[0][0] != CLIENT_HELLO:
        return None
    data, rec_version = h
    want = int.from_bytes(data[1:4], "big")
    body = data[4:4 + want]
    complete = len(body) == want
    res = {"record_version": rec_version, "version": None, "supported_versions": [], "tls13": False, "sni": [], "alpn": [], "cipher_suites": 0,
           "extensions": [], "ech": False, "esni": False, "truncated": not complete}
    r = _Reader(body)
    try:
        res["version"] = r.u16()
        r.take(32)
        r.take(r.u8())
        n = r.u16()
        if n % 2:
            raise _Bad()
        r.take(n)
        res["cipher_suites"] = n // 2
        r.take(r.u8())
        if r.p == len(body) and complete:                               # 没有扩展的老式 ClientHello
            return res
        ext_end = r.u16()
        if complete and r.p + ext_end != len(body):
            raise _Bad()
        r.end = min(r.end, r.p + ext_end)
        while r.p < r.end:
            etype, n = r.u16(), r.u16()
            if r.p + n > r.end:
                if complete:
                    raise _Bad()
                break
            res["extensions"].append(etype)
            _extension(res, etype, r.take(n))
    except _Bad:
        if complete or not res["sni"]:                                  # 没到齐的消息，坏在已读到 SNI 之后：保留已读到的（truncated 本来就为真）
            return None
    if not complete and not res["sni"]:
        return None
    res["tls13"] = TLS13 in res["supported_versions"]
    res["ech"] = EXT_ECH in res["extensions"]
    res["esni"] = EXT_ESNI in res["extensions"]
    return res
