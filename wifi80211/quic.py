# -*- coding: utf-8 -*-
"""
QUIC 客户端 Initial 包（RFC 9000 / 9001，v2 见 RFC 9369）：取出里面的 TLS ClientHello，用来读 SNI。

Initial 包的密钥只由目的连接 ID 和协议里公开的盐推出（RFC 9001 5.2），任何旁观者都能解开——这不是破解，是协议的设计：
握手前的内容本来就不保密。只处理客户端发出的 Initial（服务端的 Initial 用客户端最初选的连接 ID 推密钥，客户端密钥解它
认证不会通过，返回 None）。AES 和 GCM 用本包 crypto 里的实现，HKDF 用标准库 hmac。
所有函数对不是 Initial / 版本不认识 / 认证失败 / 结构坏的输入返回 None（或空表），不抛异常。
"""
import collections
import hashlib
import hmac
import logging
import struct

from . import crypto

log = logging.getLogger(__name__)

VERSIONS = {
    1: {"salt": bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), "labels": (b"quic key", b"quic iv", b"quic hp"), "initial": 0},
    0x6b3343cf: {"salt": bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"), "labels": (b"quicv2 key", b"quicv2 iv", b"quicv2 hp"), "initial": 1},
}


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def expand_label(secret, label, length):
    """TLS 1.3 的 HKDF-Expand-Label（上下文为空），标签前缀是 "tls13 "。length 不超过 32，HKDF-Expand 只要一轮。"""
    info = struct.pack(">H", length) + bytes([6 + len(label)]) + b"tls13 " + label + b"\x00"
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]


REASONS = {"not_initial": "不是客户端 Initial（短包头或别的包类型）", "version": "QUIC 版本不认得", "malformed": "结构不对或被截断", "auth": "认证失败（不是客户端 Initial，或内容被改）"}


def initial_keys(dcid, version=1):
    """客户端 Initial 的 (key, iv, hp)：RFC 9001 5.2 / A.1。版本不认识返回 None。"""
    v = VERSIONS.get(version)
    if v is None:
        return None
    secret = expand_label(hkdf_extract(v["salt"], dcid), b"client in", 32)
    return tuple(expand_label(secret, lab, n) for lab, n in zip(v["labels"], (16, 12, 16)))


def varint(b, p):
    """RFC 9000 16 的可变长整数 -> (值, 下一个位置)；不够长抛 IndexError（外层统一接住）。"""
    n = 1 << (b[p] >> 6)
    if p + n > len(b):
        raise IndexError
    return int.from_bytes(b[p:p + n], "big") & ((1 << (8 * n - 2)) - 1), p + n


def parse_frames(data):
    """解 Initial 载荷里的帧 -> {"crypto": [(offset, bytes)], "frames": [名字...], "truncated": 是否遇到不认识 / 被截断的帧}。
    Initial 里只允许 PADDING、PING、ACK、CRYPTO、CONNECTION_CLOSE；别的帧不认识，停下来标 truncated。"""
    out = {"crypto": [], "frames": [], "truncated": False}
    p = 0
    try:
        while p < len(data):
            t = data[p]
            if t == 0:
                p += 1
                if not out["frames"] or out["frames"][-1] != "padding":
                    out["frames"].append("padding")
            elif t == 1:
                out["frames"].append("ping")
                p += 1
            elif t in (2, 3):
                out["frames"].append("ack")
                _, p = varint(data, p + 1)                                  # 最大确认号
                _, p = varint(data, p)                                      # 延迟
                count, p = varint(data, p)
                _, p = varint(data, p)                                      # 第一个确认区间
                for _ in range(count):
                    _, p = varint(data, p)
                    _, p = varint(data, p)
                if t == 3:
                    for _ in range(3):
                        _, p = varint(data, p)
            elif t == 6:
                off, p = varint(data, p + 1)
                ln, p = varint(data, p)
                if p + ln > len(data):
                    raise IndexError
                out["crypto"].append((off, bytes(data[p:p + ln])))
                out["frames"].append("crypto")
                p += ln
            else:
                raise IndexError
    except IndexError:
        out["truncated"] = True
    return out


def parse_initial(datagram, why=None):
    """一个 UDP 载荷里的第一个包，若是能解开的客户端 Initial ->
    {"version", "dcid", "scid", "token", "pn"（包号，受保护头里截断的那几个字节）, "crypto": [(offset, bytes)], "frames", "truncated", "rest"（同一数据报里后面合并的包）}；否则 None。
    why 给一个列表时，失败的原因代号追加进去（not_initial / version / malformed / auth），诊断用。"""
    try:
        return _parse_initial(bytes(datagram), why)
    except (IndexError, ValueError, TypeError, struct.error):
        _no(why, "malformed")
        return None


def _no(why, reason):
    if why is not None:
        why.append(reason)


def _parse_initial(d, why=None):
    if len(d) < 7 or not d[0] & 0x80 or not d[0] & 0x40:                       # 长包头、固定位
        _no(why, "not_initial")
        return None
    version = struct.unpack(">I", d[1:5])[0]
    v = VERSIONS.get(version)
    if v is None:
        _no(why, "version")
        return None
    if (d[0] >> 4) & 3 != v["initial"]:
        _no(why, "not_initial")
        return None
    p = 5
    dl = d[p]
    dcid = d[p + 1:p + 1 + dl]
    p += 1 + dl
    sl = d[p]
    scid = d[p + 1:p + 1 + sl]
    p += 1 + sl
    if dl > 20 or sl > 20 or len(dcid) != dl or len(scid) != sl:
        _no(why, "malformed")
        return None
    tl, p = varint(d, p)
    token = d[p:p + tl]
    p += tl
    length, p = varint(d, p)
    end = p + length
    if end > len(d) or length < 4 + 16:                                        # 头保护的样本取包号起点后 4 字节处的 16 字节
        _no(why, "malformed")
        return None
    key, iv, hp = initial_keys(dcid, version)
    mask = crypto.aes_block(hp, d[p + 4:p + 20])                                # 头保护：用密文的第 5..20 字节当样本
    first = d[0] ^ (mask[0] & 0x0F)
    pnl = (first & 3) + 1
    pn_bytes = bytes(a ^ b for a, b in zip(d[p:p + pnl], mask[1:1 + pnl]))
    header = bytes([first]) + d[1:p] + pn_bytes
    nonce = bytes(a ^ b for a, b in zip(iv, (b"\x00" * 12 + pn_bytes)[-12:]))
    plain, ok = crypto.gcm_decrypt(key, nonce, header, d[p + pnl:end])
    if not ok:
        _no(why, "auth")
        return None
    fr = parse_frames(plain)
    return {"version": version, "dcid": bytes(dcid), "scid": bytes(scid), "token": bytes(token), "pn": int.from_bytes(pn_bytes, "big"), "crypto": fr["crypto"],
            "frames": fr["frames"], "truncated": fr["truncated"], "rest": d[end:]}


def parse_datagram(datagram, why=None):
    """一个 UDP 载荷里所有能解开的客户端 Initial（QUIC 允许把几个包合并进一个数据报，后面的不是 Initial 就停）。"""
    out = []
    while datagram:
        r = parse_initial(datagram, why)
        if r is None:
            break
        out.append(r)
        datagram = r["rest"]
    return out


def crypto_stream(chunks):
    """按偏移把 CRYPTO 片段拼成从 0 开始连续的字节（重复 / 重叠的只取新的部分；遇到缺口就停在缺口前）。"""
    buf, have = b"", 0
    for off, data in sorted(chunks, key=lambda c: c[0]):
        if off > have:
            break
        if off + len(data) > have:
            buf += data[have - off:]
            have = off + len(data)
    return buf


def client_hello(stream):
    """CRYPTO 流的开头若是完整的 ClientHello 握手消息（类型 1，3 字节长度），返回这条消息（含 4 字节头）；不完整 / 不是则 None。"""
    if len(stream) < 4 or stream[0] != 1:
        return None
    n = int.from_bytes(stream[1:4], "big")
    return bytes(stream[:4 + n]) if len(stream) >= 4 + n else None


def collect(datagrams, stats=None):
    """一组 UDP 载荷（客户端发的 Initial，可以多个包、乱序）-> {目的连接 ID: {"version", "scid", "packets", "stream", "client_hello"}}。
    一个 ClientHello 装不进一个包（Chrome 的后量子密钥交换会让它超过 1200 字节）时，靠偏移把几个包的 CRYPTO 拼起来。
    stats 给一个 Counter：把诊断计数累加进去（datagrams / packets / conns / incomplete / 各拒绝原因），自己不写日志，由调用方汇总后写一条；不给就自己写一条 DEBUG。"""
    conns, rejected, packets = {}, {}, 0
    for dg in datagrams:
        why = []
        got = parse_datagram(dg, why)
        if not got and why:                                           # 一个包都没解开才算这个数据报被拒，原因取第一个
            rejected[why[0]] = rejected.get(why[0], 0) + 1
        packets += len(got)
        for r in got:
            c = conns.setdefault(r["dcid"], {"version": r["version"], "scid": r["scid"], "packets": 0, "chunks": []})
            c["packets"] += 1
            c["chunks"] += r["crypto"]
    out = {}
    for dcid, c in conns.items():
        stream = crypto_stream(c["chunks"])
        out[dcid] = {"version": c["version"], "scid": c["scid"], "packets": c["packets"], "stream": stream, "client_hello": client_hello(stream)}
    if datagrams:
        mine = stats if stats is not None else collections.Counter()
        mine["datagrams"] += len(datagrams)
        mine["packets"] += packets
        mine["conns"] += len(out)
        mine["incomplete"] += sum(1 for v in out.values() if v["client_hello"] is None)
        for k, v in rejected.items():
            mine["rejected_" + k] += v
        if stats is None:
            log.debug("%s", describe(mine))
    return out


def describe(stats):
    """collect 累加出的诊断计数 -> 一句中文。"""
    rej = "、".join("%s %d" % (REASONS[k], stats["rejected_" + k]) for k in sorted(REASONS) if stats["rejected_" + k])
    return "QUIC：%d 个数据报里解开 %d 个 Initial 包（%d 个连接），ClientHello 读全 %d 个、CRYPTO 流不完整 %d 个；没解开的数据报：%s" % (
        stats["datagrams"], stats["packets"], stats["conns"], stats["conns"] - stats["incomplete"], stats["incomplete"], rej or "无")
