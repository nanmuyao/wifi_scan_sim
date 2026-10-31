# -*- coding: utf-8 -*-
"""
SAE（WPA3-Personal 的同时认证）认证帧的解析，以及 SAE / OWE 用到的椭圆曲线上的公开值检查。纯标准库。

SAE 在认证帧（算法 3）里交换两条消息：
  commit（序号 1）：状态码(2) ‖ 椭圆曲线组(2) ‖ [反阻塞令牌] ‖ 标量(曲线字节数) ‖ 元素 x ‖ 元素 y ‖ [后面的元素：口令标识、拒绝的组…]
  confirm（序号 2）：状态码(2) ‖ send-confirm(2) ‖ confirm（哈希长度：SHA-256 32、SHA-384 48、SHA-512 64 字节）
  状态码：0 成功；76 要求反阻塞令牌；77 不支持这个组；126 用 hash-to-element（H2E）。
从口令推 PMK 需要双方的私有随机数，抓包里没有——所以这里只做「抓包里看得见的东西」：帧的结构，以及用公开值能检查的事：
  标量在 [1, n-1]，元素 (x, y) 在曲线上；OWE 的 DH 公钥 x 能解出曲线上的点。
组 19 / 20 / 21 = NIST P-256 / P-384 / P-521，曲线 y^2 = x^3 - 3x + b (mod p)。
"""
import struct

SAE_ALGORITHM = 3
STATUS_SUCCESS, STATUS_ANTI_CLOGGING, STATUS_GROUP_NOT_SUPPORTED, STATUS_H2E = 0, 76, 77, 126

# 组 -> (名字, p, b, 阶 n, 坐标字节数, 哈希)
_P256 = (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
         0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
         0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
_P384 = (0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
         0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
         0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973)
_P521 = (0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
         0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
         0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409)
GROUPS = {19: ("P-256", *_P256[:2], _P256[2], 32, "sha256"),
          20: ("P-384", *_P384[:2], _P384[2], 48, "sha384"),
          21: ("P-521", *_P521[:2], _P521[2], 66, "sha512")}
HASH_LEN = {"sha256": 32, "sha384": 48, "sha512": 64}


def on_curve(group, x, y):
    """(x, y) 是不是组 group 的曲线上的点（0 <= x, y < p 且 y^2 = x^3 - 3x + b）。不认识的组返回 None。"""
    g = GROUPS.get(group)
    if g is None:
        return None
    _name, p, b, _n, _size, _h = g
    return 0 <= x < p and 0 <= y < p and (y * y - (x * x * x - 3 * x + b)) % p == 0


def x_on_curve(group, x):
    """x 坐标能不能对应曲线上的点（x^3 - 3x + b 是模 p 的平方数，欧拉判别）。OWE 的 DH 公钥只带 x。不认识的组返回 None。"""
    g = GROUPS.get(group)
    if g is None:
        return None
    _name, p, b, _n, _size, _h = g
    if not 0 <= x < p:
        return False
    rhs = (x * x * x - 3 * x + b) % p
    return rhs == 0 or pow(rhs, (p - 1) // 2, p) == 1


def scalar_valid(group, scalar):
    g = GROUPS.get(group)
    return None if g is None else 1 <= scalar < g[3]


def parse_auth(body, group=None):
    """认证帧（帧体，从算法字段起）-> SAE 内容的字典；不是 SAE 或结构不对返回 None。
    commit：{"type": "commit", "status", "group", "scalar"(bytes), "element"(bytes，x‖y), "extra"(bytes), "token"(bytes 或 None)}
            状态码 76（要求令牌）时只有 group 和 token；状态码 77 或不认识的组时没有 scalar / element，后面的字节放 extra。
    confirm：{"type": "confirm", "status", "send_confirm", "confirm"}；group 给了就按组的哈希长度切（后面的放 extra），没给就整段当 confirm。
    其余字段在解析时算好：on_curve（commit，元素在曲线上）、scalar_ok。"""
    if len(body) < 6:
        return None
    alg, seq, status = struct.unpack("<HHH", body[:6])
    if alg != SAE_ALGORITHM or seq not in (1, 2):
        return None
    rest = body[6:]
    if seq == 1:
        if len(rest) < 2:
            return {"type": "commit", "status": status, "group": None, "scalar": None, "element": None, "extra": rest, "token": None, "on_curve": None, "scalar_ok": None}
        grp = struct.unpack("<H", rest[:2])[0]
        rest = rest[2:]
        out = {"type": "commit", "status": status, "group": grp, "scalar": None, "element": None, "extra": b"", "token": None, "on_curve": None, "scalar_ok": None}
        if status == STATUS_ANTI_CLOGGING:
            out["token"] = rest
            return out
        g = GROUPS.get(grp)
        if status not in (STATUS_SUCCESS, STATUS_H2E) or g is None or len(rest) < 3 * g[4]:
            out["extra"] = rest
            return out
        size = g[4]
        out["scalar"], out["element"], out["extra"] = rest[:size], rest[size:3 * size], rest[3 * size:]
        s = int.from_bytes(out["scalar"], "big")
        out["scalar_ok"] = scalar_valid(grp, s)
        out["on_curve"] = on_curve(grp, int.from_bytes(out["element"][:size], "big"), int.from_bytes(out["element"][size:], "big"))
        return out
    if len(rest) < 2:
        return None
    send = struct.unpack("<H", rest[:2])[0]
    rest = rest[2:]
    n = HASH_LEN[GROUPS[group][5]] if group in GROUPS else len(rest)
    if len(rest) < n:
        return None
    return {"type": "confirm", "status": status, "send_confirm": send, "confirm": rest[:n], "extra": rest[n:]}
