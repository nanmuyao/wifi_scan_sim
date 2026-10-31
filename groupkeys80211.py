# -*- coding: utf-8 -*-
"""
组密钥（GTK / IGTK）：从 M3 和组密钥握手（G1）的 Key Data 里解出来，再用它解组播 / 广播数据帧。纯标准库。

Key Data 的保护：描述符版本 1（RC4）= RC4，密钥 Key IV ‖ KEK，丢掉前 256 字节密钥流；版本 2 / 3 / 0 = AES 密钥包装（RFC 3394，KEK）。
M3 的 Key Data 加密位（Key Info bit 12）置位；WPA1 的 G1 没有这一位，但 Key Data 总是 RC4 加密。
解开后（RSN）是一串 KDE：0xDD、长度、OUI(3)、数据类型、数据；组密钥 KDE 的类型 1：[密钥序号 | Tx<<2, 保留, GTK…]，
IGTK KDE 的类型 9：[密钥序号(2，小端), IPN(6), IGTK…]；末尾可能有 0xDD 0x00… 的填充，也可能夹着 RSN 元素（0x30），跳过。
WPA1（描述符 254）没有 KDE：Key Data 就是 GTK 本身，序号在 Key Info 的 bit 4-5。
"""
from collections import namedtuple

import decrypt80211 as dec
import eapol
import frames80211 as fr
import handshake80211 as hs
import ie
import kdf80211

# n：EAPOL 帧号；ap：发送 GTK 的 AP（组播帧的 A2 / BSSID）；igtk：(序号, IPN, 密钥) 或 None；source：M3 / G1
GroupKey = namedtuple("GroupKey", "n ap key_id tx gtk igtk source")

OUI_WFA = b"\x00\x0f\xac"
KDE_GTK, KDE_IGTK = 1, 9


def unwrap_key_data(kek, e):
    """解出 EAPOL-Key 的 Key Data 明文；完整性校验不过（密钥不对）返回 None。"""
    data = e["data"]
    if e["descriptor"] == 254 or e["key_info"]["version"] == 1:
        return kdf80211.rc4_key_unwrap(kek, e["iv"], data)
    if len(data) % 8 or len(data) < 24:
        return None
    pt, ok = kdf80211.aes_key_unwrap(kek, data)
    return pt if ok else None


def parse_kdes(data):
    """[(数据类型, 数据)]：只收 WFA OUI 的 KDE；RSN 元素和别的 OUI 跳过；0xDD 0x00 之后是填充。"""
    out, p = [], 0
    while p + 2 <= len(data):
        t, n = data[p], data[p + 1]
        if t == 0xDD and n == 0:
            break
        body = data[p + 2:p + 2 + n]
        if len(body) < n:
            break
        if t == 0xDD and n >= 4 and body[:3] == OUI_WFA:
            out.append((body[3], body[4:]))
        p += 2 + n
    return out


def keys_from_data(plain, e, ap, n, source):
    """从解开的 Key Data 取出组密钥，没有返回 None。"""
    if e["descriptor"] == 254:
        ki = e["key_info"]
        return GroupKey(n, ap, ki["index"], ki["install"], plain[:e["key_length"] or len(plain)], None, source)
    gtk, igtk = None, None
    for typ, body in parse_kdes(plain):
        if typ == KDE_GTK and len(body) > 2 and gtk is None:
            gtk = (body[0] & 3, bool(body[0] & 4), body[2:])
        elif typ == KDE_IGTK and len(body) > 8 and igtk is None:
            igtk = (body[0] | body[1] << 8, body[2:8], body[8:])
    if gtk is None:
        return None
    return GroupKey(n, ap, gtk[0], gtk[1], gtk[2], igtk, source)


def track_group(frames, done):
    """frames：iter_frames 的结果；done：handshake80211.track 推出的握手。返回 [GroupKey]。
    M3 按 ANonce 找到它属于哪个握手，G1 在这对地址的握手里从新到旧试；两者都先用 KCK 验 MIC，再用 KEK 解 Key Data。"""
    out = []
    for f in frames:
        raw = fr.eapol_payload(f)
        if raw is None and f.h["protected"]:
            raw = hs._decrypted_eapol(done, f)
        e = eapol.parse(raw) if raw is not None else None
        if e is None or "key_info" not in e:
            continue
        msg = e.get("message")
        if msg not in (3, "G1") or (msg == 3 and e["descriptor"] == 254):     # WPA1 的 M3 里没有 GTK，GTK 在后面的 G1 里
            continue
        pair = {f.h["sa"], f.h["da"]}
        cands = sorted((x for x in done if {x.ap, x.sta} == pair and x.frames["m2"] < f.n), key=lambda x: -x.frames["m2"])
        if msg == 3:
            cands = [x for x in cands if x.anonce == e["nonce"]]
        for x in cands:
            e2 = eapol.parse(raw, mic_len=x.mic_len)
            zeroed = eapol.zero_mic(raw[:4 + e2["length"]], x.mic_len)
            if hs.compute_mic(x.mic_alg, x.kck, zeroed, x.mic_len) != e2["mic"]:
                continue
            plain = unwrap_key_data(x.kek, e2)
            if plain is None:
                continue
            gk = keys_from_data(plain, e2, f.h["sa"], f.n, "M3" if msg == 3 else "G1")
            if gk is not None:
                out.append(gk)
            break
    return out


def group_ciphers(frames, done=()):
    """{BSSID: 组密码套件名}：信标 / 探测响应里 RSN（WPA1 是厂商）元素的组套件，没有信标的抓包退而用（重）关联请求里的。WEP 等不处理的不收。
    done（可选）：都没有时用 AP 握手里的成对套件当猜测。"""
    out, fallback = {}, {}
    for f in frames:
        h = f.h
        if h["type"] != 0 or h["protected"] or h["subtype"] not in (0, 2, 5, 8) or not h["bssid"]:
            continue
        els, _ = ie.walk(f.body[ie.FIXED_LEN[h["subtype"]]:])
        d = ie.decode_all(els)
        r = d.get("rsn") or d.get("wpa")
        if r and r.get("group") and r["group"][1] in hs.CIPHERS:
            # 抓包里没有信标时，关联请求里 STA 声明的组套件就是它要加入的 AP 的组套件
            (out if h["subtype"] in (5, 8) else fallback).setdefault(h["bssid"], hs.CIPHERS[r["group"][1]][0])
    for x in done:           # 连关联请求也没抓到：猜组套件 = 成对套件（最常见），猜错了 MIC 过不去，不会解出假明文
        fallback.setdefault(x.ap, x.cipher)
    return dict(fallback, **out)


def decrypt_group(keys, ciphers, frame):
    """用 AP 发的组密钥解一个组播 / 广播数据帧（FromDS，A1 是组地址，A2 = BSSID）。
    按帧头里的密钥序号找 GTK，装上时间在帧之前的从新到旧试，MIC 决定。返回 (GroupKey, 明文) 或 None。目前只处理 CCMP / GCMP。"""
    h = frame.h
    if h["type"] != 2 or not h["protected"] or not (int(h["addr1"].split(":")[0], 16) & 1) or not h["from_ds"] or h["to_ds"]:
        return None
    cipher = ciphers.get(h["addr2"])
    if cipher not in dec.MIC_LEN or len(frame.body) < 8:
        return None
    key_id = dec.pn_of(frame.body)[1]
    for gk in sorted((k for k in keys if k.ap == h["addr2"] and k.key_id == key_id and k.n < frame.n), key=lambda k: -k.n):
        try:
            pt, ok, _pn = dec.decrypt_aead(gk.gtk, cipher, frame)
        except ValueError:
            continue
        if ok:
            return gk, pt
    return None
