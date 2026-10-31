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

from . import decrypt as dec
from . import eapol
from . import frames as fr
from . import handshake as hs
from . import ie
from . import kdf

# n：EAPOL 帧号；ap：发送 GTK 的 AP（组播帧的 A2 / BSSID）；igtk：(序号, IPN, 密钥) 或 None；source：M3 / G1
GroupKey = namedtuple("GroupKey", "n ap key_id tx gtk igtk source")

OUI_WFA = b"\x00\x0f\xac"
KDE_GTK, KDE_IGTK = 1, 9


def unwrap_key_data(kek, e):
    """解出 EAPOL-Key 的 Key Data 明文；完整性校验不过（密钥不对）返回 None。"""
    data = e["data"]
    if e["descriptor"] == 254 or e["key_info"]["version"] == 1:
        return kdf.rc4_key_unwrap(kek, e["iv"], data)
    if len(data) % 8 or len(data) < 24:
        return None
    pt, ok = kdf.aes_key_unwrap(kek, data)
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


MLO_GTK, MLO_IGTK, MLO_BIGTK, MLO_LINK = 0x10, 0x11, 0x12, 0x13


def mlo_keys(plain, n, source, links=None):
    """多链路（802.11be）的 M3 / G1 Key Data：每条链路各有自己的组密钥。
    链路 KDE（0x13）：链路 ID 在第 1 字节低 4 位，后面 6 字节是这条链路上 AP 的 MAC（也是组播帧的发送地址）。
    MLO GTK KDE（0x10）：密钥序号 / Tx / 链路 ID（第 1 字节：bit0-1 序号、bit2 Tx、bit4-7 链路）‖ RSC(6) ‖ GTK。
    MLO IGTK（0x11）/ BIGTK（0x12，保护信标）KDE：密钥序号(2，小端) ‖ IPN(6) ‖ 链路 ID（高 4 位）‖ 密钥。
    links 是调用方保存的 {链路 ID: MAC}，本函数把这条消息里的链路 KDE 并进去再用；链路 ID 对不上的丢掉。IGTK / BIGTK 放在单独的 GroupKey 里（gtk 为空，key_id = -1，只有 igtk 有值），这样组播数据帧的解密不会误用它们。"""
    kdes = parse_kdes(plain)
    links = {} if links is None else links          # 链路 ID -> AP 的链路 MAC；只有 M3 带链路 KDE，之后的组密钥握手（G1）要用 M3 记下的
    links.update({body[0] & 15: ":".join("%02x" % x for x in body[1:7]) for typ, body in kdes if typ == MLO_LINK and len(body) >= 7})
    out = []
    for typ, body in kdes:
        if typ == MLO_GTK and len(body) >= 8 + 16 - 1:
            ap = links.get(body[0] >> 4)
            if ap is not None:
                out.append(GroupKey(n, ap, body[0] & 3, bool(body[0] & 4), bytes(body[7:]), None, source))
        elif typ in (MLO_IGTK, MLO_BIGTK) and len(body) >= 9 + 16:
            ap = links.get(body[8] >> 4)
            if ap is not None:
                out.append(GroupKey(n, ap, -1, False, b"", (body[0] | body[1] << 8, bytes(body[2:8]), bytes(body[9:])), source))
    return out


def track_group(frames, done):
    """frames：iter_frames 的结果；done：handshake80211.track 推出的握手。返回 [GroupKey]。
    M3 按 ANonce 找到它属于哪个握手，G1 在这对地址的握手里从新到旧试；两者都先用 KCK 验 MIC，再用 KEK 解 Key Data。"""
    out = []
    mld = hs.mld_addresses(frames)
    link_maps = {}                       # AP（MLD 地址）-> {链路 ID: 链路 MAC}
    for f in frames:
        if f.h["type"] == 0 and f.h["subtype"] == 3 and not f.h["protected"]:        # 重关联响应：FT 漫游后新 AP 的组密钥在 FTE 的子元素里
            gk = _ft_group_key(f, done)
            if gk is not None:
                out.append(gk)
            continue
        raw = fr.eapol_payload(f)
        if raw is None and f.h["protected"]:
            raw = hs._decrypted_eapol(done, f, mld)
        e = eapol.parse(raw) if raw is not None else None
        if e is None or "key_info" not in e:
            continue
        msg = e.get("message")
        if msg not in (3, "G1") or (msg == 3 and e["descriptor"] == 254):     # WPA1 的 M3 里没有 GTK，GTK 在后面的 G1 里
            continue
        pair = {mld.get(f.h["sa"], f.h["sa"]), mld.get(f.h["da"], f.h["da"])}
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
            out.extend(mlo_keys(plain, f.n, "M3" if msg == 3 else "G1", link_maps.setdefault(x.ap, {})))
            break
    return out


def _rsn_field(frames, field, names, done=(), guess=None):
    """{BSSID: 套件名}：信标 / 探测响应的 RSN（WPA1 是厂商）元素里的某个套件字段，没有信标的抓包退而用（重）关联请求里的。"""
    out, fallback = {}, {}
    for f in frames:
        h = f.h
        if h["type"] != 0 or h["protected"] or h["subtype"] not in (0, 2, 5, 8) or not h["bssid"]:
            continue
        els, _ = ie.walk(f.body[ie.FIXED_LEN[h["subtype"]]:])
        d = ie.decode_all(els)
        r = d.get("rsn") or d.get("wpa")
        if r and r.get(field) and r[field][1] in names:
            # 抓包里没有信标时，关联请求里 STA 声明的套件就是它要加入的 AP 的套件
            (out if h["subtype"] in (5, 8) else fallback).setdefault(h["bssid"], names[r[field][1]])
    if guess is not None:
        for x in done:
            fallback.setdefault(x.ap, guess(x))
    return dict(fallback, **out)


def _ft_group_key(f, done):
    """重关联响应的 FTE：子元素 2 = GTK：密钥序号(2，小端，低 2 位) ‖ 密钥长度(1) ‖ RSC(8) ‖ AES 包装的 GTK（长度 + 8）；
    子元素 4 = IGTK：密钥序号(2) ‖ IPN(6) ‖ 密钥长度(1) ‖ 包装的 IGTK。用这对地址的握手（包括漫游得到的）的 KEK 解，完整性校验通过才算。"""
    h = f.h
    d = ie.decode_all(ie.walk(f.body[ie.FIXED_LEN[3]:])[0])
    fte = d.get("fte")
    if not fte:
        return None
    subs = {}
    for sid, body in fte["subelements"]:
        subs.setdefault(sid, body)
    g = subs.get(2)
    if g is None or len(g) < 11 + 24 or (len(g) - 11) % 8:
        return None
    ap, sta = h["addr2"], h["addr1"]
    for x in sorted((x for x in done if x.ap == ap and x.sta == sta and x.frames["m2"] < f.n), key=lambda x: -x.frames["m2"]):
        gtk, ok = kdf.aes_key_unwrap(x.kek, g[11:])
        if not ok or len(gtk) != g[2]:
            continue
        igtk = None
        ig = subs.get(4)
        if ig is not None and len(ig) >= 9 + 24 and (len(ig) - 9) % 8 == 0:
            key, ok2 = kdf.aes_key_unwrap(x.kek, ig[9:])
            if ok2 and len(key) == ig[8]:
                igtk = (ig[0] | ig[1] << 8, bytes(ig[2:8]), key)
        return GroupKey(f.n, ap, g[0] & 3, True, gtk, igtk, "FT")
    return None


def group_ciphers(frames, done=()):
    """{BSSID: 组密码套件名}：RSN 元素的组套件。WEP 等不处理的不收。
    done（可选）：信标和关联请求都没有时，用 AP 握手里的成对套件当猜测（最常见；猜错了 MIC 过不去，不会解出假明文）。"""
    return _rsn_field(frames, "group", {t: v[0] for t, v in hs.CIPHERS.items()}, done, lambda x: x.cipher)


def group_mgmt_ciphers(frames):
    """{BSSID: 组管理套件名（BIP-…）}：RSN 元素的组管理套件（启用 PMF 才有）。"""
    return _rsn_field(frames, "group_mgmt", {t: v[0] for t, v in dec.BIP_SUITES.items()})


BIGTK_IDS = (6, 7)


def _infer_bip(mic_len, key_len):
    """不知道组管理套件时，由 MIC 长度和密钥长度推出可能的 BIP 套件名。"""
    return [name for name, klen, mlen in dec.BIP_SUITES.values() if klen == key_len and mlen == mic_len]


def verify_bip(igtks, mgmt_ciphers, frame):
    """校验一个广播 / 组播管理帧的 MME，用 AP 的 IGTK / BIGTK（按 MME 里的密钥序号）。先试装上时间在帧之前的（从新到旧），
    再试装上时间在帧之后的（从旧到新）：信标常常比关联早抓到，它用的就是之后才送给站点的那把密钥，MIC 吻合就是实实在在的证明。
    套件取自 RSN 的组管理套件；不知道时按 MME 的 MIC 长度和密钥长度推（8 字节 MIC 只能是 BIP-CMAC-128；16 字节的 16 位密钥是 GMAC-128，32 位密钥可能是 GMAC-256 或 CMAC-256，两个都试）。
    返回 "ok" / "bad"（有密钥但不吻合）/ "no_igtk"（没有可用的密钥）/ "unsupported"（MME 用的是 BIGTK：信标保护），帧里没有 MME 返回 None。"""
    h = frame.h
    if h["type"] != 0 or h["protected"] or dec.find_mme(frame.body) is None:
        return None
    cipher = mgmt_ciphers.get(h["addr2"])
    key_id, _ipn, mic, _off = dec.find_mme(frame.body)
    if key_id in BIGTK_IDS:              # 密钥序号 6 / 7 = BIGTK（保护信标）：信标的 MIC 范围规则还没确定，不判
        return "unsupported"
    same = [k for k in igtks if k.ap == h["addr2"] and k.igtk is not None and k.igtk[0] == key_id]
    cands = sorted((k for k in same if k.n < frame.n), key=lambda k: -k.n) + sorted((k for k in same if k.n >= frame.n), key=lambda k: k.n)
    tried = False
    for k in cands:
        for name in ([cipher] if cipher else _infer_bip(len(mic), len(k.igtk[2]))):
            tried = True
            if dec.verify_bip(k.igtk[2], name, frame)[0]:
                return "ok"
    return "bad" if tried else "no_igtk"


def decrypt_group(keys, ciphers, frame):
    """用 AP 发的组密钥解一个组播 / 广播数据帧（FromDS，A1 是组地址，A2 = BSSID）。
    按帧头里的密钥序号找 GTK，装上时间在帧之前的从新到旧试，MIC 决定。返回 (GroupKey, 明文) 或 None。"""
    h = frame.h
    if h["type"] != 2 or not h["protected"] or not (int(h["addr1"].split(":")[0], 16) & 1) or not h["from_ds"] or h["to_ds"]:
        return None
    cipher = ciphers.get(h["addr2"])
    if cipher not in dec.SUPPORTED or len(frame.body) < 8:
        return None
    key_id = dec.pn_of(frame.body)[1]
    for gk in sorted((k for k in keys if k.ap == h["addr2"] and k.key_id == key_id and k.n < frame.n), key=lambda k: -k.n):
        try:
            pt, ok = dec.decrypt_any(cipher, gk.gtk, frame)
        except ValueError:
            continue
        if ok:
            return gk, pt
    return None
