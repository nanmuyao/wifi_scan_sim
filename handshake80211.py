# -*- coding: utf-8 -*-
"""
从抓包里跟踪四次握手并推导成对密钥（PTK = KCK ‖ KEK ‖ TK）。纯标准库 + pycryptodome 的 AES 单块。

流程：M1（AP -> STA，带 ANonce）-> M2（STA -> AP，带 SNonce、MIC，Key Data 里是 STA 选定的 RSN / WPA 元素）。
M2 里的元素告诉我们认证方式（AKM）和成对密码套件，于是知道用哪种推导、KCK / KEK / TK 多长、MIC 用哪种算法。
对每个候选 PMK（口令 + SSID 经 PBKDF2，或直接给的 PMK / MSK）推导 PTK，用 KCK 重算 M2 的 MIC：**MIC 吻合就证明了整条链**
（PMK、地址、两个 nonce、哈希选择、KCK 长度）全对——这是 AP 用真实的 KCK 算出的值，不依赖任何第三方实现。

不支持：快速切换（FT，AKM 3 / 4 / 9 / 13 / 25）的 PTK 推导走 PMK-R0 / PMK-R1，不一样（阶段 E）。
"""
import hashlib
import hmac
from collections import namedtuple

import crypto80211  # noqa: F401  (保证 kdf80211 的依赖可导入)
import decrypt80211 as dec
import eapol
import frames80211 as fr
import ie
import kdf80211

PAIRWISE_LABEL = b"Pairwise key expansion"
OUI_IEEE, OUI_MS = 0x000FAC, 0x0050F2

# 密码套件类型 -> (名字, TK 字节数)。TKIP 的 TK 是 32 字节：128 位加密密钥 + 两个 64 位 Michael 密钥
CIPHERS = {2: ("TKIP", 32), 4: ("CCMP-128", 16), 8: ("GCMP-128", 16), 9: ("GCMP-256", 32), 10: ("CCMP-256", 32)}

# 认证方式（AKM）-> 推导用的哈希。"by_mic" 表示由 MIC 长度决定（16 -> SHA-256，24 -> SHA-384，32 -> SHA-512，对应 ECC 组 19 / 20 / 21）
AKMS = {1: "sha1", 2: "sha1", 5: "sha256", 6: "sha256", 8: "sha256", 11: "sha256", 12: "sha384", 18: "by_mic", 24: "by_mic"}
FT_AKMS = (3, 4, 9, 13, 19, 25)
KDF_BY_MIC_LEN = {16: "sha256", 24: "sha384", 32: "sha512"}
# 哈希 -> (KCK 字节数, KEK 字节数)
KEY_LENGTHS = {"sha1": (16, 16), "sha256": (16, 16), "sha384": (24, 32), "sha512": (32, 32)}

Handshake = namedtuple("Handshake", "ap sta anonce snonce pmk akm cipher kdf descriptor version kck kek tk mic_alg mic_len frames")


def mic_algorithm(version, mic_len, akm=None):
    """EAPOL-Key MIC 的算法：描述符版本 1 = HMAC-MD5，2 = HMAC-SHA1（取前 16 字节），3 = AES-128-CMAC。
    版本 0 表示由认证方式（AKM）决定：SAE（8）= AES-128-CMAC；其余（OWE 18、Suite-B 11 / 12、SAE-EXT-KEY 24）= HMAC，
    哈希随 MIC 长度走：16 字节 = HMAC-SHA-256，24 = HMAC-SHA-384，32 = HMAC-SHA-512（都取前 MIC 长度字节）。"""
    if version == 1:
        return "hmac-md5"
    if version == 2:
        return "hmac-sha1"
    if version == 3:
        return "cmac"
    if akm == 8:
        return "cmac"
    return {16: "hmac-sha256", 24: "hmac-sha384", 32: "hmac-sha512"}.get(mic_len)


def compute_mic(alg, kck, eapol_zeroed, mic_len):
    if alg == "hmac-md5":
        return hmac.new(kck, eapol_zeroed, hashlib.md5).digest()[:mic_len]
    if alg == "hmac-sha1":
        return hmac.new(kck, eapol_zeroed, hashlib.sha1).digest()[:mic_len]
    if alg == "cmac":
        return kdf80211.aes_cmac(kck, eapol_zeroed)[:mic_len]
    if alg == "hmac-sha256":
        return hmac.new(kck, eapol_zeroed, hashlib.sha256).digest()[:mic_len]
    if alg == "hmac-sha384":
        return hmac.new(kck, eapol_zeroed, hashlib.sha384).digest()[:mic_len]
    if alg == "hmac-sha512":
        return hmac.new(kck, eapol_zeroed, hashlib.sha512).digest()[:mic_len]
    raise ValueError("不认识的 MIC 算法 %r" % alg)


def derive_ptk(pmk, aa, spa, anonce, snonce, kdf_hash, kck_len, kek_len, tk_len):
    """PTK = KCK ‖ KEK ‖ TK。上下文 = min(AA, SPA) ‖ max(AA, SPA) ‖ min(ANonce, SNonce) ‖ max(ANonce, SNonce)。"""
    data = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    n = kck_len + kek_len + tk_len
    if kdf_hash == "sha1":
        ptk = kdf80211.prf_sha1(pmk, PAIRWISE_LABEL, data, n)
    else:
        ptk = kdf80211.kdf(kdf_hash, pmk, PAIRWISE_LABEL, data, n * 8)
    return ptk[:kck_len], ptk[kck_len:kck_len + kek_len], ptk[kck_len + kek_len:]


def pmk_from_passphrase(passphrase, ssid):
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"), ssid, 4096, 32)


def candidate_pmks(keys, ssid, pmk_len):
    """(来源描述, PMK) 列表。keys：[("wpa-pwd" / "wpa-psk" / "msk" / "wep", 值)]。
    wpa-pwd 的值可以是「口令」或「口令:SSID」；没有 SSID 就用抓包里看到的。"""
    out = []
    for typ, val in keys:
        if typ == "wpa-pwd":
            pw, _, own_ssid = val.partition(":")
            use = own_ssid.encode() if own_ssid else ssid
            if use is not None and pmk_len == 32:
                out.append(("wpa-pwd:%s" % pw, pmk_from_passphrase(pw, use)))
        elif typ == "wpa-psk":
            try:
                raw = bytes.fromhex(val)
            except ValueError:
                continue
            if len(raw) == pmk_len:
                out.append(("wpa-psk:%s…" % val[:8], raw))
        elif typ == "msk":
            try:
                raw = bytes.fromhex(val)
            except ValueError:
                continue
            if len(raw) >= pmk_len:
                out.append(("msk:%s…" % val[:8], raw[:pmk_len]))
    return out


def suite_info(m2, d):
    """从 M2 的 Key Data 里的 RSN 元素（WPA1 是厂商元素）取 (AKM 类型, 成对套件类型)；没有返回 (None, None)。"""
    r = d.get("rsn") or d.get("wpa")
    if not r or not r.get("akm") or not r.get("pairwise"):
        return None, None
    return r["akm"][0][1], r["pairwise"][0][1]


def ssids_by_bssid(frames):
    """{BSSID: SSID 字节串}：信标、探测响应、关联请求里的 SSID 元素。"""
    out = {}
    for f in frames:
        h = f.h
        if h["type"] != 0 or h["protected"] or h["subtype"] not in (0, 2, 5, 8):
            continue
        off = ie.FIXED_LEN.get(h["subtype"])
        els, _ = ie.walk(f.body[off:])
        for e in els:
            if e.id == 0 and e.ext is None and h["bssid"]:
                out.setdefault(h["bssid"], bytes(e.data))
                break
    return out


def mld_addresses(frames):
    """{链路地址: MLD 地址}：（重）关联请求 / 响应里的 Multi-Link 元素给出发送方的 MLD 地址，每站点配置里的 MAC 是它其它链路的地址。
    多链路设备推导 PTK 时用的是双方的 MLD 地址，不是各条链路的地址。"""
    out = {}
    for f in frames:
        h = f.h
        if h["type"] != 0 or h["protected"] or h["subtype"] not in (0, 1, 2, 3):
            continue
        els, _ = ie.walk(f.body[ie.FIXED_LEN[h["subtype"]]:])
        for e in els:
            if e.id == ie.ID_EXTENSION and e.ext == ie.EXT_MULTI_LINK:
                ml = ie.decode_multi_link(e.data, ie.ML_PROFILE_FIXED.get(h["subtype"], 0))
                if ml and ml["mld_mac"]:
                    out[h["sa"]] = ml["mld_mac"]
                    for sta in ml["stas"]:
                        if sta["mac"]:
                            out[sta["mac"]] = ml["mld_mac"]
    return out


def _mac(s):
    return bytes.fromhex(s.replace(":", ""))


def _decrypted_eapol(done, f):
    """重新握手的 EAPOL 报文在数据帧里被当前的 PTK 加密：用已推出的握手解开，是 EAPOL 就返回报文。"""
    got = dec.decrypt_frame(done, f)
    if got is None:
        return None
    pt = got[1]
    if pt[:6] != fr.LLC_SNAP or pt[6:8] != fr.ETHERTYPE_EAPOL:
        return None
    return pt[8:]


def track(frames, keys):
    """frames：frames80211.iter_frames 的结果（列表）。返回 (成功的握手 [Handshake], 失败 / 跳过的 [(帧号, 原因)])。"""
    ssids = ssids_by_bssid(frames)
    mld = mld_addresses(frames)
    pending = {}                     # (ap, sta) -> 最近的 M1 (anonce, replay_counter, 帧号)
    done, skipped = [], []
    for f in frames:
        raw = fr.eapol_payload(f)
        if raw is None and f.h["protected"]:
            raw = _decrypted_eapol(done, f)
        e = eapol.parse(raw) if raw is not None else None
        if e is None or "key_info" not in e or not e["key_info"]["pairwise"]:
            continue
        msg = e.get("message")
        h = f.h
        if msg == 1:
            pending[(h["sa"], h["da"])] = (e["nonce"], e["replay_counter"], f.n)
        elif msg == 2:
            ap, sta = h["da"], h["sa"]
            m1 = pending.get((ap, sta))
            if m1 is None or m1[1] != e["replay_counter"]:
                skipped.append((f.n, "找不到与 Replay Counter 对应的 M1"))
                continue
            els, _ = ie.walk(e["data"])
            akm, cipher = suite_info(e, ie.decode_all(els))
            if akm is None:
                skipped.append((f.n, "M2 的 Key Data 里没有 RSN / WPA 元素"))
                continue
            if akm in FT_AKMS:
                skipped.append((f.n, "快速切换（AKM %d）的 PTK 推导不同，阶段 E" % akm))
                continue
            if akm not in AKMS or cipher not in CIPHERS:
                skipped.append((f.n, "不支持的 AKM %s / 密码套件 %s" % (akm, cipher)))
                continue
            hs = _try(f, raw, e, m1, mld.get(ap, ap), mld.get(sta, sta), akm, cipher, ssids.get(h["bssid"]), keys)
            if hs is None:
                skipped.append((f.n, "没有候选 PMK 让 M2 的 MIC 吻合"))
            else:
                done.append(hs)
    return done, skipped


def _try(f, raw, e, m1, ap, sta, akm, cipher, ssid, keys):
    anonce, snonce = m1[0], e["nonce"]
    mic_len = e["mic_len"]          # 由 M2 帧自己的长度关系推出（M2 的 Key Data 里有 RSN 元素，长度必然自洽；否则拿不到 AKM，早就跳过了）
    kdf_hash = KDF_BY_MIC_LEN[mic_len] if AKMS[akm] == "by_mic" else AKMS[akm]
    kck_len, kek_len = KEY_LENGTHS[kdf_hash]
    tk_len = CIPHERS[cipher][1]
    pmk_len = {"sha1": 32, "sha256": 32, "sha384": 48, "sha512": 64}[kdf_hash]
    descriptor, version = e["descriptor"], e["key_info"]["version"]
    e2 = eapol.parse(raw, mic_len=mic_len)
    alg = mic_algorithm(version, mic_len, akm)
    zeroed = eapol.zero_mic(raw[:4 + e2["length"]], mic_len)
    for source, pmk in candidate_pmks(keys, ssid, pmk_len):
        kck, kek, tk = derive_ptk(pmk, _mac(ap), _mac(sta), anonce, snonce, kdf_hash, kck_len, kek_len, tk_len)
        if hmac.compare_digest(compute_mic(alg, kck, zeroed, mic_len), e2["mic"]):
            return Handshake(ap, sta, anonce, snonce, (source, pmk), akm, CIPHERS[cipher][0], kdf_hash, descriptor, version,
                             kck, kek, tk, alg, mic_len, {"m1": m1[2], "m2": f.n})
    return None
