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
import ft80211
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
# 快速切换的认证方式 -> 哈希（"by_mic" 同上）；XXKey 的字节数（None = 同哈希输出长度）
FT_HASH = {3: "sha256", 4: "sha256", 9: "sha256", 13: "sha384", 19: "sha384", 25: "by_mic"}
FT_XXKEY_LEN = {3: 32, 4: 32, 9: 32, 13: 48, 19: 32, 25: None}
# FT-802.1X（3、13）的 XXKey 是 MSK 的第二个 256 比特（前 256 比特是普通的 PMK）：由 wpa2-ft-eap 的 PMKR1Name 吻合确认（3）；13 样例里没有，按同一条规则
FT_MSK_OFFSET = {3: 32, 13: 32}
KDF_BY_MIC_LEN = {16: "sha256", 24: "sha384", 32: "sha512"}
# 哈希 -> (KCK 字节数, KEK 字节数)
KEY_LENGTHS = {"sha1": (16, 16), "sha256": (16, 16), "sha384": (24, 32), "sha512": (32, 32)}

Handshake = namedtuple("Handshake", "ap sta anonce snonce pmk akm cipher kdf descriptor version kck kek tk mic_alg mic_len frames ft", defaults=(None,))
# ft：快速切换握手才有，{"pmk_r0", "r0name", "ssid", "mdid", "r0kh_id"}——漫游到别的 AP 时从 PMK-R0 重新推 PMK-R1 要用


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
    if akm in (8, 9):
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


def candidate_pmks(keys, ssid, pmk_len, msk_offset=0):
    """(来源描述, PMK) 列表。keys：[("wpa-pwd" / "wpa-psk" / "msk" / "wep", 值)]。
    wpa-pwd 的值可以是「口令」或「口令:SSID」；没有 SSID 就用抓包里看到的。
    msk：从第 msk_offset 字节起取 pmk_len 字节（普通 802.1X 取开头；快速切换的 802.1X 取第二个 256 比特，msk_offset = 32）。"""
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
            if len(raw) >= msk_offset + pmk_len:
                out.append(("msk:%s…" % val[:8], raw[msk_offset:msk_offset + pmk_len]))
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
    ft_ctx = ft_contexts(frames)
    pending = {}                     # (ap, sta) -> 最近的 M1 (anonce, replay_counter, 帧号)
    done, skipped = [], []
    for f in frames:
        if f.h["type"] == 0 and f.h["subtype"] == 2 and not f.h["protected"]:
            roam = _ft_roam(f, done)
            if roam == "mismatch":
                skipped.append((f.n, "空中漫游的重关联请求：没有 FT 握手的 PMK-R0 让 FTE 的 MIC 吻合"))
            elif roam is not None:
                done.append(roam)
            continue
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
            if akm not in AKMS and akm not in FT_AKMS or cipher not in CIPHERS:
                skipped.append((f.n, "不支持的 AKM %s / 密码套件 %s" % (akm, cipher)))
                continue
            if akm in FT_AKMS:
                r = (d_ := ie.decode_all(els)).get("rsn") or {}
                hs = _try_ft(f, raw, e, m1, ap, sta, akm, cipher, ssids.get(h["bssid"]), keys, ft_ctx.get((ap, sta)), r.get("pmkids") or [])
            else:
                hs = _try(f, raw, e, m1, mld.get(ap, ap), mld.get(sta, sta), akm, cipher, ssids.get(h["bssid"]), keys)
            if hs is None:
                skipped.append((f.n, "没有候选 PMK 让 M2 的 MIC 吻合"))
            else:
                done.append(hs)
    return done, skipped


FtContext = namedtuple("FtContext", "mdid r0kh_id r1kh_id frame")


def ft_contexts(frames):
    """{(BSSID, STA): FtContext}：（重）关联响应里的移动域 ID 和 FTE 的 R0KH-ID / R1KH-ID（快速切换的密钥层级要用）。"""
    out = {}
    for f in frames:
        h = f.h
        if h["type"] != 0 or h["protected"] or h["subtype"] not in (1, 3):
            continue
        d = ie.decode_all(ie.walk(f.body[ie.FIXED_LEN[h["subtype"]]:])[0])
        md, fte = d.get("mdie"), d.get("fte")
        if md and fte and fte["r0kh_id"] is not None and fte["r1kh_id"] is not None:
            out[(h["addr2"], h["addr1"])] = FtContext(md["mdid"].to_bytes(2, "little"), fte["r0kh_id"], fte["r1kh_id"], f.n)
    return out


def _ft_roam(f, done):
    """空中漫游（FT 协议）：重关联请求带 RSNE（PMKID = 新 AP 的 PMKR1Name）、MDE、FTE（ANonce、SNonce、新 AP 的 R1KH-ID、R0KH-ID 和 MIC）。
    用已推出的 FT 初始握手里的 PMK-R0，换上新 AP 的 R1KH-ID 推 PMK-R1 和 PTK，再用 FTE 的 MIC 验证：
    MIC = CMAC / HMAC(KCK, STA ‖ AP ‖ 序号 5 ‖ RSNE ‖ MDE ‖ FTE（MIC 清零）‖ [RSNXE])。不是 FT 的重关联请求返回 None；是 FT 但对不上返回 "mismatch"。"""
    h = f.h
    els, _ = ie.walk(f.body[ie.FIXED_LEN[2]:])
    raw = {}
    for el in els:
        if el.ext is None and el.id in (48, 54, 55, 244):
            raw.setdefault(el.id, el)
    if 55 not in raw or 54 not in raw or 48 not in raw:
        return None
    d = ie.decode_all(els)
    fte, md, rsn = d.get("fte"), d.get("mdie"), d.get("rsn")
    if not fte or not md or not rsn or fte["r1kh_id"] is None or fte["r0kh_id"] is None or len(fte["r1kh_id"]) != 6:
        return None
    sta, ap = h["addr2"], h["addr1"]
    mdid = md["mdid"].to_bytes(2, "little")
    elem = lambda el: bytes([el.id, len(el.data)]) + el.data                       # noqa: E731
    fte_raw = elem(raw[55])
    zeroed_fte = fte_raw[:4] + bytes(fte["mic_length"]) + fte_raw[4 + fte["mic_length"]:]
    message = _mac(sta) + _mac(ap) + b"\x05" + elem(raw[48]) + elem(raw[54]) + zeroed_fte
    if fte["rsnxe_used"]:                       # MIC Control 的「RSNXE 已用」位置位：RSNXE（H2E 的 WPA3 样例）也在 MIC 的覆盖范围里，排在 FTE 之后
        if 244 not in raw:
            return "mismatch"
        message += elem(raw[244])
    for x in sorted((x for x in done if x.sta == sta and x.ft and x.ft["mdid"] == mdid and x.ft["r0kh_id"] == fte["r0kh_id"]), key=lambda x: -x.frames["m2"]):
        pmk_r1, r1name = ft80211.derive_r1(x.ft["pmk_r0"], x.kdf, x.ft["r0name"], fte["r1kh_id"], _mac(sta))
        kck_len, kek_len = KEY_LENGTHS[x.kdf]
        kck, kek, tk = ft80211.derive_ptk(pmk_r1, x.kdf, fte["snonce"], fte["anonce"], _mac(ap), _mac(sta), kck_len, kek_len, len(x.tk))
        alg = "cmac" if x.akm in (3, 4, 9) else "hmac-" + x.kdf
        if hmac.compare_digest(compute_mic(alg, kck, message, fte["mic_length"]), fte["mic"]):
            return Handshake(ap, sta, fte["anonce"], fte["snonce"], (x.pmk[0], pmk_r1), x.akm, x.cipher, x.kdf, x.descriptor, x.version, kck, kek, tk, alg,
                             fte["mic_length"], {"m1": f.n, "m2": f.n, "pmkr1name_ok": r1name in (rsn.get("pmkids") or []), "roam": True}, x.ft)
    return "mismatch"


def _try_ft(f, raw, e, m1, ap, sta, akm, cipher, ssid, keys, ctx, pmkids):
    """快速切换的初始 4 次握手：XXKey -> PMK-R0 -> PMK-R1 -> PTK（ft80211），用 M2 的 MIC 验证；
    M2 的 RSN 元素里的 PMKID 应当等于推出的 PMKR1Name，是第二个独立的验证（结果放在 frames["pmkr1name_ok"]）。"""
    if ctx is None or ssid is None:
        return None
    anonce, snonce = m1[0], e["nonce"]
    mic_len = e["mic_len"]
    kdf_hash = KDF_BY_MIC_LEN[mic_len] if FT_HASH[akm] == "by_mic" else FT_HASH[akm]
    kck_len, kek_len = KEY_LENGTHS[kdf_hash]
    tk_len = CIPHERS[cipher][1]
    descriptor, version = e["descriptor"], e["key_info"]["version"]
    e2 = eapol.parse(raw, mic_len=mic_len)
    alg = mic_algorithm(version, mic_len, akm)
    zeroed = eapol.zero_mic(raw[:4 + e2["length"]], mic_len)
    for source, xx in candidate_pmks(keys, ssid, FT_XXKEY_LEN[akm] or ft80211.DIGEST_LEN[kdf_hash], FT_MSK_OFFSET.get(akm, 0)):
        pmk_r0, r0name = ft80211.derive_r0(xx, kdf_hash, ssid, ctx.mdid, ctx.r0kh_id, _mac(sta))
        pmk_r1, r1name = ft80211.derive_r1(pmk_r0, kdf_hash, r0name, ctx.r1kh_id, _mac(sta))
        kck, kek, tk = ft80211.derive_ptk(pmk_r1, kdf_hash, snonce, anonce, _mac(ap), _mac(sta), kck_len, kek_len, tk_len)
        if hmac.compare_digest(compute_mic(alg, kck, zeroed, mic_len), e2["mic"]):
            return Handshake(ap, sta, anonce, snonce, (source, pmk_r1), akm, CIPHERS[cipher][0], kdf_hash, descriptor, version,
                             kck, kek, tk, alg, mic_len, {"m1": m1[2], "m2": f.n, "pmkr1name_ok": r1name in pmkids},
                             {"pmk_r0": pmk_r0, "r0name": r0name, "ssid": ssid, "mdid": ctx.mdid, "r0kh_id": ctx.r0kh_id})
    return None


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
