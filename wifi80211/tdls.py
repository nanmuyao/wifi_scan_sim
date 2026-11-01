# -*- coding: utf-8 -*-
"""
TDLS（直连链路建立，802.11z）：两个站点经过 AP 交换三条 TDLS 建立帧，推出对等密钥 TPK，之后直接互发加密数据帧。纯标准库。

建立帧是普通数据帧（以太类型 0x890d），先由各自的 PTK 保护经 AP 转发，所以要先解密（pipeline80211）才能读：
  载荷：类型 2 ‖ 类别 12 ‖ 动作 ‖ …
    Setup Request（0）：对话令牌(1) ‖ 能力(2) ‖ 元素…          FTE 里有发起方的 SNonce
    Setup Response（1）：状态(2) ‖ 对话令牌(1) ‖ 能力(2) ‖ 元素… FTE 里有响应方的 ANonce、发起方的 SNonce，带 MIC
    Setup Confirm（2）：状态(2) ‖ 对话令牌(1) ‖ 元素…            FTE 带 MIC
  元素：链路标识（101：BSSID ‖ 发起方 ‖ 响应方）、RSNE（48）、超时间隔（56）、FTE（55）。
密钥：TPK-Key-Input = SHA-256(min(SNonce, ANonce) ‖ max(SNonce, ANonce))
      TPK = KDF-256(Key-Input, "TDLS PMK", min(发起方, 响应方) ‖ max(发起方, 响应方) ‖ BSSID)，前 128 比特 TPK-KCK、后 128 比特 TPK-TK（CCMP-128）。
验证：FTE 的 MIC = AES-128-CMAC(TPK-KCK, 发起方 ‖ 响应方 ‖ 序号(1：Response 2、Confirm 3) ‖ 链路标识元素 ‖ RSNE ‖ 超时间隔元素 ‖ FTE（MIC 清零）)（元素都带 ID 和长度）。
"""
import hashlib
import logging
from collections import namedtuple

from . import decrypt as dec
from . import ie
from . import kdf

log = logging.getLogger(__name__)

ETHERTYPE = 0x890D
SETUP_REQUEST, SETUP_RESPONSE, SETUP_CONFIRM = 0, 1, 2
# 动作 -> 元素从第几个字节开始（类型 1 ‖ 类别 1 ‖ 动作 1 ‖ [状态 2] ‖ 令牌 1 ‖ [能力 2]）
ELEMENTS_AT = {SETUP_REQUEST: 6, SETUP_RESPONSE: 8, SETUP_CONFIRM: 6}
# initiator / responder / bssid 是 "aa:bb:…" 字符串；frames：{"response": 帧号, "confirm": 帧号或 None}
TdlsKey = namedtuple("TdlsKey", "initiator responder bssid kck tk cipher frames")


def _mac(b):
    return ":".join("%02x" % x for x in b)


def _raw(el):
    return bytes([el.id, len(el.data)]) + el.data


def parse_action(data):
    """SNAP 之后的 TDLS 载荷 -> {"action", "status", "token", "bssid", "initiator", "responder", "rsne", "timeout", "fte", "fte_raw", "link_raw", "rsne_raw", "timeout_raw"}。
    不是 TDLS 建立帧（不是类型 2 / 类别 12，或动作不是 0 / 1 / 2）、元素残缺返回 None。"""
    if len(data) < 6 or data[0] != 2 or data[1] != 12 or data[2] not in ELEMENTS_AT:
        return None
    action = data[2]
    status = int.from_bytes(data[3:5], "little") if action != SETUP_REQUEST else None
    token = data[3] if action == SETUP_REQUEST else data[5]
    start = ELEMENTS_AT[action]
    if len(data) < start:
        return None
    els, truncated = ie.walk(data[start:])
    if truncated:
        return None
    by = {}
    for e in els:
        if e.ext is None:
            by.setdefault(e.id, e)
    link = by.get(101)
    out = {"action": action, "status": status, "token": token, "bssid": None, "initiator": None, "responder": None, "fte": None,
           "link_raw": _raw(link) if link else None, "rsne_raw": _raw(by[48]) if 48 in by else None, "timeout_raw": _raw(by[56]) if 56 in by else None,
           "fte_raw": _raw(by[55]) if 55 in by else None, "rsne": None}
    if link and len(link.data) == 18:
        out["bssid"], out["initiator"], out["responder"] = _mac(link.data[0:6]), _mac(link.data[6:12]), _mac(link.data[12:18])
    if 55 in by:
        out["fte"] = ie.decode_ft(by[55].data)
    if 48 in by:
        out["rsne"] = ie.decode_all([by[48]]).get("rsn")
    return out


def derive_tpk(snonce, anonce, initiator, responder, bssid):
    """返回 (TPK-KCK, TPK-TK)，地址是 6 字节。"""
    key_input = hashlib.sha256(min(snonce, anonce) + max(snonce, anonce)).digest()
    tpk = kdf.kdf("sha256", key_input, b"TDLS PMK", min(initiator, responder) + max(initiator, responder) + bssid, 256)
    return tpk[:16], tpk[16:]


def mic_of(kck, action, msg):
    """Response / Confirm 的 FTE MIC（见模块说明）。msg 是 parse_action 的结果。"""
    seq = {SETUP_RESPONSE: 2, SETUP_CONFIRM: 3}[action]
    fte = msg["fte_raw"]
    mic_len = msg["fte"]["mic_length"]
    zeroed = fte[:4] + bytes(mic_len) + fte[4 + mic_len:]
    initiator, responder = bytes.fromhex(msg["initiator"].replace(":", "")), bytes.fromhex(msg["responder"].replace(":", ""))
    data = initiator + responder + bytes([seq]) + msg["link_raw"] + msg["rsne_raw"] + msg["timeout_raw"] + zeroed
    return kdf.aes_cmac(kck, data, 16)


def track(msdus):
    """msdus：{帧号: [解密后的 MSDU（LLC/SNAP 开头）]}（pipeline80211.decrypt_capture 的结果整理成这样）。
    找出所有 TDLS 建立三件套，推 TPK，用 Response / Confirm 的 MIC 验证，返回通过验证的 [TdlsKey]（只收 CCMP-128，TDLS 的规定）。
    同一条建立帧经 AP 转发会出现两次（STA→AP、AP→STA），内容相同，按（动作，链路标识，令牌）去重。"""
    reqs, resps, confs = {}, {}, {}
    for n in sorted(msdus):
        for m in msdus[n]:
            if len(m) < 8 or m[:3] != b"\xaa\xaa\x03" or int.from_bytes(m[6:8], "big") != ETHERTYPE:
                continue
            msg = parse_action(m[8:])
            if msg is None or msg["bssid"] is None or msg["fte"] is None:
                continue
            key = (msg["bssid"], msg["initiator"], msg["responder"], msg["token"])
            {SETUP_REQUEST: reqs, SETUP_RESPONSE: resps, SETUP_CONFIRM: confs}[msg["action"]].setdefault(key, (n, msg))
    out = []
    for key, (n_resp, resp) in resps.items():
        bssid, initiator, responder, _tok = key
        r = resp["rsne"]
        if not r or not r.get("pairwise") or r["pairwise"][0][1] != 4:                  # 只做 CCMP-128
            continue
        anonce, snonce = resp["fte"]["anonce"], resp["fte"]["snonce"]
        mac = lambda s: bytes.fromhex(s.replace(":", ""))                             # noqa: E731
        kck, tk = derive_tpk(snonce, anonce, mac(initiator), mac(responder), mac(bssid))
        conf = confs.get(key)
        ok_resp = resp["rsne_raw"] is not None and resp["timeout_raw"] is not None and mic_of(kck, SETUP_RESPONSE, resp) == resp["fte"]["mic"]
        ok_conf = conf is not None and conf[1]["rsne_raw"] is not None and conf[1]["timeout_raw"] is not None and mic_of(kck, SETUP_CONFIRM, conf[1]) == conf[1]["fte"]["mic"]
        log.debug("TDLS：发起方 %s 与对端 %s（BSSID %s）：Response 的 MIC %s，Confirm %s", initiator, responder, bssid, "吻合" if ok_resp else "对不上",
                  "缺失" if conf is None else ("吻合" if ok_conf else "对不上"))
        if ok_resp or ok_conf:
            out.append(TdlsKey(initiator, responder, bssid, kck, tk, "CCMP-128", {"response": n_resp, "confirm": conf[0] if conf else None, "response_mic_ok": ok_resp, "confirm_mic_ok": ok_conf}))
    if resps:
        log.info("TDLS：看到 %d 组建立帧，%d 组 MIC 验证通过", len(resps), len(out))
    return out


def decrypt_frame(keys, frame):
    """直连的受保护数据帧：两个对端互发，A3 = BSSID。返回 (TdlsKey, 明文) 或 None。"""
    h = frame.h
    if h["type"] != 2 or not h["protected"]:
        return None
    pair = {h["addr1"], h["addr2"]}
    for k in keys:
        if pair == {k.initiator, k.responder} and h["addr3"] == k.bssid:
            try:
                pt, ok, _pn = dec.decrypt_aead(k.tk, k.cipher, frame)
            except ValueError:
                continue
            if ok:
                return k, pt
    return None
