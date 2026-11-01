# -*- coding: utf-8 -*-
"""
把前面各层接起来：一个抓包文件 + 密钥表 -> 每个受保护数据帧解密后的 MSDU（LLC/SNAP 开头）。纯标准库。

顺序：4 次握手 / 重新握手 / FT 漫游推出的 PTK（handshake80211），M3 / G1 / FT 响应里的 GTK（groupkeys80211），WEP 密钥；
每个受保护的帧依次试 WEP、单播（成对密钥）、组播（GTK）、用户直接给的 TK，最后是 TDLS 对端直连（TPK），MIC / ICV 通过的才算解开。QoS 的 A-MSDU 位置位的帧拆成多个 MSDU。

诊断：decrypt_capture 可以多给一个 stats 字典（不改变返回值），填上解开 / 没解开的数字和原因；diagnose 是它的包装，explain 把这些数字翻成「最可能的原因和下一步」。
"""
import logging

from . import amsdu
from . import decrypt as dec
from . import groupkeys as gk
from . import handshake as hs
from . import keyfile
from . import logs
from . import tdls as tdls80211

log = logging.getLogger(__name__)
EXAMPLES = 5                                                   # 每种原因最多记几个帧号


def _pair_of(h):
    """单播帧里的 (AP, 设备)：发往 AP 的（ToDS）A1 是 AP，AP 发来的（FromDS）A2 是 AP；别的情形（直连、WDS）按 A1 / A2 原样。"""
    if h["from_ds"] and not h["to_ds"]:
        return h["addr2"], h["addr1"]
    return h["addr1"], h["addr2"]


def decrypt_capture(frames, keys, stats=None):
    """frames：frames80211.iter_frames 的结果（列表）。返回 {帧号: {"how": "wep" / "pairwise" / "group" / "user_tk" / "tdls", "msdus": [bytes, ...]}}，
    只含解开了的受保护数据帧（受保护的管理帧、认证帧里的 WEP 不含 LLC，不在其中）。
    stats：可选的 dict，给了就填上诊断信息，见 diagnose；不影响返回值。"""
    tstats, gstats = {}, {}
    ksum = keyfile.summary(keys)
    log.info("解密：%d 个帧，密钥 %s", len(frames), "、".join("%s %d 把" % kv for kv in ksum.items()) if ksum else "一把也没有")
    done, _ = hs.track(frames, keys, tstats)
    mld = hs.mld_addresses(frames)
    gkeys, gciph = gk.track_group(frames, done, gstats), gk.group_ciphers(frames, done)
    wkeys = dec.wep_keys(keys)
    utks = dec.user_tks(keys)
    if mld:
        log.debug("多链路：%d 个链路地址对应 MLD 地址", len(mld))
    out = {}
    protected = 0
    tr = log.isEnabledFor(logs.TRACE)
    failed = []                                                # 没解开的受保护数据帧
    for f in frames:
        h = f.h
        if h["type"] != 2 or not h["protected"]:
            continue
        protected += 1
        how, plain = None, None
        w = dec.decrypt_wep(wkeys, f)
        if w is not None:
            how, plain = "wep", w[0]
        else:
            p = dec.decrypt_frame(done, f, mld)
            if p is not None:
                how, plain = "pairwise", p[1]
            else:
                g = gk.decrypt_group(gkeys, gciph, f)
                if g is not None:
                    how, plain = "group", g[1]
                else:
                    u = dec.decrypt_user_tk(utks, f, mld) if utks else None            # 用户直接给的 TK（密钥表里的 "tk" 项），没有握手也能解单播帧
                    if u is not None:
                        how, plain = "user_tk", u[0]
        if plain is None:
            failed.append(f)
            if tr:
                logs.trace(log, "第 %d 帧：受保护的数据帧，没解开（%s -> %s）", f.n, h["addr2"], h["addr1"])
            continue
        if h["qos"] is not None and h["qos"]["amsdu"]:
            msdus = [bytes(s["payload"]) for s in amsdu.parse(plain)["subframes"]]
        else:
            msdus = [plain]
        out[f.n] = {"how": how, "msdus": msdus}
        if tr:
            logs.trace(log, "第 %d 帧：解开（%s），%d 个 MSDU", f.n, how, len(msdus))
    # TDLS：建立帧已经在上面解开，推出 TPK 之后，两个对端之间直接互发的帧（A3 = BSSID）也能解
    tkeys = tdls80211.track({n: v["msdus"] for n, v in out.items()})
    if tkeys:
        for f in list(failed):
            r = tdls80211.decrypt_frame(tkeys, f)
            if r is not None:
                out[f.n] = {"how": "tdls", "msdus": [r[1]]}
                failed.remove(f)
    by_how = {}
    for v in out.values():
        by_how[v["how"]] = by_how.get(v["how"], 0) + 1
    log.info("解密结果：受保护的数据帧 %d 个，解开 %d 个%s，没解开 %d 个", protected, len(out), "（%s）" % "、".join("%s %d" % kv for kv in sorted(by_how.items())) if by_how else "", len(failed))
    reasons, examples, pair_frames = _classify(failed, done, gkeys, gciph, mld) if failed and (stats is not None or log.isEnabledFor(logging.DEBUG)) else ({}, {}, {})
    for r, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
        log.debug("没解开的原因：%s —— %d 个（例：帧 %s）", _reason_text(r), n, "、".join(str(x) for x in examples[r]))
    if protected and len(out) * 2 < protected:
        top = max(reasons.items(), key=lambda kv: kv[1])[0] if reasons else None
        log.warning("一半以上的受保护数据帧没解开（%d / %d）%s", protected - len(out), protected, "，主要原因：" + _reason_text(top) if top else "")
    if stats is not None:
        stats.update({"frames": len(frames), "protected_data": protected, "decrypted": len(out), "by_how": by_how, "undecrypted": reasons, "examples": examples,
                      "pair_frames": [{"ap": ap, "sta": sta, "reason": r, "count": n} for (ap, sta, r), n in sorted(pair_frames.items())],
                      "keys": ksum, "wep_keys": len(wkeys), "user_tks": len(utks), "handshake": tstats, "group": gstats, "tdls_keys": len(tkeys)})
    return out


def _reason_text(code):
    return dec.WHY.get(code) or gk.WHY_GROUP.get(code) or {"other": "不属于单播也不属于 AP 发出的组播（WDS / 直连 / 别的）"}.get(code, code)


def _classify(failed, done, gkeys, gciph, mld):
    """没解开的受保护数据帧 -> ({原因代码: 个数}, {原因代码: [前几个帧号]}, {(AP, 设备, 原因): 个数})。组播 / 广播的看组密钥，单播的看握手。"""
    reasons, examples, pair_frames = {}, {}, {}
    for f in failed:
        h = f.h
        if int(h["addr1"].split(":")[0], 16) & 1:
            r = gk.why_not_group(gkeys, gciph, f)
            if r == "not_group":
                r = "other"
        elif h["to_ds"] and h["from_ds"]:
            r = "other"
        else:
            r = dec.why_not(done, f, mld)
            ap, sta = _pair_of(h)
            pair_frames[(ap, sta, r)] = pair_frames.get((ap, sta, r), 0) + 1
        reasons[r] = reasons.get(r, 0) + 1
        ex = examples.setdefault(r, [])
        if len(ex) < EXAMPLES:
            ex.append(f.n)
    return reasons, examples, pair_frames


def diagnose(frames, keys):
    """跑一遍 decrypt_capture，返回诊断字典（见 decrypt_capture 的 stats）：frames、protected_data、decrypted、by_how、undecrypted（原因 -> 个数）、examples、
    pair_frames（每对 (AP, 设备) 的没解开原因）、keys（密钥类型 -> 把数，不含值）、handshake（pairs：每对的 M1–M4 帧号 / SSID / 状态码，ssids，eapol）、group。"""
    stats = {}
    decrypt_capture(frames, keys, stats)
    return stats


def explain(stats):
    """诊断字典 -> 中文的原因和下一步，一行一条。只说数据支持的结论。"""
    n, ok = stats["protected_data"], stats["decrypted"]
    if n == 0:
        return ["抓包里没有受保护的数据帧：没抓到数据帧（监听的信道不对？），或者是开放网络。"]
    if ok == n:
        return ["所有 %d 个受保护的数据帧都解开了。" % n]
    lines = []
    pairs = stats["handshake"].get("pairs", [])
    keys = stats["keys"]
    if not keys:
        lines.append("没有给任何密钥。")
    has_user_tk = stats["user_tks"] > 0
    if not pairs and not has_user_tk:
        lines.append("整个抓包里没有找到四次握手的报文（EAPOL）：抓包开始时设备多半已经连着。需要在开始抓包之后让设备断开重连（关再开 WiFi），才抓得到握手。")
    for p in pairs:
        who = "AP %s 与设备 %s（SSID %s）" % (p["ap"], p["sta"], "未知" if p["ssid"] is None else '"%s"' % p["ssid"])
        st = p["state"]
        if st == "mic_mismatch":
            lines.append("%s的握手 MIC 对不上（试了 %d 个候选密钥）：多半是口令输错，或 SSID 不对；也可能握手报文被截断。先核对口令和 SSID，大小写要一致。" % (who, p["candidates"]))
        elif st == "only_m1":
            lines.append("%s的握手只抓到 M1（帧 %s），没抓到 M2：设备的回复没被监听到。让设备断开重连再抓一次，并确认监听的信道和 AP 的信道一致。" % (who, hs._frames_text(p["msgs"][1])))
        elif st == "no_candidates":
            lines.append("%s的握手有 M2，但没有可用的候选密钥：%s。" % (who, hs.NO_CANDIDATE_WHY.get(p.get("no_candidates_why"), "原因不明")))
        elif st == "m2_without_m1":
            lines.append("%s的握手只抓到 M2 / 缺 RSN 元素：M1 没抓到，无法推导密钥。让设备断开重连再抓一次。" % who)
        elif st == "unsupported":
            lines.append("%s的握手用了不支持的认证方式 / 密码套件（%s）。" % (who, "、".join(o.split(":", 1)[1] for o in p["other"] if o.startswith("unsupported"))))
        elif st == "incomplete":
            lines.append("%s的握手报文不全（M1 帧 %s；M2 帧 %s）。" % (who, hs._frames_text(p["msgs"][1]), hs._frames_text(p["msgs"][2])))
    by_pair = {}
    for pf in stats["pair_frames"]:
        by_pair.setdefault(pf["reason"], []).append(pf)
    state = {(p["ap"], p["sta"]): p["state"] for p in pairs}
    for pf in by_pair.get("no_handshake", []):
        if (pf["ap"], pf["sta"]) not in state:
            lines.append("有 %d 个帧属于 AP %s 与设备 %s，但抓包里没有这一对的握手：设备在抓包开始前就已连上，或者握手报文没被监听到。需要在开始抓包之后让它断开重连。" % (pf["count"], pf["ap"], pf["sta"]))
    for pf in by_pair.get("before_handshake", []):
        lines.append("有 %d 个帧（AP %s，设备 %s）早于这对设备的握手，当时用的密钥没抓到：属于正常现象，只有握手之后的帧能解。" % (pf["count"], pf["ap"], pf["sta"]))
    for pf in by_pair.get("mic_failed", []):
        if state.get((pf["ap"], pf["sta"])) == "verified":
            lines.append("AP %s 与设备 %s的握手验证通过，但仍有 %d 个帧的 MIC 不对：多半是中途重新握手换了密钥而没抓到，或帧在传输中损坏。" % (pf["ap"], pf["sta"], pf["count"]))
    u = stats["undecrypted"]
    for code in ("cipher_unknown", "no_gtk_for_ap", "no_gtk_keyid", "gtk_after_frame"):
        if u.get(code):
            lines.append("%d 个组播 / 广播帧没解开：%s。" % (u[code], gk.WHY_GROUP[code]))
    if u.get("cipher_unsupported"):
        lines.append("%d 个帧没解开：%s。" % (u["cipher_unsupported"], dec.WHY["cipher_unsupported"]))
    if not lines:
        lines.append("%d 个受保护的数据帧没解开，但数据不足以判断原因；把日志文件（--log-level debug）发给我看。" % (n - ok))
    return lines
