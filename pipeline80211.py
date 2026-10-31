# -*- coding: utf-8 -*-
"""
把前面各层接起来：一个抓包文件 + 密钥表 -> 每个受保护数据帧解密后的 MSDU（LLC/SNAP 开头）。纯标准库。

顺序：4 次握手 / 重新握手 / FT 漫游推出的 PTK（handshake80211），M3 / G1 / FT 响应里的 GTK（groupkeys80211），WEP 密钥；
每个受保护的帧依次试 WEP、单播（成对密钥）、组播（GTK），最后是 TDLS 对端直连（TPK），MIC / ICV 通过的才算解开。QoS 的 A-MSDU 位置位的帧拆成多个 MSDU。
"""
import amsdu
import decrypt80211 as dec
import groupkeys80211 as gk
import handshake80211 as hs
import tdls80211


def decrypt_capture(frames, keys):
    """frames：frames80211.iter_frames 的结果（列表）。返回 {帧号: {"how": "wep" / "pairwise" / "group", "msdus": [bytes, ...]}}，
    只含解开了的受保护数据帧（受保护的管理帧、认证帧里的 WEP 不含 LLC，不在其中）。"""
    done, _ = hs.track(frames, keys)
    mld = hs.mld_addresses(frames)
    gkeys, gciph = gk.track_group(frames, done), gk.group_ciphers(frames, done)
    wkeys = dec.wep_keys(keys)
    out = {}
    for f in frames:
        h = f.h
        if h["type"] != 2 or not h["protected"]:
            continue
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
        if plain is None:
            continue
        if h["qos"] is not None and h["qos"]["amsdu"]:
            msdus = [bytes(s["payload"]) for s in amsdu.parse(plain)["subframes"]]
        else:
            msdus = [plain]
        out[f.n] = {"how": how, "msdus": msdus}
    # TDLS：建立帧已经在上面解开，推出 TPK 之后，两个对端之间直接互发的帧（A3 = BSSID）也能解
    tkeys = tdls80211.track({n: v["msdus"] for n, v in out.items()})
    if tkeys:
        for f in frames:
            if f.n in out:
                continue
            r = tdls80211.decrypt_frame(tkeys, f)
            if r is not None:
                out[f.n] = {"how": "tdls", "msdus": [r[1]]}
    return out
