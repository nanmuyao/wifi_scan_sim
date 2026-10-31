#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CCMP / GCMP / TKIP / WEP 解密对照 tshark：样例里 tshark 解出明文的每一帧，用我们握手推出的 TK 解一遍，
要求 MIC 通过且明文逐字节相同。没法解的帧分类固定成数字（改进或退步都会让测试失败）：
  ok         单播：MIC 通过、明文与 tshark 相同
  group      组播 / 广播：用 M3 / G1 里解出的 GTK，MIC 通过、明文与 tshark 相同
  mgmt       受保护的单播管理帧（PMF）：同样的 MIC + 明文相同
  wep        WEP（数据帧和共享密钥认证的第 3 帧）：ICV 通过、明文相同
  no_hs      找不到适用的密钥（FT、TDLS 对端直连、TKIP 之类还没处理的）
  stale      有握手但解不开
  ours_only  tshark 没解出、我们 MIC 通过（应为 0：多出来的要弄清是怎么回事）
"""
import collections
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decrypt80211 as dec  # noqa: E402
import decrypt_oracle as d  # noqa: E402
import fetch_samples  # noqa: E402
import frames80211 as fr  # noqa: E402
import groupkeys80211 as gk  # noqa: E402
import handshake80211 as hs  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


AEAD = ("CCMP", "GCMP", "TKIP", "WEP")
CATEGORIES = ("ok", "group", "mgmt", "wep", "no_hs", "stale", "ours_only")


def classify(path, keys):
    frames = list(fr.iter_frames(path))
    done, _ = hs.track(frames, keys)
    gkeys, gciph = gk.track_group(frames, done), gk.group_ciphers(frames, done)
    wkeys = dec.wep_keys(keys)
    ts = d.tshark_plain(path, keys)
    out = collections.Counter()
    for f in frames:
        if not f.h["protected"] or f.h["type"] == 1:
            continue
        theirs = ts.get(f.n)
        if theirs is not None and theirs["method"] not in AEAD:
            continue
        wep = dec.decrypt_wep(wkeys, f)
        if wep is not None or (theirs is not None and theirs["method"] == "WEP"):
            if theirs is None:
                out["ours_only"] += 1
            else:
                out["wep" if wep is not None and wep[0] == theirs["plain"] else "stale"] += 1
            continue
        pair = {f.h["addr1"], f.h["addr2"]}
        if not [x for x in done if {x.ap, x.sta} == pair and x.frames["m2"] < f.n]:
            g = gk.decrypt_group(gkeys, gciph, f)
            if g is not None and theirs is not None and g[1] == theirs["plain"]:
                out["group"] += 1
            elif theirs is not None:
                out["no_hs"] += 1
            elif g is not None:
                out["ours_only"] += 1
            continue
        got = dec.decrypt_frame(done, f)
        if theirs is None:
            if got is not None:
                out["ours_only"] += 1
        elif got is not None and got[1] == theirs["plain"]:
            out["mgmt" if f.h["type"] == 0 else "ok"] += 1
        else:
            out["stale"] += 1
    return tuple(out[k] for k in CATEGORIES)


EXPECTED = {
    "owe-3-dh-groups.pcapng.gz": (1, 0, 0, 0, 0, 0, 2),
    "owe.pcapng.gz": (5, 5, 0, 0, 0, 0, 0),
    "wep.pcapng.gz": (0, 0, 0, 11, 0, 0, 0),
    "wpa-Induction.pcap.gz": (203, 73, 0, 0, 0, 0, 0),
    "wpa-ccmp-256.pcapng.gz": (8, 6, 0, 0, 0, 0, 0),
    "wpa-eap-tls.pcap.gz": (59, 2, 0, 0, 0, 0, 0),
    "wpa-gcmp-256.pcapng.gz": (8, 5, 0, 0, 0, 0, 0),
    "wpa-gcmp.pcapng.gz": (9, 6, 0, 0, 0, 0, 0),
    "wpa-mlo-ccmp.pcapng.gz": (0, 0, 0, 0, 0, 0, 0),
    "wpa-test-decode-mgmt.pcap.gz": (0, 0, 3, 0, 0, 0, 0),
    "wpa-test-decode-tdls.pcap.gz": (6, 0, 0, 0, 2, 0, 0),
    "wpa-test-decode.pcap.gz": (716, 40, 0, 0, 0, 0, 0),
    "wpa1-gtk-rekey.pcapng.gz": (16, 6, 0, 0, 0, 0, 0),
    "wpa2-ft-eap.pcapng.gz": (0, 0, 0, 0, 4, 0, 0),
    "wpa2-ft-psk.pcapng.gz": (0, 0, 0, 0, 17, 0, 0),
    "wpa2-psk-ccmp-tkip.pcapng.gz": (8, 4, 0, 0, 0, 0, 0),
    "wpa2-psk-mfp.pcapng.gz": (7, 2, 0, 0, 0, 0, 0),
    "wpa3-ft-sae-ext-key-group20.pcapng.gz": (0, 0, 0, 0, 0, 0, 0),
    "wpa3-ft-sae-h2e.pcapng.gz": (0, 0, 0, 0, 10, 0, 0),
    "wpa3-mlo.pcapng.gz": (0, 0, 0, 0, 0, 0, 0),
    "wpa3-sae-ext-key-group21.pcapng.gz": (0, 0, 0, 0, 0, 0, 2),
    "wpa3-sae.pcapng.gz": (6, 4, 0, 0, 0, 0, 0),
    "wpa3-suiteb-192.pcapng.gz": (0, 0, 3, 0, 0, 0, 0),
    "wpa_ptk_extended_key_id.pcap.gz": (19, 12, 0, 0, 0, 0, 0),
}

if __name__ == "__main__":
    keys = d.parse_keys()
    fetch_samples.fetch()
    totals = [0] * len(CATEGORIES)
    for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
        got = classify(os.path.join(fetch_samples.SAMPLE_DIR, name), keys)
        totals = [a + b for a, b in zip(totals, got)]
        check(got == EXPECTED[name], "%s：%s（表里 %s）" % (name, dict(zip(CATEGORIES, got)), dict(zip(CATEGORIES, EXPECTED[name]))))
    check(sorted(EXPECTED) == sorted(os.listdir(fetch_samples.SAMPLE_DIR)), "表里的样例就是目录里的全部样例")
    check(totals[0] == 1071 and totals[1] == 165 and totals[2] == 6 and totals[3] == 11 and totals[5] == 0 and totals[6] == 4, "与 tshark 明文逐字节相同：单播 %d 帧、组播 %d 帧、受保护管理帧 %d 帧、WEP %d 帧；tshark 解不了而我们解开的 %d 帧" % (totals[0], totals[1], totals[2], totals[3], totals[6]))
    print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
    sys.exit(0 if not failures else 1)
