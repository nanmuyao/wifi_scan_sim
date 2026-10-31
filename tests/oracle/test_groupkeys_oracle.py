#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""groupkeys80211 对照 tshark：我们从 M3 / G1 的 Key Data 里解出的 GTK，和 tshark 打在帧上的 wlan.analysis.gtk 比。
每个样例固定成 (我们解出几个, 其中 M3 / G1 各几个, 与 tshark 相同的 tshark GTK 数, tshark 有而我们没有的数, 我们有而 tshark 没有的数)。
GTK 能被解出本身就是证明：先用 KCK 验 M3 / G1 的 MIC，再让 KEK 过一遍 AES 密钥包装的完整性校验（RFC 3394 的 A6A6… 头）。
tshark 有而我们没有：wpa2-ft-psk 漫游后新 AP 的 GTK（空中漫游，阶段 E 下一步）。我们有而 tshark 没有：tshark 4.4 加载不了的 64 字节 PMK 握手、它没跟踪的加密重新握手里的 G1、PMF 之类。
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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


def tshark_gtks(path, usable):
    with d.key_env(usable) as env:
        r = subprocess.run(["tshark", "-r", path] + d.TSHARK_DECRYPT + ["-T", "fields", "-e", "wlan.analysis.gtk"], capture_output=True, text=True, env=env).stdout
    return {l.replace(":", "") for l in r.split("\n") if l}


def same(a, b):
    return a.startswith(b) or b.startswith(a)        # TKIP 的 32 字节 GTK，tshark 只打一部分


def summarize(path, keys, usable):
    frames = list(fr.iter_frames(path))
    done, _ = hs.track(frames, keys)
    ours = gk.track_group(frames, done)
    ts = tshark_gtks(path, usable)
    ours_hex = {k.gtk.hex() for k in ours}
    return (len(ours), sum(k.source == "M3" for k in ours), sum(k.source == "G1" for k in ours),
            sum(any(same(o, t) for o in ours_hex) for t in ts),
            sum(not any(same(o, t) for o in ours_hex) for t in ts),
            sum(not any(same(o, t) for t in ts) for o in ours_hex)), ours


EXPECTED = {
    "owe-3-dh-groups.pcapng.gz": (3, 3, 0, 0, 0, 1),
    "owe.pcapng.gz": (1, 1, 0, 1, 0, 0),
    "wep.pcapng.gz": (0, 0, 0, 0, 0, 0),
    "wpa-Induction.pcap.gz": (1, 1, 0, 1, 0, 0),
    "wpa-ccmp-256.pcapng.gz": (1, 1, 0, 1, 0, 0),
    "wpa-eap-tls.pcap.gz": (12, 3, 9, 2, 0, 4),
    "wpa-gcmp-256.pcapng.gz": (1, 1, 0, 1, 0, 0),
    "wpa-gcmp.pcapng.gz": (1, 1, 0, 1, 0, 0),
    "wpa-mlo-ccmp.pcapng.gz": (0, 0, 0, 0, 0, 0),
    "wpa-test-decode-mgmt.pcap.gz": (1, 1, 0, 0, 0, 1),
    "wpa-test-decode-tdls.pcap.gz": (2, 2, 0, 0, 0, 1),
    "wpa-test-decode.pcap.gz": (1, 1, 0, 1, 0, 0),
    "wpa1-gtk-rekey.pcapng.gz": (3, 0, 3, 3, 0, 0),
    "wpa2-ft-eap.pcapng.gz": (1, 1, 0, 1, 0, 0),
    "wpa2-ft-psk.pcapng.gz": (1, 1, 0, 1, 1, 0),
    "wpa2-psk-ccmp-tkip.pcapng.gz": (1, 1, 0, 1, 0, 0),
    "wpa2-psk-mfp.pcapng.gz": (1, 1, 0, 1, 0, 0),
    "wpa3-ft-sae-ext-key-group20.pcapng.gz": (1, 1, 0, 0, 0, 1),
    "wpa3-ft-sae-h2e.pcapng.gz": (1, 1, 0, 1, 0, 0),
    "wpa3-mlo.pcapng.gz": (0, 0, 0, 0, 0, 0),
    "wpa3-sae-ext-key-group21.pcapng.gz": (1, 1, 0, 0, 0, 1),
    "wpa3-sae.pcapng.gz": (1, 1, 0, 1, 0, 0),
    "wpa3-suiteb-192.pcapng.gz": (3, 3, 0, 0, 0, 1),
    "wpa_ptk_extended_key_id.pcap.gz": (3, 3, 0, 1, 0, 0),
}
if __name__ == "__main__":
    fetch_samples.fetch()
    keys = d.parse_keys()
    usable, _ = d.tshark_usable(keys)
    got_all = {}
    for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
        got, _ours = summarize(os.path.join(fetch_samples.SAMPLE_DIR, name), keys, usable)
        got_all[name] = got
        if name in EXPECTED:
            check(got == EXPECTED[name], "%s：%s（表里 %s）" % (name, got, EXPECTED[name]))
        else:
            print('    "%s": %s,' % (name, got))
    if EXPECTED:
        check(sum(v[0] for v in got_all.values()) == 41 and sum(v[3] for v in got_all.values()) == 18, "共解出 %d 个组密钥，%d 个 GTK 与 tshark 相同" % (sum(v[0] for v in got_all.values()), sum(v[3] for v in got_all.values())))
        check(sorted(EXPECTED) == sorted(os.listdir(fetch_samples.SAMPLE_DIR)), "表里的样例就是目录里的全部样例")
        print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
        sys.exit(0 if not failures else 1)
