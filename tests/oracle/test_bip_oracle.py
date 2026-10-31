#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BIP 在真实抓包上：带 Management MIC 元素的帧，我们找到的个数和 tshark（wlan.tag.number == 76）的一致，
每帧的校验结果固定成数字。tshark 只显示 MME 不校验它，所以答案是我们自己的 MIC：
wpa3-suiteb-192 的 1 个 BIP-GMAC-256 解除认证帧，用 M3 里解出的 IGTK 验证通过（IV = A2 ‖ IPN 反过来，AAD = 屏蔽后的帧控制 ‖ A1 A2 A3 ‖ MIC 清零的帧体）；
wpa3-mlo 的 2 个信标用 BIGTK（密钥序号 6，保护信标，MLO 的 M3 里解出来了）保护：我们试了 BIP-CMAC-128 在 FC 屏蔽、时间戳清零、MIC 清零或去掉、IPN 前缀等各种组合，都对不上——信标保护的 MIC 范围规则没弄清，所以不判（unsupported）。
"""
import collections
import os
import subprocess
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


EXPECTED = {"wpa3-mlo.pcapng.gz": {"unsupported": 2}, "wpa3-suiteb-192.pcapng.gz": {"ok": 1}}

fetch_samples.fetch()
keys = d.parse_keys()
for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    frames = list(fr.iter_frames(path))
    done, _ = hs.track(frames, keys)
    igtks, mc = gk.track_group(frames, done), gk.group_mgmt_ciphers(frames)
    got = collections.Counter(r for r in (gk.verify_bip(igtks, mc, f) for f in frames) if r is not None)
    ours_mme = sum(dec.find_mme(f.body) is not None for f in frames if f.h["type"] == 0)
    theirs = len(subprocess.run(["tshark", "-r", path, "-Y", "wlan.tag.number == 76", "-T", "fields", "-e", "frame.number"], capture_output=True, text=True).stdout.split())
    check(ours_mme == theirs, "%s：带 MME 的帧 我们 %d / tshark %d" % (name, ours_mme, theirs))
    check(dict(got) == EXPECTED.get(name, {}), "%s：校验结果 %s（表里 %s）" % (name, dict(got), EXPECTED.get(name, {})))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
