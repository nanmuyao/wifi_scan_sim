#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""用户直接给 TK（密钥表里的 "tk" 项，没有口令也没有握手）：我们的 decrypt_user_tk 与 tshark 用同一把 TK 解出的单播帧逐字节相同。
TK 取自 Wireshark 测试套件公布的值（tests/oracle/test_published_keys.py 用同一份文件）：
  wpa2-psk-mfp（CCMP-128）、wpa-ccmp-256、wpa-gcmp（GCMP-128）、wpa-gcmp-256：只有这一把 TK，tshark 解出所有单播帧；
  wpa-mlo-ccmp：Wireshark 测试里 TK 是用户给的。这个抓包没有关联帧，拿不到 MLD 地址，多链路的数据帧 tshark 和我们都解不开，
  只有受保护的解除认证帧（管理帧用链路地址）两边都解得开。
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decrypt80211 as dec  # noqa: E402
import decrypt_oracle as d  # noqa: E402
import fetch_samples  # noqa: E402
import frames80211 as fr  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


text = open(os.path.join(fetch_samples.EXTRAS_DIR, "suite_decryption.py"), encoding="utf-8").read()


def published_tk(name):
    m = re.search(r"capture_file\('%s'\)(.*?)(?=capture_file\(|\Z)" % re.escape(name), text, re.S)
    tks = re.findall(r'wlan\.analysis\.tk == "?([0-9a-fA-F]+)"?', m.group(1))
    return tks[0].lower() if tks else None


fetch_samples.fetch()
EXPECTED = {"wpa2-psk-mfp.pcapng.gz": 7, "wpa-ccmp-256.pcapng.gz": 8, "wpa-gcmp.pcapng.gz": 9, "wpa-gcmp-256.pcapng.gz": 8, "wpa-mlo-ccmp.pcapng.gz": 1}
for name, want in EXPECTED.items():
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    tk = "0e4dd207a9cefdf129eb9e17547080ec" if name == "wpa-mlo-ccmp.pcapng.gz" else published_tk(name)
    keys = [("tk", tk)]
    theirs = d.tshark_plain(path, keys)
    tks = dec.user_tks(keys)
    ours = {}
    for f in fr.iter_frames(path):
        r = dec.decrypt_user_tk(tks, f)
        if r is not None:
            ours[f.n] = r[0]
    same = sorted(ours) == sorted(theirs) and all(ours[n] == theirs[n]["plain"] for n in ours)
    check(same and len(ours) == want, "%s：只给一把 TK %s…：我们解出 %d 帧，tshark %d 帧，帧号和明文逐字节相同（表里 %d）" % (name, tk[:8], len(ours), len(theirs), want))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
