#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wireshark 测试套件自己公布的答案：每个样例的测试里用 `wlan.analysis.tk == …` / `wlan.analysis.gtk == …` 过滤，
这些十六进制就是它的作者认定的 TK 和 GTK。用它们当最后一把尺子——它不依赖我们装的 tshark 版本（tshark 4.4 解不开的 FT 漫游、MLO、64 字节 PMK 的样例也有答案）：
  - 公布的每个 TK，必须是我们某个握手（含重新握手、FT 漫游）推出的 TK；
  - 公布的每个 GTK，必须是我们从 M3 / G1 / FT 响应里解出的某个 GTK。
wpa-mlo-ccmp 公布的 TK 是用户直接给的（密钥表里的 tk 项），抓包里没有握手可推，算作已知输入。
（TKIP 的 TK 是 32 字节，公布的只有前 16 字节，按前缀比；公布值比我们长或短时按较短的前缀比。）
没有被公布的、我们多推出来的密钥不算错（Wireshark 的断言不一定列全）。
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wifi80211 import decrypt as dec  # noqa: E402
import decrypt_oracle as d  # noqa: E402
import fetch_samples  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import groupkeys as gk  # noqa: E402
from wifi80211 import handshake as hs  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


SUITE = os.path.join(fetch_samples.EXTRAS_DIR, "suite_decryption.py")


def published():
    """{样例文件名: (TK 集合, GTK 集合)}：从 suite_decryption.py 里 capture_file('…') 之后的 -Y 过滤器里取。"""
    text = open(SUITE, encoding="utf-8").read()
    out = {}
    for m in re.finditer(r"capture_file\('([^']+)'\)(.*?)(?=capture_file\(|\Z)", text, re.S):
        name, rest = m.group(1), m.group(2)
        flt = re.search(r"'-Y',\s*'([^']*)'", rest)
        if not flt:
            continue
        tks, gtks = out.setdefault(name, (set(), set()))
        tks.update(x.lower() for x in re.findall(r'wlan\.analysis\.tk == "?([0-9a-fA-F]+)"?', flt.group(1)))
        gtks.update(x.lower() for x in re.findall(r'wlan\.analysis\.gtk == "?([0-9a-fA-F]+)"?', flt.group(1)))
    return out


def has(ours, want):
    return any(o.startswith(want) or want.startswith(o) for o in ours)


fetch_samples.fetch()
keys = d.parse_keys() + [("tk", "0e4dd207a9cefdf129eb9e17547080ec")]
pub = published()
n_tk = n_gtk = 0
for name, (tks, gtks) in sorted(pub.items()):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    if not os.path.exists(path):
        continue
    frames = list(fr.iter_frames(path))
    done, _ = hs.track(frames, keys)
    ours_tk = {h.tk.hex() for h in done} | {k.hex() for k in dec.user_tks(keys)}       # wpa-mlo-ccmp 的 TK 是用户直接给的，不是推出来的
    ours_gtk = {g.gtk.hex() for g in gk.track_group(frames, done) if g.gtk}
    missing_tk = {t for t in tks if not has(ours_tk, t)}
    missing_gtk = {g for g in gtks if not has(ours_gtk, g)}
    n_tk += len(tks) - len(missing_tk)
    n_gtk += len(gtks) - len(missing_gtk)
    check(not missing_gtk and not missing_tk,
          "%s：公布的 TK %d 个、GTK %d 个，我们都推出来了%s" % (name, len(tks), len(gtks), "" if not (missing_tk or missing_gtk) else "（缺：TK %s GTK %s）" % (sorted(missing_tk), sorted(missing_gtk))))
check(len(pub) >= 20, "从 Wireshark 的测试里读到 %d 个样例的公布值" % len(pub))
print("\n共核对 %d 个公布的 TK、%d 个公布的 GTK" % (n_tk, n_gtk))
print("结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
