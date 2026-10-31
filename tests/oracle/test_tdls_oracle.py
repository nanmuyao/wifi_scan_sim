#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TDLS 对照 tshark（wpa-test-decode-tdls）：
  - 我们从解密后的 Setup Request / Response / Confirm 里推出的 TPK-TK 等于 tshark 打出的那把额外的 TK（握手测试里「tshark 多出 1 个 TK」就是它）；
  - Response 和 Confirm 的 FTE MIC 都用 TPK-KCK 验证通过（第二把尺子，不依赖 tshark）；
  - 两个对端之间直接互发的 2 个数据帧，我们用 TPK-TK 解出的明文与 tshark 逐字节相同，IPv4 头校验和吻合。
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
import net80211 as net  # noqa: E402
import pipeline80211 as pl  # noqa: E402
import tdls80211 as t  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


fetch_samples.fetch()
keys = d.parse_keys()
path = os.path.join(fetch_samples.SAMPLE_DIR, "wpa-test-decode-tdls.pcap.gz")
frames = list(fr.iter_frames(path))
res = pl.decrypt_capture(frames, keys)
tk = t.track({n: v["msdus"] for n, v in res.items() if v["how"] != "tdls"})
check(len(tk) == 1, "解出一条 TDLS 链路")
k = tk[0]
check(k.frames["response_mic_ok"] and k.frames["confirm_mic_ok"] and (k.frames["response"], k.frames["confirm"]) == (19, 21), "Setup Response（帧 19）和 Confirm（帧 21）的 MIC 都通过")
usable, _ = d.tshark_usable(keys)
with d.key_env(usable) as env:
    out = subprocess.run(["tshark", "-r", path] + d.TSHARK_DECRYPT + ["-T", "fields", "-e", "wlan.analysis.tk"], capture_output=True, text=True, env=env).stdout
theirs = {l.replace(":", "") for l in out.split("\n") if l}
check(k.tk.hex() in theirs, "TPK-TK %s… 就是 tshark 打出的 TK 之一（它共打出 %d 把）" % (k.tk.hex()[:8], len(theirs)))
tplain = d.tshark_plain(path, keys)
direct = {n: v for n, v in res.items() if v["how"] == "tdls"}
check(sorted(direct) == [23, 24], "对端直连的帧：%s" % sorted(direct))
for n, v in sorted(direct.items()):
    check(n in tplain and tplain[n]["plain"] == v["msdus"][0], "帧 %d：明文与 tshark 逐字节相同" % n)
    ds = net.describe(v["msdus"][0])
    check(ds is not None and ds["layers"][:2] == ["snap", "ipv4"] and all(c is True for c in ds["checks"]), "帧 %d：%s，校验和吻合" % (n, "/".join(ds["layers"])))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
