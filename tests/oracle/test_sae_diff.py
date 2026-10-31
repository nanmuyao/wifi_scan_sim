#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SAE 认证帧与 OWE 的 DH 参数元素：对照 tshark，并用公开值做独立检查。
  - SAE commit / confirm：消息类型、组、标量、元素、send-confirm、confirm 与 tshark 的字段逐个相同；
  - 每个 commit 的标量在 [1, n-1]，元素 (x, y) 在曲线上——不依赖 tshark，是对「标量 / 元素的偏移和长度对不对」的独立证明；
  - OWE 的 DH 公钥：组 / 公钥与 tshark 相同，公钥长度与组一致，x 在曲线上有对应的点。
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_samples  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import ie  # noqa: E402
from wifi80211 import sae  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def hx(s):
    return bytes.fromhex(s.replace(":", "")) if s else None


def tshark_rows(path, flt, fields):
    cmd = ["tshark", "-r", path, "-Y", flt, "-T", "fields"] + [x for f in ["frame.number"] + fields for x in ("-e", f)]
    rows = {}
    for line in subprocess.run(cmd, capture_output=True, text=True).stdout.split("\n"):
        if line:
            c = (line.split("\t") + [""] * (len(fields) + 1))[:len(fields) + 1]
            rows[int(c[0])] = c[1:]
    return rows


# 样例 -> (SAE commit 帧数, confirm 帧数, 其中 commit 带 H2E 状态 126 的帧数, OWE DH 元素帧数)
EXPECTED = {"owe-3-dh-groups.pcapng.gz": (0, 0, 0, 6), "owe.pcapng.gz": (0, 0, 0, 2), "wpa3-ft-sae-ext-key-group20.pcapng.gz": (2, 2, 2, 0),
            "wpa3-ft-sae-h2e.pcapng.gz": (2, 2, 2, 0), "wpa3-mlo.pcapng.gz": (2, 2, 2, 0), "wpa3-sae-ext-key-group21.pcapng.gz": (2, 2, 2, 0), "wpa3-sae.pcapng.gz": (2, 2, 0, 0)}
fetch_samples.fetch()
for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    sae_t = tshark_rows(path, "wlan.fixed.sae_message_type", ["wlan.fixed.sae_message_type", "wlan.fixed.finite_cyclic_group", "wlan.fixed.scalar",
                                                           "wlan.fixed.finite_field_element", "wlan.fixed.send_confirm", "wlan.fixed.confirm", "wlan.fixed.status_code"])
    owe_t = tshark_rows(path, "wlan.ext_tag.owe_dh_parameter.group", ["wlan.ext_tag.owe_dh_parameter.group", "wlan.ext_tag.owe_dh_parameter.public_key"])
    commits = confirms = h2e = owe = 0
    ok, group_seen = True, None
    for f in fr.iter_frames(path):
        h = f.h
        if h["type"] != 0 or h["protected"]:
            continue
        if h["subtype"] == 11:
            r = sae.parse_auth(f.body, group_seen)
            if r is None:
                ok = ok and f.n not in sae_t
                continue
            t = sae_t.get(f.n)
            ok = ok and t is not None and int(t[0]) == (1 if r["type"] == "commit" else 2) and int(t[6], 16) == r["status"]
            if r["type"] == "commit":
                commits += 1
                h2e += r["status"] == sae.STATUS_H2E
                group_seen = r["group"]
                ok = ok and int(t[1]) == r["group"] and hx(t[2]) == r["scalar"] and hx(t[3]) == r["element"] and r["scalar_ok"] is True and r["on_curve"] is True and r["extra"] is not None
            else:
                confirms += 1
                ok = ok and int(t[4]) == r["send_confirm"] and hx(t[5]) == r["confirm"]
        elif h["subtype"] in (0, 1, 2, 3):
            els, _ = ie.walk(f.body[ie.FIXED_LEN[h["subtype"]]:])
            dh = next((ie.decode_owe_dh(e.data) for e in els if e.id == 255 and e.ext == ie.EXT_OWE_DH), None)
            if dh is None:
                continue
            owe += 1
            t = owe_t.get(f.n)
            size = sae.GROUPS[dh["group"]][4]
            ok = ok and t is not None and int(t[0]) == dh["group"] and hx(t[1]) == dh["public"] and len(dh["public"]) == size and sae.x_on_curve(dh["group"], int.from_bytes(dh["public"], "big")) is True
    ok = ok and commits + confirms == len(sae_t) and owe == len(owe_t)
    want = EXPECTED.get(name, (0, 0, 0, 0))
    check(ok and (commits, confirms, h2e, owe) == want, "%s：SAE commit %d / confirm %d（H2E %d），OWE DH %d；与 tshark 一致、标量与元素合法（表里 %s）" % (name, commits, confirms, h2e, owe, want))
check(all(n in os.listdir(fetch_samples.SAMPLE_DIR) for n in EXPECTED), "表里的样例都在目录里（没列出的样例没有 SAE / OWE 元素，也核对过 tshark 同样没有）")
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
