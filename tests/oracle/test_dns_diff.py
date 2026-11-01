#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解密后的 DNS / mDNS：用我们解出来的明文（pipeline80211 + net80211 + dns80211），逐帧和 tshark 比
  id、QR、rcode、提问的名字与类型、各区记录个数，以及应答里的 A / AAAA / CNAME；
  每个样例里的 DNS 帧数、提问数、应答记录数固定成表。"""
import collections
import ipaddress
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decrypt_oracle as d  # noqa: E402
import fetch_samples  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import net  # noqa: E402
from wifi80211 import pipeline as pl  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


FIELDS = ["dns.id", "dns.flags.response", "dns.flags.rcode", "dns.qry.name", "dns.qry.type", "dns.count.answers", "dns.count.auth_rr", "dns.count.add_rr", "dns.a", "dns.aaaa", "dns.cname"]


def tshark_rows(path, keys):
    usable, _ = d.tshark_usable(keys)
    with d.key_env(usable) as env:
        cmd = ["tshark", "-r", path] + d.TSHARK_DECRYPT + ["-Y", "(dns || mdns) && wlan.fc.protected==1", "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=|", "-e", "frame.number"]
        for f in FIELDS:
            cmd += ["-e", f]
        out = subprocess.run(cmd, capture_output=True, text=True, env=env).stdout
    rows = {}
    for line in out.split("\n"):
        if line:
            c = (line.split("\t") + [""] * (len(FIELDS) + 1))[:len(FIELDS) + 1]
            rows[int(c[0])] = dict(zip(FIELDS, c[1:]))
    return rows


def split(s):
    return [x for x in s.split("|") if x]


def ours(q):
    ans = q["answers"] + q["authority"] + q["additional"]                  # tshark 的 dns.a / dns.aaaa / dns.cname 涵盖三个记录区（mDNS 探测把地址放在授权区）
    n_ans = len(q["answers"])
    return {"dns.id": "0x%04x" % q["id"], "dns.flags.response": "True" if q["response"] else "False", "dns.flags.rcode": str(q["rcode"]) if q["response"] else "",
            "dns.qry.name": [x["name"] for x in q["questions"]], "dns.qry.type": [str(x["type"]) for x in q["questions"]],
            "dns.count.answers": str(n_ans), "dns.count.auth_rr": str(len(q["authority"])), "dns.count.add_rr": str(len(q["additional"])),
            "dns.a": [x["data"] for x in ans if x["type"] == 1 and isinstance(x["data"], str)],
            "dns.aaaa": [str(ipaddress.ip_address(x["data"])) for x in ans if x["type"] == 28 and isinstance(x["data"], str)],
            "dns.cname": [x["data"] for x in ans if x["type"] == 5]}


def same(q, t):
    e = ours(q)
    for k in FIELDS:
        got = t[k]
        if isinstance(e[k], list):
            got = [str(ipaddress.ip_address(x)) for x in split(got)] if k == "dns.aaaa" else split(got)
        if e[k] != got:
            return k
    return None


EXPECTED = {
    "wpa-Induction.pcap.gz": (37, 71, 59, 16, 0),
    "wpa-ccmp-256.pcapng.gz": (1, 1, 0, 0, 0),
    "wpa3-sae-ext-key-group21.pcapng.gz": (2, 0, 4, 2, 2),          # tshark 加载不了 64 字节的 PMK，这两帧它解不开，靠校验和判断解对了
}
fetch_samples.fetch()
keys = d.parse_keys()
for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    res = pl.decrypt_capture(list(fr.iter_frames(path)), keys)
    ts = tshark_rows(path, keys)
    cnt, mine, bad = collections.Counter(), {}, []
    for n, v in res.items():
        for m in v["msdus"]:
            ds = net.describe(m)
            if ds and "dns" in ds["layers"]:
                mine[n] = ds["dns"]
                cnt["frames"] += 1
                cnt["questions"] += len(ds["dns"]["questions"])
                cnt["answers"] += len(ds["dns"]["answers"])
                cnt["responses"] += ds["dns"]["response"]
                k = same(ds["dns"], ts[n]) if n in ts else None
                if k:
                    bad.append((n, k))
    if cnt or ts:
        extra = sorted(set(mine) - set(ts))
        check(not bad and not (set(ts) - set(mine)), "%s：tshark 认出的 %d 个 DNS 帧我们都认出，且逐字段一致（不一致 %s，tshark 独有 %s）" % (name, len(ts), bad[:3], sorted(set(ts) - set(mine))[:5]))
        row = (cnt["frames"], cnt["questions"], cnt["answers"], cnt["responses"], len(extra))
        check(row == EXPECTED.get(name), "%s：帧 / 提问 / 应答记录 / 响应帧 / 只有我们解出的帧 = %s（表里 %s）" % (name, row, EXPECTED.get(name)))
check(sorted(EXPECTED) == sorted(n for n in os.listdir(fetch_samples.SAMPLE_DIR) if n in EXPECTED), "表里的样例都在目录里")
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
