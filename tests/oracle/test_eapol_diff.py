#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""eapol.parse 在 24 个样例的全部 EAPOL-Key 帧上与 tshark 逐字段对照（不需要密钥，不解密）。需要 tshark 和样例。"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "oracle"))
from wifi80211 import eapol  # noqa: E402
import fetch_samples  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


FIELDS = [("version", "eapol.version"), ("type", "eapol.type"), ("length", "eapol.len"), ("descriptor", "eapol.keydes.type"),
          ("key_info", "wlan_rsna_eapol.keydes.key_info"), ("key_length", "eapol.keydes.key_len"),
          ("replay_counter", "eapol.keydes.replay_counter"), ("nonce", "wlan_rsna_eapol.keydes.nonce"), ("rsc", "wlan_rsna_eapol.keydes.rsc"),
          ("key_id", "wlan_rsna_eapol.keydes.id"), ("mic", "wlan_rsna_eapol.keydes.mic"), ("data_length", "wlan_rsna_eapol.keydes.data_len"),
          ("data", "wlan_rsna_eapol.keydes.data"), ("message", "wlan_rsna_eapol.keydes.msgnr")]


def tshark_eapol(path):
    cmd = ["tshark", "-r", path, "-Y", "eapol.type == 3", "-T", "fields", "-e", "frame.number"]
    for _, f in FIELDS:
        cmd += ["-e", f]
    rows = {}
    for line in subprocess.run(cmd, capture_output=True, text=True).stdout.split("\n"):
        if line:
            p = line.split("\t") + [""] * (len(FIELDS) + 1)
            rows[int(p[0])] = dict(zip([n for n, _ in FIELDS], p[1:]))
    return rows


def ours(path):
    out = {}
    for f in fr.iter_frames(path):
        raw = fr.eapol_payload(f)
        if raw is not None:
            e = eapol.parse(raw)
            if e is not None:
                out[f.n] = e
    return out


def same(name, want, e):
    """tshark 的字符串 want 与我们解出的 e 里的同名字段比较。"""
    if name in ("version", "type", "length", "descriptor", "key_length", "replay_counter", "data_length"):
        v = e["descriptor"] if name == "descriptor" else e[name]
        return int(want, 0) == v
    if name == "key_info":
        return int(want, 0) == e["key_info"]["raw"]
    if name == "message":
        return want == "" or int(want) == e.get("message")
    key = {"nonce": "nonce", "rsc": "rsc", "key_id": "key_id", "mic": "mic", "data": "data"}[name]
    return want.replace(":", "") == e[key].hex()


fetch_samples.fetch()
total = 0
bad_fields = {}
needs_akm = []          # 长度关系推不出 MIC 长度的帧：必须由认证方式给定 mic_len
for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    t, o = tshark_eapol(path), ours(path)
    if sorted(t) != sorted(o):
        check(False, "%s：EAPOL-Key 帧集合不同（tshark %s，我们 %s）" % (name, sorted(t), sorted(o)))
        continue
    total += len(t)
    for n, row in t.items():
        e = o[n]
        if not same("mic", row["mic"], e):
            needs_akm.append((name, n))
            mic_len = len(row["mic"].replace(":", "")) // 2           # 用 tshark 从认证方式得到的 MIC 长度重解
            for f in fr.iter_frames(path):
                if f.n == n:
                    e = eapol.parse(fr.eapol_payload(f), mic_len=mic_len)
        for fname, want in row.items():
            if want == "" and fname != "message" and fname not in ("data", "key_id", "rsc"):
                bad_fields.setdefault(fname, []).append((name, n, "tshark 没给值"))
            elif not same(fname, want, e):
                bad_fields.setdefault(fname, []).append((name, n, want, e.get(fname)))
check(total == 109, "24 个样例共 %d 个 EAPOL-Key 帧，两边帧集合一致（应为 109）" % total)
check(needs_akm == [("wpa3-suiteb-192.pcapng.gz", 44)],
      "只有 1 帧靠长度关系推不出 MIC 长度（%s）：Suite-B 192 的第一个 M1，Key Data Length 写 0 但尾部多 22 字节；给定 mic_len=24 后与 tshark 一致" % needs_akm)
for fname, _ in FIELDS:
    check(fname not in bad_fields, "字段 %s 在全部帧上一致%s" % (fname, ("：不一致 %d 处，例如 %s" % (len(bad_fields[fname]), bad_fields[fname][:2])) if fname in bad_fields else ""))

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
