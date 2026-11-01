#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""抓包质量的序号统计：对 24 个样例，用 tshark 的字段（wlan.ta / wlan.ra / wlan.seq / wlan.frag / wlan.fc.retry / wlan.qos.tid / wlan.fc.type）
在测试里独立重算每个序号计数器的 帧数 / 听到 / 缺口 / 断档 / 断档帧数 / 重复 / 乱序 / 重传，和 wifi80211/health.py 逐个计数器比较（"ra" 与 "tid" 两种分法各比一次）。
这检查的是字段解析和记账（谁是发送方、序号、分片、重传位、QoS 的 TID），不检查「缺口等于丢帧」这个语义——那一条靠 tests/test_health.py 和本文件末尾的真实样例「删帧」实验。
末尾：在 wpa-Induction 上，从帧数最多的那个计数器里随机删掉一部分（中间的、不是重传的）帧，缺口数必须正好多出删掉的个数。"""
import collections
import os
import random
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_samples  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import health  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


FIELDS = ["frame.number", "wlan.fc.type", "wlan.ta", "wlan.ra", "wlan.seq", "wlan.frag", "wlan.fc.retry", "wlan.qos.tid"]


def tshark_rows(path):
    cmd = ["tshark", "-r", path, "-Y", "(wlan.fc.type == 0 || wlan.fc.type == 2) && wlan.seq", "-T", "fields", "-E", "occurrence=f"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    rows = {}
    for line in out.split("\n"):
        if line:
            c = (line.split("\t") + [""] * len(FIELDS))[:len(FIELDS)]
            rows[int(c[0])] = dict(zip(FIELDS, c))
    return rows


def group(mac):
    return bool(int(mac[:2], 16) & 1)


def reference(rows, ns, by):
    """独立的实现：只用 tshark 的字段，只处理 ns 里的帧（我们也解析了的）。-> 各计数器的 (帧数, 听到, 缺口, 断档, 断档帧数, 重复, 乱序, 重传) 排序后的列表。"""
    state = {}
    run = collections.Counter()
    for n in sorted(ns):
        r = rows[n]
        ta, ra, sn, retry = r["wlan.ta"], r["wlan.ra"], int(r["wlan.seq"]), int(r["wlan.fc.retry"] in ("True", "1"))
        tid = r["wlan.qos.tid"]
        if r["wlan.fc.type"] == "2" and tid != "":
            tid = int(tid)
            if group(ra):
                key = ("g", ta, tid)
            else:
                key = ("q", ta, ra if by == "ra" else None, tid)
        else:
            key = ("t", ta)
        s = state.setdefault(key, {"last": None, "frames": 0, "seen": 0, "missing": 0, "outages": 0, "outage_frames": 0, "dup": 0, "reordered": 0, "retries": 0})
        s["frames"] += 1
        s["retries"] += retry
        if s["last"] is None:
            s["last"], s["seen"] = sn, 1
            continue
        d = (sn - s["last"]) % 4096
        if d == 0:
            s["dup"] += 1
            run[key] = 0
        elif d > 2048:
            s["reordered"] += 1
            run[key] += 1
            if run[key] >= health.RESYNC_AFTER:
                s["last"], run[key] = sn, 0
                s["seen"] += 1
        else:
            run[key] = 0
            s["seen"] += 1
            if d - 1 > health.MAX_LOSS_GAP:
                s["outages"] += 1
                s["outage_frames"] += d - 1
            else:
                s["missing"] += d - 1
            s["last"] = sn
    # "tid" 分法只对 QoS 单播有意义：reference 里 ra=None 的键就是它；"ra" 分法下不会出现 None
    return sorted((s["frames"], s["seen"], s["missing"], s["outages"], s["outage_frames"], s["dup"], s["reordered"], s["retries"]) for s in state.values())


def mine(frames, by):
    seq = health.sequence(frames, by)
    return sorted((c["frames"], c["seen"], c["missing"], c["outages"], c["outage_frames"], c["dup"], c["reordered"], c["retries"]) for c in seq["counters"].values())


# 每个样例：(计数器个数, 听到的 MSDU 总数, 缺口总数, 断档处数, 只有我们有的帧, 只有 tshark 有的帧)（"ra" 分法）。数字是这次跑出来的，由 tshark 的独立重算逐个计数器对上之后写进表里。
# 只有 tshark 有的帧：wpa-Induction 里 3 个校验和不对的帧，tshark 认得出序号，我们不信校验和不对的头，统一排除。
EXPECTED = {
    "owe-3-dh-groups.pcapng.gz": (5, 20, 44, 0, 0, 0),
    "owe.pcapng.gz": (2, 34, 102, 0, 0, 0),
    "wep.pcapng.gz": (2, 17, 7, 1, 0, 0),
    "wpa-Induction.pcap.gz": (3, 693, 200, 0, 0, 3),
    "wpa-ccmp-256.pcapng.gz": (6, 30, 8, 3, 0, 0),
    "wpa-eap-tls.pcap.gz": (3, 79, 4, 0, 0, 0),
    "wpa-gcmp-256.pcapng.gz": (5, 29, 20, 3, 0, 0),
    "wpa-gcmp.pcapng.gz": (5, 30, 8, 2, 0, 0),
    "wpa-mlo-ccmp.pcapng.gz": (4, 5, 4, 0, 0, 0),
    "wpa-test-decode-mgmt.pcap.gz": (4, 9, 8, 0, 0, 0),
    "wpa-test-decode-tdls.pcap.gz": (12, 24, 53, 0, 0, 0),
    "wpa-test-decode.pcap.gz": (7, 3945, 1465, 510, 0, 0),
    "wpa1-gtk-rekey.pcapng.gz": (2, 96, 30, 2, 0, 0),
    "wpa2-ft-eap.pcapng.gz": (5, 35, 24, 1, 0, 0),
    "wpa2-ft-psk.pcapng.gz": (7, 22, 36, 0, 0, 0),
    "wpa2-psk-ccmp-tkip.pcapng.gz": (6, 21, 54, 1, 0, 0),
    "wpa2-psk-mfp.pcapng.gz": (6, 18, 36, 1, 0, 0),
    "wpa3-ft-sae-ext-key-group20.pcapng.gz": (7, 22, 2, 0, 0, 0),
    "wpa3-ft-sae-h2e.pcapng.gz": (6, 26, 39, 2, 0, 0),
    "wpa3-mlo.pcapng.gz": (9, 19, 34, 0, 0, 0),
    "wpa3-sae-ext-key-group21.pcapng.gz": (5, 13, 1, 1, 0, 0),
    "wpa3-sae.pcapng.gz": (6, 140, 9, 0, 0, 0),
    "wpa3-suiteb-192.pcapng.gz": (4, 41, 0, 0, 0, 0),
    "wpa_ptk_extended_key_id.pcap.gz": (6, 57, 0, 0, 0, 0),
}

fetch_samples.fetch()
names = sorted(os.listdir(fetch_samples.SAMPLE_DIR))
table = {}
for name in names:
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    frames = list(fr.iter_frames(path))
    rows = tshark_rows(path)
    ours_ns = {f.n for f in frames if f.h["type"] in (0, 2) and f.fcs_ok is not False}                  # 校验和不对的帧不参与序号统计（tshark 对它们也给不出序号）
    only_ours, only_tshark = sorted(ours_ns - set(rows)), sorted(set(rows) - ours_ns)
    ns = ours_ns & set(rows)
    framesel = [f for f in frames if f.n in ns or f.fcs_ok is False]                   # 坏帧还是喂进去，由 health 自己跳过
    bad = []
    for by in ("ra", "tid"):
        a, b = mine(framesel, by), reference(rows, ns, by)
        if a != b:
            bad.append(by)
    check(not bad, "%s：序号计数器逐个和 tshark 字段的独立重算一致（%d 个帧；不一致的分法 %s；只有我们有 %s，只有 tshark 有 %s）" % (name, len(ns), bad, only_ours[:3], only_tshark[:3]))
    seq = health.sequence(framesel, "ra")
    cs = list(seq["counters"].values())
    table[name] = (len(cs), sum(c["seen"] for c in cs), sum(c["missing"] for c in cs), sum(c["outages"] for c in cs), len(only_ours), len(only_tshark))

check(table == EXPECTED, "每个样例的 (计数器, 听到, 缺口, 断档, 只有我们有的帧, 只有 tshark 有的帧) 和表一致%s" % ("" if table == EXPECTED else "：不同的 %s" % [(n, table[n], EXPECTED.get(n)) for n in table if table[n] != EXPECTED.get(n)][:3]))

# ---- 真实样例上的「删帧」实验：缺口数必须正好多出删掉的个数 ----
print("== 在真实样例上删帧：缺口数 = 删掉的个数 ==")
path = os.path.join(fetch_samples.SAMPLE_DIR, "wpa-Induction.pcap.gz")
frames = list(fr.iter_frames(path))
base = health.sequence(frames, "ra")
busiest = max(base["counters"], key=lambda k: base["counters"][k]["frames"])
ctr = base["counters"][busiest]
idx = [i for i, f in enumerate(frames) if f.h["type"] in (0, 2) and health._keys(f.h)[0] == busiest]
# 只删「中间的、不是重传、也不和上一个同序号」的帧；第一个和最后一个不删（删了看不出来）
cand = [i for k, i in enumerate(idx) if 0 < k < len(idx) - 1 and not frames[i].h["retry"] and frames[i].h["seq_num"] != frames[idx[k - 1]].h["seq_num"] and frames[i].h["seq_num"] != frames[idx[k + 1]].h["seq_num"]]
rng = random.Random(20261102)
for frac in (0.05, 0.10, 0.20):
    pick = set(rng.sample(cand, int(len(cand) * frac)))
    kept = [f for i, f in enumerate(frames) if i not in pick]
    after = health.sequence(kept, "ra")["counters"][busiest]
    check(after["missing"] - ctr["missing"] == len(pick) and after["outages"] == ctr["outages"],
          "删掉这个计数器里 %d%% 的帧（%d 个，共 %d 个候选）：缺口从 %d 增加到 %d，正好多出 %d 个，断档数不变" % (round(frac * 100), len(pick), len(cand), ctr["missing"], after["missing"], len(pick)))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
