#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""密钥与解密层的日志和诊断（handshake / groupkeys / decrypt / pipeline / keyfile / tdls）：
  1. 真实样例 wpa-Induction：握手、组密钥、解密结果的日志行与诊断数字；
  2. 合成场景：口令不对、只有 M1、根本没有握手、不知道 SSID、SSID 写错、用户直接给 TK、握手之后换了密钥、帧早于握手、组播帧没有组密钥——
     每个场景检查日志的级别和内容、pipeline.diagnose 的数字、pipeline.explain 给出的那一句；
  3. 泄露检查：在 wpa-Induction / wpa2-ft-psk / wpa-ccmp-256 上以 TRACE 级别跑完整条链，所有日志（过滤器之前的原始消息）里不能出现口令、PMK、KCK / KEK / TK、GTK；
     经过 logs.setup 的过滤器写出的文件里也不能有 32 个以上十六进制字符连在一起；
  4. 不改行为：开了日志和没开日志，decrypt_capture 的结果相同。"""
import hashlib
import logging
from collections import namedtuple
import os
import re
import struct
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "oracle"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
import aead_build as ab  # noqa: E402
import decrypt_oracle as d  # noqa: E402
import fetch_samples  # noqa: E402
import synth  # noqa: E402
from wifi80211 import decrypt as dec  # noqa: E402
from wifi80211 import eapol, keyfile, logs  # noqa: E402
from wifi80211 import groupkeys as gk  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import handshake as hs  # noqa: E402
from wifi80211 import pipeline as pl  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


class Collect(logging.Handler):
    """收集过滤器之前的原始日志记录。"""

    def __init__(self):
        super().__init__(logging.NOTSET)
        self.records = []

    def emit(self, record):
        self.records.append((record.levelname, record.name, record.getMessage()))

    def texts(self, level=None, name=None):
        return [m for lv, nm, m in self.records if (level is None or lv == level) and (name is None or nm.endswith(name))]


class capture:
    def __init__(self, level=logging.DEBUG):
        self.level, self.h = level, Collect()

    def __enter__(self):
        self.root = logging.getLogger("wifi80211")
        self.saved = (self.root.level, self.root.propagate)
        self.root.setLevel(self.level)
        self.root.addHandler(self.h)
        return self.h

    def __exit__(self, *a):
        self.root.removeHandler(self.h)
        self.root.setLevel(self.saved[0])


EAPOL_INDUCTION = {"1": 1, "2": 1, "3": 1, "4": 1}
# ---------------------------------------------------------------------------
print("== 真实样例 wpa-Induction ==")
fetch_samples.fetch()
KEYS = d.parse_keys()
path = os.path.join(fetch_samples.SAMPLE_DIR, "wpa-Induction.pcap.gz")
frames = list(fr.iter_frames(path))
with capture() as cap:
    stats = pl.diagnose(frames, KEYS)
info = cap.texts("INFO")
check(any("握手：看到 1 对 (AP, 设备)，1 对验证通过，共推出 1 个握手" in m for m in info), "INFO：1 对 (AP, 设备)，1 对验证通过，推出 1 个握手")
check(any("组密钥：看到 1 条 M3 / G1，装上 1 个组密钥，没装上 0 条" in m for m in info), "INFO：组密钥看到 1 条 M3，装上 1 个")
check(any("受保护的数据帧 280 个，解开 276 个（group 73、pairwise 203），没解开 4 个" in m for m in info), "INFO：280 个受保护的数据帧，解开 276 个（group 73、pairwise 203）")
check(any(m.startswith("解密：737 个帧，密钥 wep 1 把、wpa-pwd 3 把、wpa-psk 13 把、msk 1 把") for m in info), "INFO：帧数和密钥的类型与把数（不含值）")
dbg = cap.texts("DEBUG")
check(any("握手验证通过（AP 00:0c:41:82:b2:55，设备 00:0d:93:82:36:3a，AKM 2，CCMP-128，MIC hmac-sha1，M1=帧 87，试了 12 个候选密钥）" in m for m in dbg), "DEBUG：握手通过的细节（第 89 帧，M1 是第 87 帧，试了 12 个候选）")
check(any('SSID "Coherer"）：M1 帧 87；M2 帧 89；M3 帧 92；M4 帧 94；结果 验证通过' in m for m in dbg), "DEBUG：这一对的 M1–M4 帧号和 SSID")
check(any("M3 里装上 GTK（AP 00:0c:41:82:b2:55，序号 2）" in m for m in dbg), "DEBUG：第 92 帧 M3 装上 GTK 序号 2（不含密钥）")
check(any("3 个（例：帧 3、26、47）" in m and "之后才装上" in m for m in dbg) and any("1 个（例：帧 776）" in m and "没有这对" in m for m in dbg), "DEBUG：没解开的原因按类汇总，带例子帧号")
check(stats["undecrypted"] == {"gtk_after_frame": 3, "no_handshake": 1} and stats["protected_data"] == 280 and stats["decrypted"] == 276, "诊断数字：没解开 4 个 = 3 个早于组密钥 + 1 个另一台设备（没有握手）")
check(stats["handshake"]["pairs"][0]["state"] == "verified" and stats["handshake"]["pairs"][0]["msgs"] == {1: [87], 2: [89], 3: [92], 4: [94]} and stats["handshake"]["ssids"] == {"00:0c:41:82:b2:55": "Coherer"}, "诊断：握手状态、M1–M4 的帧号、SSID")
check(stats["group"] == {"m3_g1": 1, "installed": 1, "failed": {}}, "诊断：组密钥 1 条 M3 → 装上 1 个")
check(stats["handshake"]["verified"] == 1 and stats["handshake"]["skipped"] == [] and stats["handshake"]["eapol"] == EAPOL_INDUCTION and stats["by_how"] == {"pairwise": 203, "group": 73}
      and stats["keys"] == {"wep": 1, "wpa-pwd": 3, "wpa-psk": 13, "msk": 1} and stats["frames"] == 737 and stats["user_tks"] == 0 and stats["wep_keys"] == 1, "诊断：握手数、EAPOL 报文个数、解开方式、密钥类型和把数、帧数")
check(not cap.texts("WARNING"), "没有 WARNING（只有 4 个没解开，不到一半）")
lines = pl.explain(stats)
check(len(lines) == 2 and "00:0d:1d:06:e0:f2" in lines[0] and "没有这一对的握手" in lines[0] and "3 个组播 / 广播帧没解开" in lines[1], "explain：另一台设备没握手；3 个组播帧早于组密钥")

# ---------------------------------------------------------------------------
print("== 合成场景 ==")
AP, STA = bytes.fromhex("02aabbccdd01"), bytes.fromhex("02aabbccdd02")
APM, STAM = ":".join("%02x" % b for b in AP), ":".join("%02x" % b for b in STA)
AN, SN = bytes([7]) * 32, bytes([9]) * 32
SNAP = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"


def ie_(i, data):
    return bytes([i, len(data)]) + data


def eapol_key(ki, nonce, replay, mic=bytes(16), data=b"", desc=2):
    body = bytes([desc]) + struct.pack(">HHQ", ki, 16, replay) + nonce + bytes(16) + bytes(8) + bytes(8) + mic + struct.pack(">H", len(data)) + data
    return bytes([2, 3]) + struct.pack(">H", len(body)) + body


RSN = ie_(48, struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac\x04" + struct.pack("<H", 1) + b"\x00\x0f\xac\x02" + struct.pack("<H", 0))
LLC = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"


def with_addrs(a1, a2, a3, fn):
    old = (synth.A1, synth.A2, synth.A3)
    synth.A1, synth.A2, synth.A3 = a1, a2, a3
    try:
        return fn()
    finally:
        synth.A1, synth.A2, synth.A3 = old


def pmk_of(pw, ssid):
    return hs.pmk_from_passphrase(pw, ssid)


def tk_of(pw, ssid):
    return hs.derive_ptk(pmk_of(pw, ssid), AP, STA, AN, SN, "sha1", 16, 16, 16)[2]


def beacon(ssid=b"HomeNet"):
    return with_addrs(b"\xff" * 6, AP, AP, lambda: synth.frame(0, 8, body=bytes(12) + ie_(0, ssid) + RSN))


def m1():
    return with_addrs(STA, AP, AP, lambda: synth.frame(2, 0, 0, 1, body=LLC + eapol_key(0x0088 | 0x0008 | 2, AN, 1)))


def m2(pw="password", ssid=b"HomeNet"):
    kck = hs.derive_ptk(pmk_of(pw, ssid), AP, STA, AN, SN, "sha1", 16, 16, 16)[0]
    raw = eapol.zero_mic(eapol_key(0x0100 | 0x0008 | 2, SN, 1, data=RSN), 16)
    mic = hs.compute_mic("hmac-sha1", kck, raw, 16)
    raw = raw[:81] + mic + raw[97:]
    return with_addrs(AP, STA, AP, lambda: synth.frame(2, 0, 1, 0, body=LLC + raw))


def data_up(tk, pn):                                   # 设备 -> AP，CCMP-128
    ab.A2, ab.A3 = STA, AP
    return ab.build("CCMP-128", tk, pn, SNAP + b"x" * 24, a1=AP, qos=0, to_ds=1, from_ds=0)


def data_down(tk, pn):                                 # AP -> 设备
    ab.A2, ab.A3 = AP, AP
    return ab.build("CCMP-128", tk, pn, SNAP + b"y" * 24, a1=STA, qos=0, to_ds=0, from_ds=1)


def group_down(tk, pn):                                # AP -> 组播
    ab.A2, ab.A3 = AP, AP
    return ab.build("CCMP-128", tk, pn, SNAP + b"z" * 24, a1=bytes.fromhex("01005e000001"), qos=0, to_ds=0, from_ds=1)


def scenario(frames_raw, keys):
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "t.pcap")
        synth.write_pcap(p, frames_raw)
        fl = list(fr.iter_frames(p))
    with capture() as cap:
        st = pl.diagnose(fl, keys)
    return st, cap, pl.explain(st)


GOOD = tk_of("password", b"HomeNet")
KEY = [("wpa-pwd", "password")]

# a. 口令不对
st, cap, ex = scenario([beacon(), m1(), m2(), data_up(GOOD, 1), data_down(GOOD, 2), data_up(GOOD, 3)], [("wpa-pwd", "wrongpass1")])
pair = st["handshake"]["pairs"][0]
check(pair["state"] == "mic_mismatch" and pair["candidates"] == 1 and pair["mic_fail"] == 1 and st["decrypted"] == 0 and st["protected_data"] == 3 and st["undecrypted"] == {"no_handshake": 3}, "口令不对：状态 mic_mismatch，试了 1 个候选，3 个帧都没解开（没有握手）")
w = cap.texts("WARNING", "handshake")
check(len(w) == 1 and "M2 的 MIC 和 1 个候选密钥都对不上" in w[0] and "口令输错" in w[0] and "SSID" in w[0] and "HomeNet" in w[0] and "wrongpass1" not in w[0], "WARNING 一条：MIC 对不上，列出可能的原因，带 SSID，不带口令")
check(any("一半以上的受保护数据帧没解开（3 / 3），主要原因：抓包里没有这对" in m for m in cap.texts("WARNING", "pipeline")), "WARNING：一半以上没解开，说出主要原因")
check(any("握手 MIC 对不上" in l and "试了 1 个候选密钥" in l and "口令输错" in l for l in ex), "explain：握手 MIC 对不上 → 核对口令和 SSID")
check(not any("整个抓包里没有找到四次握手" in l for l in ex), "explain：不会说「没有握手」（握手报文是有的，是密钥不对）")
check(not any("但抓包里没有这一对的握手" in l for l in ex) and any("共推出 0 个握手（含重新握手 / FT 漫游），1 条被跳过" in m for m in cap.texts("INFO", "handshake")), "explain：这一对已经有说法，不再重复说「没有这一对的握手」；INFO 里数出 1 条被跳过")

# b. 只有 M1
st, cap, ex = scenario([beacon(), m1(), data_up(GOOD, 1)], KEY)
check(st["handshake"]["pairs"][0]["state"] == "only_m1" and st["handshake"]["pairs"][0]["msgs"] == {1: [2], 2: [], 3: [], 4: []}, "只有 M1：状态 only_m1，M1 在第 2 帧")
check(any("只抓到 M1（帧 2），没抓到 M2" in m for m in cap.texts("WARNING", "handshake")), "WARNING：只抓到 M1")
check(any("只抓到 M1（帧 2），没抓到 M2" in l and "信道" in l for l in ex), "explain：只抓到 M1 → 让设备重连，核对信道")

# c. 完全没有握手
st, cap, ex = scenario([beacon(), data_up(GOOD, 1), data_down(GOOD, 2)], KEY)
check(st["handshake"]["pairs"] == [] and st["handshake"]["eapol"] == {} and st["undecrypted"] == {"no_handshake": 2}, "完全没有握手：没有任何 (AP, 设备) 对，没有 EAPOL 报文")
check(any("整个抓包里没有找到四次握手的 EAPOL 报文" in m for m in cap.texts("INFO", "handshake")), "INFO：整个抓包里没有找到四次握手")
check(ex[0].startswith("整个抓包里没有找到四次握手的报文（EAPOL）") and "断开重连" in ex[0] and "设备在抓包开始前就已连上" in ex[1], "explain：没有握手 → 开始抓包之后让设备重连；并列出有帧但没握手的这一对")

# d. 不知道 SSID / SSID 写错
st, cap, ex = scenario([m1(), m2(), data_up(GOOD, 1)], KEY)
p = st["handshake"]["pairs"][0]
check(p["state"] == "no_candidates" and p["no_candidates_why"] == "no_ssid" and p["ssid"] is None, "没有信标：不知道 SSID，口令没法用，状态 no_candidates / no_ssid")
check(any("密钥里的口令没写 SSID，而抓包里没有信标" in m and "口令:SSID" in m for m in cap.texts("WARNING", "handshake")), "WARNING：口令没写 SSID 又没有信标 → 建议写成 口令:SSID")
check(any("不知道这个 AP 的 SSID" in l and "没有可用的候选密钥" in l for l in ex), "explain：不知道 SSID")
check(any("有 M2 但没有可用的候选密钥：不知道这个 AP 的 SSID" in m for m in cap.texts("WARNING", "handshake")), "WARNING：有 M2 但没有可用的候选密钥，说出原因")
st, cap, ex = scenario([beacon(), m1(), m2(), data_up(GOOD, 1)], [("wpa-pwd", "password:OtherNet")])
check(st["handshake"]["pairs"][0]["state"] == "mic_mismatch" and st["handshake"]["pairs"][0]["ssid"] == "HomeNet", "密钥里写了别的 SSID（password:OtherNet）：试了但 MIC 不对，抓到的 SSID 是 HomeNet")
check(any("SSID 不对" in l and "HomeNet" in l for l in ex), "explain：SSID 不对，并带出抓包里的 SSID")
st, cap, ex = scenario([beacon(), m1(), m2(), data_up(GOOD, 1)], [("wep", "1234567890")])
check(st["handshake"]["pairs"][0]["state"] == "no_candidates" and st["handshake"]["pairs"][0]["no_candidates_why"] == "no_matching_key" and any("没有适用于这种认证方式的密钥" in l for l in ex), "只给了 WEP 密钥：没有适用于 PSK 的候选 → no_matching_key")

# e. 用户直接给 TK
st, cap, ex = scenario([data_up(GOOD, 1), data_down(GOOD, 2)], [("tk", GOOD.hex())])
check(st["decrypted"] == 2 and st["by_how"] == {"user_tk": 2} and st["user_tks"] == 1 and ex == ["所有 2 个受保护的数据帧都解开了。"], "用户直接给 TK：2 个帧都解开，how 是 user_tk，explain 说全部解开")
check(any("（user_tk 2）" in m for m in cap.texts("INFO", "pipeline")), "INFO：解开 2 个（user_tk 2）")
st, cap, ex = scenario([data_up(GOOD, 1)], [("tk", "00" * 16)])
check(st["decrypted"] == 0 and st["user_tks"] == 1 and not any("整个抓包里没有找到四次握手" in l for l in ex), "给了 TK 但不对：解不开；explain 不再建议「抓握手」（用户本来就没打算靠握手）")

# f. 握手验证通过，但之后换了密钥
OTHER = bytes([5]) * 16
st, cap, ex = scenario([beacon(), m1(), m2(), data_up(GOOD, 1), data_up(OTHER, 2), data_up(OTHER, 3)], KEY)
check(st["decrypted"] == 1 and st["undecrypted"] == {"mic_failed": 2} and st["handshake"]["pairs"][0]["state"] == "verified", "握手通过后有 2 个帧换了别的密钥：mic_failed 2 个，握手本身通过")
check(any("握手验证通过" in l and "仍有 2 个帧的 MIC 不对" in l and "重新握手" in l for l in ex), "explain：握手通过但仍有 2 个帧 MIC 不对 → 多半重新握手换了密钥")
# g. 帧早于握手
st, cap, ex = scenario([data_up(GOOD, 1), beacon(), m1(), m2(), data_up(GOOD, 2)], KEY)
check(st["undecrypted"] == {"before_handshake": 1} and st["decrypted"] == 1 and any("早于这对设备的握手" in l for l in ex), "握手之前的帧：before_handshake，explain 说明属于正常现象")
# h. 组播帧没有组密钥
st, cap, ex = scenario([beacon(), m1(), m2(), group_down(GOOD, 1)], KEY)
check(st["undecrypted"] == {"no_gtk_for_ap": 1} and any("1 个组播 / 广播帧没解开：没有这个 AP 的组密钥（没抓到 M3 / G1）" in l for l in ex), "组播帧没有组密钥：no_gtk_for_ap，explain 指出没抓到 M3 / G1")
check(any("组密钥：看到 0 条 M3 / G1，装上 0 个组密钥，没装上 0 条" in m for m in cap.texts("INFO", "groupkeys")), "INFO：组密钥看到 0 条 M3 / G1")

# i. explain 的边界
check(hs._frames_text([]) == "无" and hs._frames_text([5]) == "5" and hs._frames_text([1, 2, 3, 4]) == "1、2、3、4" and hs._frames_text([1, 2, 3, 4, 5, 6]) == "1、2、3、4…共 6 个", "帧号列表的文字：空 / 1 个 / 4 个 / 超过 4 个只列前 4 个并说共几个")
base = {"protected_data": 0, "decrypted": 0, "keys": {}, "user_tks": 0, "handshake": {}, "pair_frames": [], "undecrypted": {}}
check(pl.explain(base)[0].startswith("抓包里没有受保护的数据帧"), "explain：没有受保护的数据帧")
check(any("没有给任何密钥" in l for l in pl.explain(dict(base, protected_data=3, decrypted=1, undecrypted={"x": 2}))) and any("数据不足以判断原因" in l for l in pl.explain(dict(base, protected_data=3, decrypted=1, keys={"tk": 1}, user_tks=1, undecrypted={"x": 2}))), "explain：没给密钥会说；数据不足以判断时老实说不知道，请看日志")


# j. 真实样例里的其它路径：FT 漫游、TDLS、多链路
print("== 其它真实样例的日志 ==")
for name, wants in (("wpa2-ft-psk.pcapng.gz", [("DEBUG", "FT 漫游验证通过（AP 02:00:00:00:01:00，设备 02:00:00:00:02:00）"), ("DEBUG", "FT 重关联响应里装上 GTK（AP 02:00:00:00:01:00，序号 1）"),
                                                   ("INFO", "共推出 2 个握手"), ("INFO", "装上 2 个组密钥"), ("DEBUG", "AKM 4，CCMP-128，MIC cmac")]),
                    ("wpa-test-decode-tdls.pcap.gz", [("INFO", "TDLS：看到 1 组建立帧，1 组 MIC 验证通过"), ("DEBUG", "Response 的 MIC 吻合，Confirm 吻合"), ("INFO", "（pairwise 6、tdls 2），没解开 0 个")]),
                    ("wpa3-mlo.pcapng.gz", [("DEBUG", "M3 里装上 6 个多链路组密钥（每条链路各一个）"), ("DEBUG", "多链路：4 个链路地址对应 MLD 地址"), ("INFO", "装上 12 个组密钥，没装上 0 条"), ("DEBUG", "AKM 24, ".replace(", ", "，"))])):
    fl = list(fr.iter_frames(os.path.join(fetch_samples.SAMPLE_DIR, name)))
    with capture() as cap:
        pl.decrypt_capture(fl, KEYS)
    missing = [w for w in wants if not any(w[1] in m for m in cap.texts(w[0]))]
    check(not missing, "%s：日志里有 %s" % (name, "；".join(w[1] for w in wants)[:140]) + ("（缺 %s）" % missing if missing else ""))
check(not any("没有组密钥 KDE" in m for m in cap.texts("DEBUG")), "多链路的 M3 / G1：装上了多链路组密钥，就不再说「没有组密钥 KDE」")

# k. TRACE 逐帧；帧体太短
st, cap, ex = scenario([beacon(), m1(), m2(), data_up(GOOD, 1), data_up(OTHER, 2), with_addrs(AP, STA, AP, lambda: synth.frame(2, 0, 1, 0, prot=1, body=b"\x00" * 10))], KEY)
check(st["undecrypted"] == {"mic_failed": 1, "too_short": 1}, "帧体只有 10 字节的受保护帧：too_short；换了密钥的：mic_failed")
with tempfile.TemporaryDirectory() as tmp:
    p = os.path.join(tmp, "t.pcap")
    synth.write_pcap(p, [beacon(), m1(), m2(), data_up(GOOD, 1), data_up(OTHER, 2), with_addrs(AP, STA, AP, lambda: synth.frame(2, 0, 1, 0, prot=1, body=b"\x00" * 10))])
    fl = list(fr.iter_frames(p))
with capture(logs.TRACE) as cap:
    pl.decrypt_capture(fl, KEY)
tr = cap.texts("TRACE")
check("第 4 帧：用 M2=帧 3 的握手解开（CCMP-128）" in tr and "第 5 帧：用 M2=帧 3 的握手试（CCMP-128），MIC 不对" in tr and "第 6 帧：用 M2=帧 3 的握手试，帧体太短" in tr, "TRACE：逐帧记用哪个握手解开 / MIC 不对 / 帧体太短")
check("第 4 帧：解开（pairwise），1 个 MSDU" in tr and any(m.startswith("第 5 帧：受保护的数据帧，没解开（") for m in tr), "TRACE：逐帧记解开 / 没解开")
check(any("第 2 帧：EAPOL-Key 报文 1，%s -> %s" % (APM, STAM) == m for m in tr) and any(m.startswith("第 3 帧：EAPOL-Key 报文 2") for m in tr), "TRACE：EAPOL-Key 报文逐条记")
check(not [m for lv, nm, m in cap.records if lv == "TRACE" and nm.endswith("report")], "只有逐帧的地方才用 TRACE")


# l. 缺 M2 / 不支持的套件 / 报文不全 / 组密钥握手失败的各种原因
print("== 握手和组密钥的其它失败情形 ==")


def m2_with(rsn_data):
    kck = hs.derive_ptk(pmk_of("password", b"HomeNet"), AP, STA, AN, SN, "sha1", 16, 16, 16)[0]
    raw = eapol.zero_mic(eapol_key(0x0100 | 0x0008 | 2, SN, 1, data=rsn_data), 16)
    raw = raw[:81] + hs.compute_mic("hmac-sha1", kck, raw, 16) + raw[97:]
    return with_addrs(AP, STA, AP, lambda: synth.frame(2, 0, 1, 0, body=LLC + raw))


def key_frame(ki, nonce, replay, data=b"", mic=None, from_ap=True):
    raw = eapol_key(ki, nonce, replay, data=data)
    if mic == "good":
        kck = hs.derive_ptk(pmk_of("password", b"HomeNet"), AP, STA, AN, SN, "sha1", 16, 16, 16)[0]
        z = eapol.zero_mic(raw, 16)
        raw = z[:81] + hs.compute_mic("hmac-sha1", kck, z, 16) + z[97:]
    a = (STA, AP, AP, (2, 0, 0, 1)) if from_ap else (AP, STA, AP, (2, 0, 1, 0))
    return with_addrs(a[0], a[1], a[2], lambda: synth.frame(*a[3], body=LLC + raw))


M3_KI, G1_KI = 0x13CA, 0x1382
st, cap, ex = scenario([beacon(), m2(), data_up(GOOD, 1)], KEY)
check(st["handshake"]["pairs"][0]["state"] == "m2_without_m1" and any("只抓到 M2" in l and "M1 没抓到" in l for l in ex) and any("找不到 Replay Counter 对应的 M1" in m for m in cap.texts("DEBUG", "handshake")), "只有 M2 没有 M1：状态 m2_without_m1，explain 说 M1 没抓到")
weird = ie_(48, struct.pack("<H", 1) + b"\x00\x0f\xac\x01" + struct.pack("<H", 1) + b"\x00\x0f\xac\x01" + struct.pack("<H", 1) + b"\x00\x0f\xac\x02" + struct.pack("<H", 0))
st, cap, ex = scenario([beacon(), m1(), m2_with(weird), data_up(GOOD, 1)], KEY)
check(st["handshake"]["pairs"][0]["state"] == "unsupported" and any("不支持的认证方式 / 密码套件（2/1）" in l for l in ex) and any("AKM 2 / 密码套件 1 不支持" in m for m in cap.texts("DEBUG", "handshake")), "M2 声明了不支持的套件：状态 unsupported，explain 说出 AKM / 套件")
st, cap, ex = scenario([beacon(), m1(), m2_with(b""), data_up(GOOD, 1)], KEY)
check(st["handshake"]["pairs"][0]["state"] == "m2_without_m1" and any("缺 RSN 元素" in l for l in ex) and any("没有 RSN / WPA 元素" in m for m in cap.texts("DEBUG", "handshake")), "M2 没有 RSN 元素：同样提示 M2 / 缺 RSN 元素")
st, cap, ex = scenario([beacon(), key_frame(M3_KI, AN, 2), data_up(GOOD, 1)], KEY)
check(st["handshake"]["pairs"][0]["state"] == "incomplete" and st["handshake"]["pairs"][0]["msgs"][3] == [2] and any("握手报文不全" in l for l in ex), "只有 M3：状态 incomplete，explain 说报文不全")
check(st["group"] == {"m3_g1": 1, "installed": 0, "failed": {"no_handshake": 1}} and any("M3 没装上组密钥：没有这对设备的（M2 在它之前的）握手" in m for m in cap.texts("DEBUG", "groupkeys")), "M3 前面没有握手：组密钥 no_handshake")
st, cap, ex = scenario([beacon(), m1(), m2(), key_frame(M3_KI, AN, 2)], KEY)
check(st["group"] == {"m3_g1": 1, "installed": 0, "failed": {"mic": 1}} and any("M3 没装上组密钥：MIC 和 1 个握手都对不上" in m for m in cap.texts("DEBUG", "groupkeys")) and any("没装上 1 条（mic 1）" in m for m in cap.texts("INFO", "groupkeys")), "M3 的 MIC 不对：组密钥 mic")
st, cap, ex = scenario([beacon(), m1(), m2(), key_frame(M3_KI, AN, 2, data=bytes(range(24)), mic="good")], KEY)
check(st["group"] == {"m3_g1": 1, "installed": 0, "failed": {"unwrap": 1}} and any("MIC 对了但 Key Data 解不开（1 个）" in m for m in cap.texts("DEBUG", "groupkeys")), "M3 的 MIC 对但 Key Data 解不开：组密钥 unwrap")
st, cap, ex = scenario([beacon(), m1(), m2(), key_frame(G1_KI, bytes(32), 3)], KEY)
check(st["group"] == {"m3_g1": 1, "installed": 0, "failed": {"mic": 1}} and any("G1 没装上组密钥" in m for m in cap.texts("DEBUG", "groupkeys")), "G1 的 MIC 不对：同样记 mic，消息里说是 G1")


from Crypto.Cipher import AES  # noqa: E402


def aes_wrap(kek, plain):                                   # RFC 3394，测试里独立写一份
    n, a, r = len(plain) // 8, bytes.fromhex("A6A6A6A6A6A6A6A6"), [plain[i * 8:i * 8 + 8] for i in range(len(plain) // 8)]
    for j in range(6):
        for i in range(n):
            b = AES.new(kek, AES.MODE_ECB).encrypt(a + r[i])
            a = bytes(x ^ y for x, y in zip(b[:8], (n * j + i + 1).to_bytes(8, "big")))
            r[i] = b[8:]
    return a + b"".join(r)


PTK = hs.derive_ptk(pmk_of("password", b"HomeNet"), AP, STA, AN, SN, "sha1", 16, 16, 16)
GTK = bytes(range(100, 116))
KDE_GTK = bytes([0xDD, 6 + 16, 0x00, 0x0F, 0xAC, 1, 0x01 | 0x04, 0]) + GTK                      # 密钥序号 1，Tx
st, cap, ex = scenario([beacon(), m1(), m2(), key_frame(M3_KI, AN, 2, data=aes_wrap(PTK[1], KDE_GTK), mic="good"), group_down(GOOD, 1)], KEY)
check(st["group"] == {"m3_g1": 1, "installed": 1, "failed": {}} and any("M3 里装上 GTK（AP %s，序号 1，Tx）" % APM in m for m in cap.texts("DEBUG", "groupkeys")), "合法的 M3（带 GTK KDE，Tx）：装上组密钥，日志写序号和 Tx")
KDE_NONE = bytes([0xDD, 0]) + bytes(14)                                                     # 解开后只有填充，没有组密钥 KDE
st, cap, ex = scenario([beacon(), m1(), m2(), key_frame(M3_KI, AN, 2, data=aes_wrap(PTK[1], KDE_NONE), mic="good")], KEY)
check(st["group"] == {"m3_g1": 1, "installed": 0, "failed": {"no_key": 1}} and any("M3 的 Key Data 解开了，但里面没有组密钥 KDE" in m for m in cap.texts("DEBUG", "groupkeys")), "M3 解开了但没有组密钥 KDE：no_key")

# m. 组播帧 / 不是单播也不是组播的帧
print("== 没解开的帧的分类 ==")
st, cap, ex = scenario([beacon(), m1(), m2(), group_down(GOOD, 1)], KEY)
ab.A2, ab.A3 = STA, AP
multicast_up = ab.build("CCMP-128", GOOD, 5, SNAP + b"q" * 24, a1=bytes.fromhex("01005e000001"), qos=0, to_ds=1, from_ds=0)
wds = ab.build("CCMP-128", GOOD, 6, SNAP + b"w" * 24, a1=bytes.fromhex("02aabbccdd09"), qos=0, to_ds=1, from_ds=1, four=True)
st, cap, ex = scenario([beacon(), m1(), m2(), multicast_up, wds], KEY)
check(st["undecrypted"] == {"other": 2} and any("不属于单播也不属于 AP 发出的组播" in m for m in cap.texts("DEBUG", "pipeline")), "ToDS 的组播地址帧、WDS 帧：other，日志说明")
F = namedtuple("F", "n h body dot11")
H = namedtuple("H", "ap sta cipher frames")
fh = lambda to_ds, from_ds, a1, a2, prot=1: {"type": 2, "protected": prot, "to_ds": to_ds, "from_ds": from_ds, "addr1": a1, "addr2": a2}      # noqa: E731
fb = bytes(30)
hs1 = H(APM, STAM, "CCMP-128", {"m2": 10})
check([dec.why_not([], F(20, fh(1, 0, APM, STAM), fb, b""))] + [dec.why_not([hs1], F(5, fh(1, 0, APM, STAM), fb, b""))] + [dec.why_not([H(APM, STAM, "WEP-40", {"m2": 10})], F(20, fh(1, 0, APM, STAM), fb, b""))]
      + [dec.why_not([hs1], F(20, fh(1, 0, APM, STAM), bytes(10), b""))] + [dec.why_not([hs1], F(20, fh(1, 0, APM, STAM), fb, b""))] == ["no_handshake", "before_handshake", "cipher_unsupported", "too_short", "mic_failed"],
      "why_not：没有握手 / 帧在握手前 / 套件不支持 / 帧体太短 / 有握手但 MIC 不对")
check(dec.why_not([H("aa", "bb", "CCMP-128", {"m2": 1})], F(20, fh(1, 0, "x", "y"), fb, b""), {"x": "aa", "y": "bb"}) == "mic_failed", "why_not：多链路的链路地址先换成 MLD 地址再配对")
GK = namedtuple("GK", "ap key_id n")
mcast = "01:00:5e:00:00:01"
gf = lambda key_id=1, a2=APM, n=20, body=None: F(n, fh(0, 1, mcast, a2), body if body is not None else bytes([0, 0, 0, key_id << 6 | 0x20]) + bytes(26), b"")       # noqa: E731
ciph = {APM: "CCMP-128"}
check([gk.why_not_group([], ciph, F(20, fh(1, 0, APM, STAM), fb, b"")), gk.why_not_group([], {}, gf()), gk.why_not_group([], ciph, gf(body=bytes(4))), gk.why_not_group([], ciph, gf()),
       gk.why_not_group([GK(APM, 2, 5)], ciph, gf(key_id=1)), gk.why_not_group([GK(APM, 1, 30)], ciph, gf(key_id=1)), gk.why_not_group([GK(APM, 1, 5)], ciph, gf(key_id=1)),
       gk.why_not_group([GK("other", 1, 5)], ciph, gf(key_id=1))] == ["not_group", "cipher_unknown", "cipher_unknown", "no_gtk_for_ap", "no_gtk_keyid", "gtk_after_frame", "mic_failed", "no_gtk_for_ap"],
      "why_not_group：非组播 / 不知道组套件 / 帧体太短 / 没有这个 AP 的组密钥 / 密钥序号不对 / 组密钥在帧之后 / MIC 不对")
check(all(c in dec.WHY or c in gk.WHY_GROUP for c in ("no_handshake", "before_handshake", "cipher_unsupported", "too_short", "mic_failed", "cipher_unknown", "no_gtk_for_ap", "no_gtk_keyid", "gtk_after_frame")), "每个原因代码都有中文说明")

# n. 「一半以上」的边界；pair_frames 的方向
st, cap, ex = scenario([beacon(), m1(), m2(), data_up(GOOD, 1), data_up(OTHER, 2)], KEY)
check(st["decrypted"] == 1 and st["protected_data"] == 2 and not cap.texts("WARNING", "pipeline"), "正好一半解开：不报「一半以上没解开」")
st, cap, ex = scenario([beacon(), m1(), m2(), data_up(GOOD, 1), data_up(OTHER, 2), data_up(OTHER, 3)], KEY)
check(len(cap.texts("WARNING", "pipeline")) == 1 and "（2 / 3）" in cap.texts("WARNING", "pipeline")[0] and "主要原因：有握手但 MIC 不对" in cap.texts("WARNING", "pipeline")[0], "3 个里解开 1 个：报警，写出 2 / 3 和主要原因")
st, cap, ex = scenario([beacon(), data_up(GOOD, 1), data_down(GOOD, 2)], KEY)
check(st["pair_frames"] == [{"ap": APM, "sta": STAM, "reason": "no_handshake", "count": 2}], "上行和下行的帧归到同一对 (AP, 设备)：AP 在前、设备在后")
big = [beacon(), m1(), m2()] + [data_up(OTHER, i) for i in range(1, 9)]
st, cap, ex = scenario(big, KEY)
check(st["examples"]["mic_failed"] == [4, 5, 6, 7, 8] and any("8 个（例：帧 4、5、6、7、8）" in m for m in cap.texts("DEBUG", "pipeline")), "例子帧号最多 5 个")

# o. 命令行：口令不对时的输出
print("== report 命令行 ==")
import subprocess  # noqa: E402
tmpd = tempfile.mkdtemp()
wk = os.path.join(tmpd, "wrong.txt")
open(wk, "w").write('"wpa-pwd","WrongPassphraseXYZ"\n')
env = dict(os.environ, PYTHONPATH=ROOT)
pr = subprocess.run([sys.executable, "-m", "wifi80211.report", path, "--keys", wk, "--no-log-file"], capture_output=True, text=True, env=env, cwd=tmpd)
check(pr.returncode == 3 and "原因分析：AP 00:0c:41:82:b2:55 与设备 00:0d:93:82:36:3a（SSID \"Coherer\"）的握手 MIC 对不上（试了 1 个候选密钥）" in pr.stderr and "口令输错" in pr.stderr, "口令不对：退出码 3，屏幕上有「原因分析」，指出哪一对握手 MIC 对不上")
check("WrongPassphraseXYZ" not in pr.stderr + pr.stdout, "屏幕上不出现口令")

check(any("3 个帧没解开：这对设备的成对密码套件不支持" in l for l in pl.explain(dict(base, protected_data=3, decrypted=0, keys={"wpa-pwd": 1}, undecrypted={"cipher_unsupported": 3}, handshake={"pairs": [{"ap": "a", "sta": "b", "ssid": None, "state": "verified", "msgs": {1: [], 2: [], 3: [], 4: []}, "candidates": 1, "other": []}]}))), "explain：套件不支持")

print("== keyfile 与 tdls 的日志 ==")
with tempfile.TemporaryDirectory() as tmp:
    kf = os.path.join(tmp, "k.txt")
    open(kf, "w").write('"wpa-pwd","TopSecretPassphrase"\n"wpa-psk","%s"\n' % ("ab" * 32))
    with capture() as cap:
        keyfile.parse(kf)
    t = cap.texts("INFO", "keyfile")
    check(len(t) == 1 and "wpa-pwd 1 把、wpa-psk 1 把" in t[0] and "TopSecretPassphrase" not in t[0] and "abab" not in t[0], "读密钥文件：INFO 只记类型和把数")
with capture() as cap:
    from wifi80211 import tdls
    tdls.track({})
check(cap.texts(name="tdls") == [], "没有 TDLS 建立帧：不写日志")

# ---------------------------------------------------------------------------
print("== 泄露检查（TRACE 级别，整条链）==")
secrets = {}                                              # 名字 -> 要找的字符串


def add(label, value, minlen=8):
    if isinstance(value, bytes):
        value = value.hex()
    if len(value) >= minlen:
        secrets[label] = value.lower()


for typ, val in KEYS:
    add("密钥表 %s" % typ, val, 8)
rawlog = Collect()
root = logging.getLogger("wifi80211")
saved_level = root.level
root.setLevel(logs.TRACE)
root.addHandler(rawlog)
tmp = tempfile.mkdtemp()
logfile = os.path.join(tmp, "leak.log")
logs.setup("trace", logfile, stream=open(os.devnull, "w"))
root.addHandler(rawlog)
ran = []
for name in ("wpa-Induction.pcap.gz", "wpa2-ft-psk.pcapng.gz", "wpa-ccmp-256.pcapng.gz"):
    fl = list(fr.iter_frames(os.path.join(fetch_samples.SAMPLE_DIR, name)))
    res = pl.decrypt_capture(fl, KEYS)
    done, _ = hs.track(fl, KEYS)
    from wifi80211 import groupkeys as gk
    for x in done:
        add("%s PMK" % name, x.pmk[1])
        add("%s KCK" % name, x.kck)
        add("%s KEK" % name, x.kek)
        add("%s TK" % name, x.tk)
        if x.ft:
            add("%s PMK-R0" % name, x.ft["pmk_r0"])
    for k in gk.track_group(fl, done):
        add("%s GTK" % name, k.gtk)
        if k.igtk:
            add("%s IGTK" % name, k.igtk[2])
    ran.append((name, len(res), len(done)))
for h in list(root.handlers):
    h.flush()
root.removeHandler(rawlog)
root.setLevel(saved_level)
logs.setup("error", None)
check(all(n > 0 for _, n, _ in ran) and all(h > 0 for _, _, h in ran), "三个样例都解出了帧、推出了握手：%s" % ran)
every = "\n".join(m for _, _, m in rawlog.records).lower()
filed = open(logfile, encoding="utf-8").read().lower()
check(len(rawlog.records) > 500 and sum(1 for lv, _, _ in rawlog.records if lv == "TRACE") > 100, "TRACE 级别确实逐帧记了（%d 条记录）" % len(rawlog.records))
leaks = sorted(k for k, v in secrets.items() if v in every.replace(":", "") or v in every)
check(not leaks, "原始日志里没有口令、PMK、KCK、KEK、TK、GTK、IGTK（检查了 %d 个值，泄露：%s）" % (len(secrets), leaks[:5]))
passes = [v for k, v in secrets.items() if k.startswith("密钥表 wpa-pwd")]
check(all(p not in filed for p in passes) and not re.search(r"[0-9a-f]{32}", filed), "经过过滤器写出的日志文件里没有口令，也没有 32 个以上的十六进制字符")
raw_hex = re.findall(r"(?<![0-9a-z])[0-9a-f]{32,}(?![0-9a-z])", every)
check(not raw_hex, "连过滤器之前的原始消息里也没有 16 字节以上的十六进制串（写日志的代码自己就不带）")

print("== 不改行为 ==")
fl = list(fr.iter_frames(os.path.join(fetch_samples.SAMPLE_DIR, "wpa-Induction.pcap.gz")))
logging.getLogger("wifi80211").setLevel(logging.CRITICAL)
quiet = pl.decrypt_capture(fl, KEYS)
with capture(logs.TRACE):
    loud = pl.decrypt_capture(fl, KEYS)
with_stats = {}
same_stats = pl.decrypt_capture(fl, KEYS, with_stats)
check(quiet == loud == same_stats and len(quiet) == 276, "日志关着 / TRACE 全开 / 带 stats：decrypt_capture 的结果完全相同（276 个帧）")
logging.getLogger("wifi80211").setLevel(logging.NOTSET)

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
