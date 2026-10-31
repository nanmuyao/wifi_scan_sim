#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""handshake80211 在 24 个样例上：握手靠 MIC 自证；推导出的 KCK / KEK / TK 与 tshark 打在帧上的逐把对照。需要 tshark 和样例。

两把尺子：
  1. MIC 自证：握手只在「用候选 PMK 推出的 KCK 重算的 M2 MIC 与抓包里的吻合」时才算成功——AP 用真密钥算出的值，不依赖第三方；
  2. tshark：它在 EAPOL 帧上打 KCK / KEK、在数据帧上打 TK（wlan.analysis.*）。tshark 打出的每一把都必须在我们的集合里。
     tshark 4.4 做不到的（64 字节 PMK、FT）它没有答案，那些只有第 1 把尺子。
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import decrypt_oracle as d  # noqa: E402
import fetch_samples  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import handshake as hs  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def tshark_keys(path, usable):
    out = {"kck": set(), "kek": set(), "tk": set()}
    with d.key_env(usable) as env:
        r = subprocess.run(["tshark", "-r", path] + d.TSHARK_DECRYPT + ["-T", "fields", "-e", "wlan.analysis.kck", "-e", "wlan.analysis.kek", "-e", "wlan.analysis.tk"],
                           capture_output=True, text=True, env=env).stdout
    for line in r.split("\n"):
        for name, v in zip(("kck", "kek", "tk"), (line.split("\t") + ["", "", ""])[:3]):
            if v:
                out[name].add(v.replace(":", ""))
    return out


fetch_samples.fetch()
keys = d.parse_keys()
usable, _ = d.tshark_usable(keys)
# 样例 -> (我们的握手数, 其中被 tshark 印证的个数, tshark 多出来的 KCK 数, KEK 数, TK 数)
# 「被印证」= 我们的 KCK 或 TK 出现在 tshark 的输出里（TKIP 的 TK 是 32 字节，tshark 只打前 16 字节，按前缀比）。
# tshark 多出来的密钥来自我们还没处理的握手：
#   （重新握手的 EAPOL 帧被当前 PTK 加密，现在边解密边跟踪，D4c-2 起不再有多出来的：wpa-eap-tls 3 个、wpa-test-decode 2 个、wpa_ptk_extended_key_id 2 个重新握手）
#   （快速切换的空中漫游由重关联请求的 FTE MIC 验证，每个 FT 样例 1 次，wpa3-ft-sae-h2e 的漫游 tshark 没有打出 TK，所以那一个只有我们的两把尺子）
#   - TDLS 的对等密钥（TPK）握手在 TDLS 动作帧里，不是 4 次握手：wpa-test-decode-tdls 的 1 个 TK。
# 我们的握手数 > 被印证数 的：tshark 4.4 做不到的（48 / 64 字节的 PMK：owe-3-dh-groups 的 2 个、wpa3-sae-ext-key-group21；多链路：wpa3-mlo），只有 MIC 自证。
EXPECTED = {
    "owe-3-dh-groups.pcapng.gz": (3, 1, 0, 0, 0), "owe.pcapng.gz": (1, 1, 0, 0, 0), "wep.pcapng.gz": (0, 0, 0, 0, 0),
    "wpa-Induction.pcap.gz": (1, 1, 0, 0, 0), "wpa-ccmp-256.pcapng.gz": (1, 1, 0, 0, 0), "wpa-eap-tls.pcap.gz": (4, 4, 0, 0, 0),
    "wpa-gcmp-256.pcapng.gz": (1, 1, 0, 0, 0), "wpa-gcmp.pcapng.gz": (1, 1, 0, 0, 0), "wpa-mlo-ccmp.pcapng.gz": (0, 0, 0, 0, 0),
    "wpa-test-decode-mgmt.pcap.gz": (1, 1, 0, 0, 0), "wpa-test-decode-tdls.pcap.gz": (2, 2, 0, 0, 1), "wpa-test-decode.pcap.gz": (3, 3, 0, 0, 0),
    "wpa1-gtk-rekey.pcapng.gz": (1, 1, 0, 0, 0), "wpa2-ft-eap.pcapng.gz": (1, 1, 0, 0, 0), "wpa2-ft-psk.pcapng.gz": (2, 2, 0, 0, 0),
    "wpa2-psk-ccmp-tkip.pcapng.gz": (1, 1, 0, 0, 0), "wpa2-psk-mfp.pcapng.gz": (1, 1, 0, 0, 0),
    "wpa3-ft-sae-ext-key-group20.pcapng.gz": (2, 0, 0, 0, 0), "wpa3-ft-sae-h2e.pcapng.gz": (2, 1, 0, 0, 0),
    "wpa3-mlo.pcapng.gz": (1, 0, 0, 0, 0), "wpa3-sae-ext-key-group21.pcapng.gz": (1, 0, 0, 0, 0), "wpa3-sae.pcapng.gz": (1, 1, 0, 0, 0),
    "wpa3-suiteb-192.pcapng.gz": (3, 3, 0, 0, 0), "wpa_ptk_extended_key_id.pcap.gz": (3, 3, 0, 0, 0),
}
total = confirmed = 0
ft_names = []
for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    done, _ = hs.track(list(fr.iter_frames(path)), keys)
    ts = tshark_keys(path, usable)
    conf = sum(1 for h in done if h.kck.hex() in ts["kck"] or any(h.tk.hex().startswith(t) for t in ts["tk"]))
    extra = (len(ts["kck"] - {h.kck.hex() for h in done}), len(ts["kek"] - {h.kek.hex() for h in done}),
             len([t for t in ts["tk"] if not any(h.tk.hex().startswith(t) for h in done)]))
    total += len(done)
    for h in done:
        if h.akm in hs.FT_AKMS:
            ft_names.append((name, h.frames["pmkr1name_ok"]))
    confirmed += conf
    check((len(done), conf) + extra == EXPECTED[name],
          "%s：握手 %d 个（MIC 自证），被 tshark 印证 %d 个；tshark 多出的 KCK / KEK / TK = %s（表里 %s）" % (name, len(done), conf, extra, EXPECTED[name]))
check(total == 37 and confirmed == 30, "共 %d 个握手通过 MIC 自证，其中 %d 个也被 tshark 印证" % (total, confirmed))
check(len(ft_names) == 7 and all(ok for _, ok in ft_names), "7 个快速切换握手（4 个初始握手 + 3 次空中漫游）：PMKID 都等于推出的 PMKR1Name（第二个独立的证明）：%s" % ft_names)
check(sorted(EXPECTED) == sorted(os.listdir(fetch_samples.SAMPLE_DIR)), "表里的样例就是目录里的全部样例")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
