#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""decrypt_oracle 自身的测试：密钥表解析、tshark -x 输出的解析（离线，合成文本）；
以及在真实样例上 tshark 能解出多少帧（精确的表：tshark 版本变了、密钥表变了都会在这里显形）。需要 tshark 和样例。"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import decrypt_oracle as d  # noqa: E402
import diff  # noqa: E402
import fetch_samples  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


print("== 密钥表解析 ==")
with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "k")
    with open(path, "w") as f:
        f.write('# comment\n\n"wep","1234567890"\n"wpa-pwd","Induction"\n  "wpa-psk","%s"  \n"msk","%s"\n"wpa-pwd","a,b"\n' % ("ab" * 32, "cd" * 64))
    keys = d.parse_keys(path)
    check([k[0] for k in keys] == ["wep", "wpa-pwd", "wpa-psk", "msk", "wpa-pwd"], "注释、空行跳过；每行的类型按顺序")
    check(keys[0] == ("wep", "1234567890") and keys[2][1] == "ab" * 32 and keys[4] == ("wpa-pwd", "a,b"), "值原样（前后空白去掉；值里有逗号也不截断）")
    ok, dropped = d.tshark_usable(keys)
    check(dropped == [] and len(ok) == 5, "msk 本来就是 64 字节，tshark 接受，不去掉")
    ok, dropped = d.tshark_usable(keys + [("wpa-psk", "ef" * 64)])
    check(dropped == [("wpa-psk", "ef" * 64)] and len(ok) == 5, "64 字节（128 位十六进制）的 wpa-psk 被去掉；32 字节的 PSK 留下")
    check(d.tshark_usable([("wpa-psk", "ab" * 48)])[1] == [] and d.tshark_usable([("wpa-psk", "ab" * 49)])[1] != [], "48 字节的 PMK（SHA-384）可用，49 字节起去掉")
    check(d.tshark_usable([("wpa-pwd", "x" * 200)])[1] == [] and d.tshark_usable([("wep", "x" * 200)])[1] == [], "口令和 WEP 密钥再长也不去掉（只看 PSK / msk 的长度）")
    with d.key_env(keys[:2]) as env:
        with open(os.path.join(env["XDG_CONFIG_HOME"], "wireshark", "80211_keys")) as f:
            check(f.read() == '"wep","1234567890"\n"wpa-pwd","Induction"\n', "key_env 写出的 80211_keys 就是这几行")
    check(not os.path.exists(env["XDG_CONFIG_HOME"]), "key_env 退出后临时目录删掉")

print("== tshark -x 输出的解析 ==")
text = ("Frame (10 bytes):\n0000  01 02 03 04 05 06 07 08 09 0a                     ..........\n"
        "Decrypted CCMP data (3 bytes):\n0000  aa bb cc                                          ...\n"
        "\n"
        "0000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f   ................\n0010  10 11 12 13                                       ....\n"
        "\n"
        "Frame (4 bytes):\n0000  de ad be ef                                       ....\n"
        "Decrypted TKIP data (2 bytes):\n0000  11 22                                             ..\n"
        "Reassembled TCP (1 bytes):\n0000  33                                                .\n\n")
g = d.parse_dump(text)
check(len(g) == 3, "按空行分帧：3 帧（第二帧只有一个数据源，tshark 不为它打标题，也不会丢）")
check([n for n, _ in g[0]] == ["Frame", "Decrypted CCMP data"] and g[0][1][1] == b"\xaa\xbb\xcc" and g[0][0][1] == bytes(range(1, 11)), "第一帧：帧本身 10 字节 + 解密数据源 3 字节")
check(g[1] == [], "没有标题的帧：数据源为空组，位置还在（和帧号一一对齐）")
g2 = d.parse_dump("Frame (20 bytes):\n0000  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f   ................\n0010  10 11 12 13                                       ....\n")
check(g2 == [[("Frame", bytes(range(20)))]], "跨两行的 20 字节：偏移列不当数据，最后一行不足 16 字节也对")
check([n for n, _ in g[2]] == ["Frame", "Decrypted TKIP data", "Reassembled TCP"], "同一帧的多个数据源按顺序")
check(d.parse_dump("") == [] and d.parse_dump("\n\n\n") == [], "空输出：没有帧")

print("== 真实样例：tshark 能解出多少帧（精确）==")
fetch_samples.fetch()
EXPECTED = {
    "owe-3-dh-groups.pcapng.gz": {"CCMP": 1}, "owe.pcapng.gz": {"CCMP": 10}, "wep.pcapng.gz": {"WEP": 11},
    "wpa-Induction.pcap.gz": {"CCMP": 203, "TKIP": 73}, "wpa-ccmp-256.pcapng.gz": {"CCMP": 14}, "wpa-eap-tls.pcap.gz": {"CCMP": 61},
    "wpa-gcmp-256.pcapng.gz": {"GCMP": 13}, "wpa-gcmp.pcapng.gz": {"GCMP": 15}, "wpa-mlo-ccmp.pcapng.gz": {},
    "wpa-test-decode-mgmt.pcap.gz": {"CCMP": 3}, "wpa-test-decode-tdls.pcap.gz": {"CCMP": 8}, "wpa-test-decode.pcap.gz": {"CCMP": 756},
    "wpa1-gtk-rekey.pcapng.gz": {"TKIP": 22}, "wpa2-ft-eap.pcapng.gz": {"CCMP": 4}, "wpa2-ft-psk.pcapng.gz": {"CCMP": 17},
    "wpa2-psk-ccmp-tkip.pcapng.gz": {"CCMP": 8, "TKIP": 4}, "wpa2-psk-mfp.pcapng.gz": {"CCMP": 9},
    "wpa3-ft-sae-ext-key-group20.pcapng.gz": {}, "wpa3-ft-sae-h2e.pcapng.gz": {"CCMP": 10}, "wpa3-mlo.pcapng.gz": {},
    "wpa3-sae-ext-key-group21.pcapng.gz": {}, "wpa3-sae.pcapng.gz": {"CCMP": 10}, "wpa3-suiteb-192.pcapng.gz": {"GCMP": 3},
    "wpa_ptk_extended_key_id.pcap.gz": {"CCMP": 31},
}
check(diff.tshark_version().startswith(diff.TSHARK_MAJOR_MINOR), "tshark 是 %s.x" % diff.TSHARK_MAJOR_MINOR)
keys = d.parse_keys()
check(len(d.tshark_usable(keys)[1]) == 2 and all(k[0] == "wpa-psk" for k in d.tshark_usable(keys)[1]), "密钥表里有 2 把 tshark 4.4 加载不了的 64 字节 wpa-psk（被去掉）")
total = 0
for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
    got = d.tshark_plain(os.path.join(fetch_samples.SAMPLE_DIR, name), keys)
    methods = {}
    for v in got.values():
        methods[v["method"]] = methods.get(v["method"], 0) + 1
    total += len(got)
    check(methods == EXPECTED.get(name), "%s：%s（表里 %s）" % (name, methods, EXPECTED.get(name)))
check(sorted(EXPECTED) == sorted(os.listdir(fetch_samples.SAMPLE_DIR)), "表里的样例就是目录里的全部样例")
check(total == 1286, "共 %d 帧（表里 1286）" % total)
w = d.tshark_plain(os.path.join(fetch_samples.SAMPLE_DIR, "wep.pcapng.gz"), keys)
check(sorted(w) == [6, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19], "WEP 样例解出的帧号：6 和 10-19（和 tshark 用显示过滤器单独查到的受保护帧号一致）")
check(w[6]["plain"][:6].hex() == "010003000000" and w[10]["plain"][:8].hex() == "aaaa030000000800", "帧号对应的明文没错位：6 号是非 IP 数据，10 号是 IPv4（LLC/SNAP + 0x0800）")
ip_frames = [v for v in w.values() if v["plain"][:3] == b"\xaa\xaa\x03"]
check(len(w) == 11 and len(ip_frames) >= 5 and all(v["plain"][3:6] == b"\x00\x00\x00" and v["plain"][6:8] in (b"\x08\x00", b"\x08\x06") for v in ip_frames), "WEP 样例：11 帧；其中 LLC/SNAP 开头的，以太类型是 0x0800（IPv4）或 0x0806（ARP）")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
