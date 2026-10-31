#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
解密的标准答案：让 tshark 用 Wireshark 测试套件公开的密钥解密，把它解出来的明文取出来。

- parse_keys：读 samples_extras/80211_keys.tmpl（口令 wpa-pwd、PMK/PSK wpa-psk、WEP 密钥 wep、EAP 的 msk）。
- tshark_plain：对一个抓包，返回 {帧号: {"method": "CCMP" / "TKIP" / ..., "plain": bytes}}。
  tshark 把解密后的字节放在一个单独的「Decrypted … data」数据源里，从 `tshark -x` 的输出里取。
  只有 tshark 解得出来的帧才在结果里（密钥不对、握手没抓全的帧它也解不出）。

用法：python3 tests/oracle/decrypt_oracle.py     # 各样例里 tshark 能解出多少帧（基线）
"""
import contextlib
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fetch_samples  # noqa: E402

KEYS_FILE = os.path.join(fetch_samples.EXTRAS_DIR, "80211_keys.tmpl")
SECTION = re.compile(r"^(.+?) \((\d+) bytes\):$")
HEXLINE = re.compile(r"^[0-9a-f]{4}  ")


def parse_keys(path=KEYS_FILE):
    """[(类型, 值)]：类型是 wpa-pwd / wpa-psk / wep / msk。忽略注释和空行。"""
    keys = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r'^"([^"]+)","([^"]*)"', line)
            if m:
                keys.append((m.group(1), m.group(2)))
    return keys


def tshark_usable(keys):
    """去掉这个版本的 tshark（4.4）不接受的密钥：64 字节（128 位十六进制）的 wpa-psk——用于 SAE-EXT-KEY 的 group 21 等，
    Wireshark 更新的版本才支持。有这样一把密钥在表里，整个表都加载失败。（msk 本来就是 64 字节，可以。）返回 (可用的, 被去掉的)。"""
    ok, dropped = [], []
    for typ, val in keys:
        (dropped if typ == "wpa-psk" and len(val) > 96 else ok).append((typ, val))
    return ok, dropped


@contextlib.contextmanager
def key_env(keys):
    """把密钥表写成一个临时的 Wireshark 配置目录（80211_keys），产出给 tshark 用的环境变量。
    不用行内的 -o uat: ——它的解析器拒绝 64 字节（128 位十六进制）的 PSK，而配置文件里这样的 PSK 是合法的。"""
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "wireshark"))
        with open(os.path.join(tmp, "wireshark", "80211_keys"), "w", encoding="utf-8") as f:
            for typ, val in keys:
                f.write('"%s","%s"\n' % (typ, val))
        yield dict(os.environ, XDG_CONFIG_HOME=tmp)


TSHARK_DECRYPT = ["-o", "wlan.enable_decryption:TRUE"]


def parse_dump(text):
    """解析 `tshark -x` 的输出 -> [[(数据源名字, bytes)]]，每个帧一组（帧与帧之间是空行；同一帧的多个数据源之间没有空行）。
    每组第一个数据源是帧本身（标题通常是 "Frame"，个别帧的标题不同，所以不按标题分组）。"""
    groups = []
    for block in text.split("\n\n"):
        if not block.strip():
            continue
        sources, name, buf = [], None, bytearray()
        for line in block.split("\n"):
            m = SECTION.match(line)
            if m:
                if name is not None:
                    sources.append((name, bytes(buf)))
                name, buf = m.group(1), bytearray()
            elif HEXLINE.match(line) and name is not None:
                buf += bytes(int(x, 16) for x in line[6:6 + 48].split())
        if name is not None:
            sources.append((name, bytes(buf)))
        groups.append(sources)
    return groups


def tshark_plain(path, keys, display_filter="wlan.fc.protected==1"):
    """{帧号: {"method": ..., "plain": bytes}}，只含 tshark 解出了明文的帧。"""
    base = ["tshark", "-r", path] + TSHARK_DECRYPT + ["-Y", display_filter]
    keys, _ = tshark_usable(keys)
    with key_env(keys) as env:
        nums = subprocess.run(base + ["-T", "fields", "-e", "frame.number"], capture_output=True, text=True, env=env).stdout.split()
        dump = subprocess.run(base + ["-x"], capture_output=True, text=True, env=env).stdout
    groups = parse_dump(dump)
    if len(groups) != len(nums):
        raise RuntimeError("tshark 输出的帧数对不上: 帧号 %d 个，数据源 %d 组" % (len(nums), len(groups)))
    out = {}
    for n, sources in zip(nums, groups):
        for name, data in sources[1:]:
            m = re.match(r"^Decrypted (\S+) data$", name)
            if m:
                out[int(n)] = {"method": m.group(1), "plain": data}
    return out


def baseline():
    keys = parse_keys()
    d = fetch_samples.SAMPLE_DIR
    total = 0
    for name in sorted(os.listdir(d)):
        path = os.path.join(d, name)
        prot = subprocess.run(["tshark", "-r", path, "-Y", "wlan.fc.protected==1", "-T", "fields", "-e", "frame.number"],
                              capture_output=True, text=True).stdout.split()
        got = tshark_plain(path, keys)
        methods = {}
        for v in got.values():
            methods[v["method"]] = methods.get(v["method"], 0) + 1
        total += len(got)
        print("%-42s 受保护 %4d 帧  tshark 解出 %4d  %s" % (name, len(prot), len(got), methods))
    print("\n共 %d 帧 tshark 能解出明文" % total)


if __name__ == "__main__":
    fetch_samples.fetch()
    baseline()
