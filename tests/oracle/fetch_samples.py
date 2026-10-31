#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
下载对照用的公开样例抓包（Wireshark 仓库 test/captures/ 里的 802.11 / WPA 样例）。

- 固定到 samples.json 里记录的 Wireshark 提交，并校验每个文件的 sha256；
  校验不通过就报错并删除该文件，不会静默使用被改过的样例。
- 下载到 tests/oracle/samples/（已加入 .gitignore）。样例来自 Wireshark 的 GPL 源码树，
  本项目是 MIT：只收录下载脚本和校验值，不收录样例文件本身。
- 已经下载且校验通过的文件不会重复下载。

用法：python3 tests/oracle/fetch_samples.py        # 需要网络，只在缺文件时联网
"""
import hashlib
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "samples.json")
SAMPLE_DIR = os.path.join(HERE, "samples")
EXTRAS_DIR = SAMPLE_DIR + "_extras"
URL = "https://raw.githubusercontent.com/wireshark/wireshark/%s/test/captures/%s"
EXTRA_URL = "https://raw.githubusercontent.com/wireshark/wireshark/%s/%s"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(manifest=MANIFEST, dest=SAMPLE_DIR, opener=urllib.request.urlopen):
    """保证 manifest 里的文件都在 dest 里且校验通过，返回 (已有, 新下载) 数量。失败抛 RuntimeError。"""
    with open(manifest, encoding="utf-8") as f:
        m = json.load(f)
    extras_dir = dest.rstrip(os.sep) + "_extras"      # 不放进抓包目录：很多测试把那个目录里的每个文件都当抓包读
    os.makedirs(dest, exist_ok=True)
    os.makedirs(extras_dir, exist_ok=True)
    have = got = 0
    # 抓包文件 + 其它固定到同一提交的文件（Wireshark 测试用的密钥表、含期望密钥值的测试脚本）
    todo = [(dest, name, want, URL % (m["wireshark_commit"], name)) for name, want in sorted(m["files"].items())]
    todo += [(extras_dir, name, e["sha256"], EXTRA_URL % (m["wireshark_commit"], e["path"])) for name, e in sorted(m.get("extras", {}).items())]
    for where, name, want, url in todo:
        path = os.path.join(where, name)
        if os.path.exists(path):
            if sha256(path) == want:
                have += 1
                continue
            os.remove(path)          # 校验不过的旧文件：删掉重下
        data = opener(url).read()
        if hashlib.sha256(data).hexdigest() != want:
            raise RuntimeError("%s: sha256 与 samples.json 不符，不使用" % name)
        with open(path, "wb") as f:
            f.write(data)
        got += 1
    return have, got


def main():
    try:
        have, got = fetch()
    except Exception as exc:
        print("样例准备失败: %s" % exc)
        return 1
    print("样例就绪：已有 %d 个，新下载 %d 个（%s）" % (have, got, SAMPLE_DIR))
    return 0


if __name__ == "__main__":
    sys.exit(main())
