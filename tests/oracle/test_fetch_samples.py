#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fetch_samples 的离线测试：用假下载器，不联网。"""
import hashlib
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_samples as fs  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


GOOD = b"good bytes"


def manifest(tmp, want=None):
    path = os.path.join(tmp, "m.json")
    with open(path, "w") as f:
        json.dump({"wireshark_commit": "abc", "files": {"a.pcap.gz": want or hashlib.sha256(GOOD).hexdigest()}}, f)
    return path


def opener_for(data, calls):
    def op(url):
        calls.append(url)
        return io.BytesIO(data)
    return op


with tempfile.TemporaryDirectory() as tmp:
    dest = os.path.join(tmp, "s")
    m = manifest(tmp)
    calls = []

    print("== 下载并校验 ==")
    check(fs.fetch(m, dest, opener_for(GOOD, calls)) == (0, 1), "第一次：下载 1 个")
    check(calls == ["https://raw.githubusercontent.com/wireshark/wireshark/abc/test/captures/a.pcap.gz"],
          "按固定提交的地址下载")
    check(fs.fetch(m, dest, opener_for(GOOD, calls)) == (1, 0) and len(calls) == 1, "第二次：命中缓存，不联网")

    print("== 被改过的本地文件 ==")
    with open(os.path.join(dest, "a.pcap.gz"), "ab") as f:
        f.write(b"x")
    check(fs.fetch(m, dest, opener_for(GOOD, calls)) == (0, 1), "校验不过：删掉重下")
    with open(os.path.join(dest, "a.pcap.gz"), "rb") as f:
        check(f.read() == GOOD, "重下后内容恢复")

    print("== 本地文件被改过，而且重下也失败（断网） ==")
    with open(os.path.join(dest, "a.pcap.gz"), "ab") as f:
        f.write(b"x")

    def offline(url):
        raise OSError("offline")
    try:
        fs.fetch(m, dest, offline)
        check(False, "应当报错")
    except OSError:
        check(True, "报错")
    check(not os.path.exists(os.path.join(dest, "a.pcap.gz")), "坏文件不残留，下次不会被误用")
    with open(os.path.join(dest, "a.pcap.gz"), "wb") as f:
        f.write(GOOD)

    print("== 下载内容与校验值不符 ==")
    os.remove(os.path.join(dest, "a.pcap.gz"))
    try:
        fs.fetch(m, dest, opener_for(b"tampered", calls))
        check(False, "应当报错")
    except RuntimeError:
        check(True, "报错，不使用该文件")
    check(not os.path.exists(os.path.join(dest, "a.pcap.gz")), "不留下校验失败的文件")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
