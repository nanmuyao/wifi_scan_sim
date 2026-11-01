# -*- coding: utf-8 -*-
"""
密钥文件：Wireshark「802.11 解密密钥」列表的文本格式，一行一把，`"类型","值"`，# 开头是注释，空行忽略。纯标准库。
  "wpa-pwd","口令"  或  "wpa-pwd","口令:SSID"     口令（SSID 缺省时用抓包里看到的）
  "wpa-psk","64 位十六进制"                        直接给 PMK（SAE-EXT-KEY 等 64 字节的是 128 位十六进制）
  "msk","十六进制"                                 802.1X 的 MSK
  "wep","十六进制"                                 WEP 密钥（5 / 13 / 16 字节）
  "tk","十六进制"                                  直接给成对临时密钥 TK（16 / 32 字节）
解析出来是 [(类型, 值)]，就是 pipeline.decrypt_capture 的 keys 参数。读错的行只报行号和类型，不把值写进错误信息。
"""
import re

TYPES = ("wpa-pwd", "wpa-psk", "msk", "wep", "tk")
HEX_TYPES = ("wpa-psk", "msk", "wep", "tk")
LINE = re.compile(r'^"([^"]+)"\s*,\s*"([^"]*)"\s*$')


def parse_text(text):
    keys = []
    for no, line in enumerate(text.split("\n"), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE.match(line)
        if not m:
            raise ValueError("第 %d 行格式不对：每行应是 \"类型\",\"值\"" % no)
        typ, val = m.group(1), m.group(2)
        if typ not in TYPES:
            raise ValueError("第 %d 行：不认识的密钥类型 %r（可用：%s）" % (no, typ, "、".join(TYPES)))
        if not val:
            raise ValueError("第 %d 行：%s 的值是空的" % (no, typ))
        if typ in HEX_TYPES:
            try:
                bytes.fromhex(val)
            except ValueError:
                raise ValueError("第 %d 行：%s 的值不是十六进制" % (no, typ)) from None
        keys.append((typ, val))
    return keys


def parse(path):
    with open(path, encoding="utf-8") as f:
        return parse_text(f.read())


def summary(keys):
    """{类型: 个数}，用来告诉用户读到了什么，不含任何值。"""
    out = {}
    for typ, _ in keys:
        out[typ] = out.get(typ, 0) + 1
    return out
