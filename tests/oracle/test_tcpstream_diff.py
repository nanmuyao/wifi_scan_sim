#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TCP 流重组对照 tshark 的「Follow TCP Stream」（-z follow,tcp,raw）：
  1. 真实抓包：wpa-Induction 解密后的 5 条 HTTP 连接，每个方向的字节逐字节相同；
  2. 合成抓包（scapy 构造的普通以太网 pcap）：按序、乱序、整段重传、部分重叠、序号回绕、中途开始、SYN+数据，两个方向各自对照。
缺口（丢包）不对照：tshark 对缺口的处理是它自己的策略，我们只承诺停在缺口前（tests/test_tcpstream.py）。"""
import logging
import os
import re
import subprocess
import sys
import tempfile

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, Ether, Raw, conf, wrpcap  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decrypt_oracle as d  # noqa: E402
import fetch_samples  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import net  # noqa: E402
from wifi80211 import pipeline as pl  # noqa: E402
from wifi80211 import tcpstream as ts  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def tshark_follow(path, extra=(), env=None):
    """-> {流号: {(ip, 端口, ip, 端口) 方向: 字节}}。"""
    run = lambda *a: subprocess.run(["tshark", "-r", path, *extra, *a], capture_output=True, text=True, env=env).stdout      # noqa: E731
    streams = sorted({int(x) for x in run("-Y", "tcp", "-T", "fields", "-e", "tcp.stream").split()})
    out = {}
    for n in streams:
        text = run("-q", "-z", "follow,tcp,raw,%d" % n)
        nodes = re.findall(r"Node (\d): (.+):(\d+)\n", text)
        ep = {int(i): (ip, int(p)) for i, ip, p in nodes}
        body = text.split("Node 1:")[1].split("\n", 1)[1] if "Node 1:" in text else ""
        got = {0: b"", 1: b""}
        for line in body.split("\n"):
            if line.startswith("="):
                break
            if line.strip():
                got[1 if line.startswith("\t") else 0] += bytes.fromhex(line.strip())
        out[n] = {ep[0] + ep[1]: got[0], ep[1] + ep[0]: got[1]}
    return out


def as_follow(direction):
    """我们的缺口表示成 tshark 在 Follow 里插的那行字：[N bytes missing in capture file] 加一个 NUL 字节（raw 模式下字符串带的结尾）。"""
    return b"".join(x if k == "data" else b"[%d bytes missing in capture file]\x00" % x for k, x in direction.pieces())


def compare(flows, follow, label):
    """每个 tshark 方向都能在我们这里找到同样的字节；返回 (方向数, 不同的方向)。"""
    bad, total = [], 0
    for n, dirs in follow.items():
        for key, want in dirs.items():
            total += 1
            mine = flows.dirs.get(key)
            got = as_follow(mine) if mine else b""
            if got != want:
                bad.append((n, key, len(want), len(got)))
    check(not bad, "%s：%d 个方向的字节和 tshark 的 Follow TCP Stream 逐字节相同（不同 %s）" % (label, total, bad[:3]))
    return total


EXPECT_REAL = (29427, 16119, 4)
print("== 真实抓包：wpa-Induction ==")
fetch_samples.fetch()
keys = d.parse_keys()
path = os.path.join(fetch_samples.SAMPLE_DIR, "wpa-Induction.pcap.gz")
res = pl.decrypt_capture(list(fr.iter_frames(path)), keys)
flows = ts.Flows()
for n, v in res.items():
    for m in v["msdus"]:
        ds = net.describe(m)
        if ds and "tcp" in ds and "ipv4" in ds["layers"]:
            flows.add(ds["ip"]["src"], ds["ip"]["dst"], ds["tcp"], n)
usable, _ = d.tshark_usable(keys)
with d.key_env(usable) as env:
    follow = tshark_follow(path, d.TSHARK_DECRYPT, env)
total = compare(flows, follow, "wpa-Induction")
full = sum(len(b) for x in flows.dirs.values() for k, b in x.pieces() if k == "data")
contiguous = sum(len(x.data()) for x in flows.dirs.values())
gaps = sum(x.gap for x in flows.dirs.values())
check(len(follow) == 5 and total == 10 and (full, contiguous, gaps) == (EXPECT_REAL), "5 条连接 10 个方向：数据共 %d 字节，其中从起点连续的 %d 字节，%d 个方向中途缺包（这个样例本身漏抓了包）" % (full, contiguous, gaps))

print("== 合成抓包 ==")
A, B = "10.1.1.2", "10.1.1.9"
pkts = []


def conn(sport, isn_c, isn_s, c2s, s2c, order=None, dup=(), syn=True):
    """一条连接：c2s / s2c 是 [(相对偏移, 数据)]；order 重排客户端的发送顺序；dup 里的下标重发一遍。"""
    p = []
    if syn:
        p += [Ether() / IP(src=A, dst=B) / TCP(sport=sport, dport=443, seq=isn_c, flags="S"),
              Ether() / IP(src=B, dst=A) / TCP(sport=443, dport=sport, seq=isn_s, ack=isn_c + 1, flags="SA"),
              Ether() / IP(src=A, dst=B) / TCP(sport=sport, dport=443, seq=isn_c + 1, ack=isn_s + 1, flags="A")]
    cs = [Ether() / IP(src=A, dst=B) / TCP(sport=sport, dport=443, seq=(isn_c + 1 + off) & 0xFFFFFFFF, flags="PA") / Raw(x) for off, x in c2s]
    cs = [cs[i] for i in (order or range(len(cs)))] + [cs[i] for i in dup]
    ss = [Ether() / IP(src=B, dst=A) / TCP(sport=443, dport=sport, seq=(isn_s + 1 + off) & 0xFFFFFFFF, flags="PA") / Raw(x) for off, x in s2c]
    return p + cs + ss


msg = bytes(range(256)) * 2
pkts += conn(40001, 1000, 9000, [(0, msg[:100]), (100, msg[100:250]), (250, msg[250:])], [(0, b"srv-hello"), (9, b" world")])
pkts += conn(40002, 1000, 9000, [(0, msg[:100]), (100, msg[100:250]), (250, msg[250:])], [(0, b"x")], order=[2, 0, 1])
pkts += conn(40003, 1000, 9000, [(0, msg[:100]), (100, msg[100:250]), (250, msg[250:])], [(0, b"x")], dup=[0, 2, 1])
pkts += conn(40004, 1000, 9000, [(0, msg[:120]), (100, msg[100:250]), (240, msg[240:])], [(0, b"x")])
pkts += conn(40005, 0xFFFFFF80, 0xFFFFFFF0, [(0, msg[:100]), (100, msg[100:250]), (250, msg[250:])], [(0, b"0123456789" * 5), (50, b"tail")])
pkts += conn(40006, 1000, 9000, [(100, msg[100:250]), (250, msg[250:])], [(0, b"x")], syn=False)
wrpcap(os.path.join(tempfile.gettempdir(), "tcpstream_synth.pcap"), pkts)
synth = os.path.join(tempfile.gettempdir(), "tcpstream_synth.pcap")
flows = ts.Flows()
for p in pkts:
    ip = net.parse_ipv4(bytes(p[IP]))
    t = net.parse_tcp(ip["payload"], ip)
    flows.add(ip["src"], ip["dst"], t)
follow = tshark_follow(synth)
compare(flows, follow, "合成的 6 条连接")
check(len(follow) == 6 and flows.dirs[(A, 40001, B, 443)].data() == msg and flows.dirs[(A, 40004, B, 443)].data() == msg[:120] + msg[120:250] + msg[250:], "6 条连接都被识别；部分重叠的那条拼回完整的 512 字节")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
