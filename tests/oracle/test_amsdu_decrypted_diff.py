#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CCMP 加密的 A-MSDU 经过 解密 -> 拆子帧 -> 事件 / 流量 的整条链，对照 tshark。
802.11ac 的下行（看视频的主要流量）常把多个包聚合进一个 QoS 数据帧（QoS Control bit 7）。样例里唯一的 A-MSDU 是解不开的 wpa-mlo-ccmp，
tests/test_pipeline.py 只用 WEP 测过拆分，所以「解密之后的路径会把 A-MSDU 拆开」之前没有真实对照。这里用独立加密方（tests/aead_build.py）合成：
上行 / 下行、1–3 个子帧、各种填充长度、一个帧里的 TLS ClientHello 分成两个子帧、DNS 应答与 SYN-ACK 聚在一起，只给一把 TK，
让 tshark（同一把 TK）逐帧数出 IP 包、地址、长度、域名，和我们逐项比；再比整条链的字节数（视频流量不能悄悄少）。
最后几个帧置位 A-MSDU 但帧体不是合法的 A-MSDU：不崩溃，日志里要说。"""
import logging
import os
import struct
import subprocess
import sys
import tempfile

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aead_build as ab  # noqa: E402
import decrypt_oracle as d  # noqa: E402
import tls_build as tb  # noqa: E402
from wifi80211 import activity, amsdu, net, traffic  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import pipeline as pl  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


TK = bytes.fromhex("5b6a79889796a5b4c3d2e1f00f1e2d3c")
AP, STA, GW, OTHER = bytes.fromhex("1a1b1c1d1e1f"), bytes.fromhex("2a2b2c2d2e2f"), bytes.fromhex("3a3b3c3d3e3f"), bytes.fromhex("4a4b4c4d4e4f")
LAN, DNS_IP, SRV, WEB = "192.168.7.20", "192.168.7.1", "203.0.113.80", "198.51.100.9"
SNAP = b"\xaa\xaa\x03\x00\x00\x00\x08\x00"
AMSDU, TID = 0x0080, 5
pn = [0]
out = []


def sub(da, sa, pkt, pad=True):
    """A-MSDU 子帧：DA 6 + SA 6 + 长度 2（大端，不含填充）+ LLC/SNAP + IP 包，非最后一个填充到 4 字节的整数倍。"""
    body = SNAP + bytes(pkt)
    s = da + sa + struct.pack(">H", len(body)) + body
    return s + (bytes((-len(s)) % 4) if pad else b"")


def send(ts, body, up, qos):
    """一个明文帧体 -> 加密的 802.11 数据帧。A-MSDU 帧的地址 3 是 BSSID（标准规定），不是子帧里的 DA / SA。"""
    pn[0] += 1
    if up:
        ab.A2, ab.A3, a1, kw = STA, AP, AP, dict(to_ds=1, from_ds=0)
    else:
        ab.A2, ab.A3, a1, kw = AP, AP, STA, dict(to_ds=0, from_ds=1)
    out.append((ts, ab.build("CCMP-128", TK, pn[0], body, a1=a1, qos=qos, **kw)))


def send_amsdu(ts, pkts, up, ends_unpadded=True):
    """pkts：[IP 包]。上行子帧 DA = 网关、SA = 设备；下行 DA = 设备、SA = 网关。"""
    da, sa = (GW, STA) if up else (STA, GW)
    parts = [sub(da, sa, p, pad=not (ends_unpadded and i == len(pkts) - 1)) for i, p in enumerate(pkts)]
    send(ts, b"".join(parts), up, AMSDU | TID)


t = 1700000000.0
CH = tb.records(tb.hello([tb.sni_ext("video.example.org"), tb.alpn_ext("h2")]))
http = b"GET /v HTTP/1.1\r\nHost: Cdn.Example.net:80\r\nUser-Agent: t\r\n\r\n"
big = lambda n, seq: IP(src=SRV, dst=LAN) / TCP(sport=443, dport=41000, seq=seq, ack=1000, flags="PA") / Raw(bytes([n % 251]) * n)      # noqa: E731
q = lambda: IP(src=LAN, dst=DNS_IP) / UDP(sport=50123, dport=53) / DNS(id=7, qd=DNSQR(qname="video.example.org"))                       # noqa: E731
a = lambda: IP(src=DNS_IP, dst=LAN) / UDP(sport=53, dport=50123) / DNS(id=7, qr=1, qd=DNSQR(qname="video.example.org"), an=DNSRR(rrname="video.example.org", type="A", rdata=SRV))   # noqa: E731

# 1 上行，3 个子帧：DNS 查询、两个 SYN
send_amsdu(t, [q(), IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=100, flags="S"), IP(src=LAN, dst=WEB) / TCP(sport=41001, dport=80, seq=500, flags="S")], up=True)
# 2 下行，2 个子帧：DNS 应答、SYN-ACK
send_amsdu(t + .01, [a(), IP(src=SRV, dst=LAN) / TCP(sport=443, dport=41000, seq=900, ack=101, flags="SA")], up=False)
# 3 下行，不聚合（QoS 但 A-MSDU 位没置）：对照
send(t + .02, SNAP + bytes(IP(src=WEB, dst=LAN) / TCP(sport=80, dport=41001, seq=700, ack=501, flags="SA")), False, TID)
# 4 上行，3 个子帧：ClientHello 的前 40 字节、其余、HTTP 请求——同一个帧里分成两个子帧的 ClientHello 要拼起来
send_amsdu(t + .03, [IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=101, ack=901, flags="PA") / Raw(CH[:40]),
                IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=141, ack=901, flags="PA") / Raw(CH[40:]),
                IP(src=LAN, dst=WEB) / TCP(sport=41001, dport=80, seq=501, ack=701, flags="PA") / Raw(http)], up=True)
# 5 下行，1 个子帧（A-MSDU 位置位但只有一个子帧）
send_amsdu(t + .04, [big(1200, 901)], up=False)
# 6 下行，3 个大子帧，长度除以 4 余 1、3、0：把填充的每种情况都走到（视频的典型形态）
send_amsdu(t + .05, [big(1397, 2101), big(1399, 3498), big(1401, 4897)], up=False)
# 7 上行，2 个子帧，第一个的 DA / SA 是设备身后的另一台机器（桥接）——设备仍然是帧头里的 STA
send(t + .06, sub(OTHER, STA, IP(src=LAN, dst=SRV) / TCP(sport=41000, dport=443, seq=1000, ack=6298, flags="A")) +
    sub(GW, OTHER, IP(src="192.168.7.99", dst=SRV) / TCP(sport=42000, dport=443, seq=1, flags="S"), pad=False), True, AMSDU | TID)
GOOD = len(out)
# 8 置位 A-MSDU 但帧体只有 7 字节：连一个子帧头都不够
send(t + 1, b"\x01\x02\x03\x04\x05\x06\x07", False, AMSDU | TID)
# 9 第一个子帧合法，第二个声明的长度超过剩余
send(t + 1.01, sub(STA, GW, IP(src=SRV, dst=LAN) / TCP(sport=443, dport=41000, seq=7000, ack=1000, flags="PA") / Raw(b"x" * 30)) + STA + GW + struct.pack(">H", 900) + SNAP + b"short", False, AMSDU | TID)
# 10 置位 A-MSDU，帧体是一个普通的 LLC/SNAP + IP 包（发送方忘了聚合）：头 14 字节当子帧头读，长度字段是乱的
send(t + 1.02, SNAP + bytes(IP(src=SRV, dst=LAN) / TCP(sport=443, dport=41000, seq=8000, ack=1000, flags="PA") / Raw(b"y" * 60)), False, AMSDU | TID)

path = os.path.join(tempfile.mkdtemp(), "amsdu.pcap")
with open(path, "wb") as f:                                              # 经典 pcap，链路类型 105 = 裸 802.11
    f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105))
    for ts, dot11 in out:
        f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(dot11), len(dot11)) + dot11)
keys = [("tk", TK.hex())]

records = []
class Grab(logging.Handler):                                               # noqa: E302
    def emit(self, r):
        records.append((r.levelno, r.getMessage()))


lg = logging.getLogger("wifi80211")
lg.addHandler(Grab())
old_level = lg.level
lg.setLevel(logging.DEBUG)
frames = list(fr.iter_frames(path))
res = pl.decrypt_capture(frames, keys)
lg.setLevel(old_level)

print("== 解密 + 拆子帧 ==")
check(len(frames) == len(out) == 10 and sorted(res) == list(range(1, 11)), "10 个加密帧全部解开（含 3 个 A-MSDU 帧体不合法的）")
check({f.n for f in frames if f.h["qos"]["amsdu"]} == set(range(1, 11)) - {3}, "QoS Control 的 A-MSDU 位：除了第 3 个（没聚合）都置位")
want_counts = {1: 3, 2: 2, 3: 1, 4: 3, 5: 1, 6: 3, 7: 2}
check({n: len(res[n]["msdus"]) for n in want_counts} == want_counts, "每个帧拆出的 MSDU 个数：%s" % want_counts)
sizes = {n: [len(m) - 8 for m in res[n]["msdus"]] for n in (5, 6)}
check(sizes == {5: [1200 + 40], 6: [1397 + 40, 1399 + 40, 1401 + 40]}, "大子帧的 IP 包长度不被填充污染（%s）" % sizes)

print("== 与 tshark 逐帧对照（同一把 TK）==")
usable, _ = d.tshark_usable(keys)
with d.key_env(usable) as env:
    cmd = ["tshark", "-r", path] + d.TSHARK_DECRYPT + ["-T", "fields", "-E", "occurrence=a", "-E", "separator=/t", "-E", "aggregator=,", "-e", "frame.number", "-e", "wlan.qos.amsdupresent",
                                                       "-e", "ip.src", "-e", "ip.dst", "-e", "ip.len", "-e", "dns.qry.name", "-e", "tls.handshake.extensions_server_name", "-e", "http.host", "-e", "dns.flags.response"]
    rows = {}
    for l in subprocess.run(cmd, capture_output=True, text=True, env=env).stdout.split("\n"):
        if l:
            c = l.split("\t") + [""] * 9
            rows[int(c[0])] = c[1:9]
check(sorted(rows) == list(range(1, 11)), "tshark 看到的也是这 10 个帧")


def ours_ip(n):
    r = []
    for m in res[n]["msdus"]:
        dsc = net.describe(m)
        if dsc and "ip" in dsc:
            r.append((dsc["ip"]["src"], dsc["ip"]["dst"], dsc["ip"]["total_length"]))
    return r


def theirs_ip(n):
    r = rows[n]
    return list(zip(r[1].split(","), r[2].split(","), [int(x) for x in r[3].split(",")])) if r[1] else []


for n in range(1, 11):
    o, th = ours_ip(n), theirs_ip(n)
    check(o == th, "第 %d 帧：%d 个 IP 包，源 / 目的 / 总长度与 tshark 逐个相同%s" % (n, len(o), "" if o == th else "（我们 %s，tshark %s）" % (o, th)))

pl_t = d.tshark_plain(path, keys)
check(all(n in pl_t for n in range(1, 11)), "tshark 对 10 个帧都解出了明文")

print("== 事件与流量（整条链）==")
ev = activity.build(frames, res)
ours = sorted((e["kind"], e["name"]) for e in ev)
want = sorted([("dns", "video.example.org"), ("tls", "video.example.org"), ("http", "cdn.example.net")])
theirs = []
for n in range(1, 11):
    r = rows[n]
    if r[4] and r[7].split(",")[0] == "False":                           # 应答里也有 dns.qry.name，只数查询
        theirs.append(("dns", r[4].split(",")[0]))
    if r[5]:
        theirs.append(("tls", r[5]))
    if r[6]:
        theirs.append(("http", r[6].lower().split(":")[0]))
check(ours == want == sorted(theirs), "事件：DNS 查询、拆成两个子帧的 TLS SNI、HTTP Host，与 tshark 读到的相同%s" % ("" if ours == want else "（我们 %s）" % ours))
check({e["station"] for e in ev} == {":".join("%02x" % b for b in STA)}, "所有事件归到帧头里的那台设备（子帧里的 DA / SA 不影响设备归属，地址 3 是 BSSID 也不影响）")

res_c = activity.analyze(frames, res)
fl = traffic.flows(res_c)
up = sum(f["bytes_up"] for f in fl)
down = sum(f["bytes_down"] for f in fl)
t_up = t_down = 0
for n in range(1, 11):
    s = sum(int(x) for x in rows[n][3].split(",") if x)
    if n in (1, 4, 7):
        t_up += s
    else:
        t_down += s
check(down == t_down and t_down > 4000, "下行字节：我们 %d，tshark 的 ip.len 之和 %d（视频形态的下行不能少）" % (down, t_down))
check(up == t_up and t_up > 0, "上行字节：我们 %d，tshark 的 ip.len 之和 %d（含设备身后那台机器 192.168.7.99 的 SYN：它从这台设备的帧里发出，算在这台设备名下）" % (up, t_up))
check(len(fl) == 4, "流 %d 条：DNS、两条 TCP、设备身后那台机器的一条" % len(fl))

print("== 置位 A-MSDU 但帧体不合法的帧 ==")
check([len(res[n]["msdus"]) for n in (8, 9, 10)] == [len(amsdu.parse(pl_t[n]["plain"])["subframes"]) for n in (8, 9, 10)] == [0, 2, 2],
      "不够一个子帧头：0 个 MSDU；第一个合法、第二个声明超长：2 个（超长的那个只剩残片，不是 IP 包）；整包当子帧读：长度字段是乱的，2 个残片：%s" % [len(res[n]["msdus"]) for n in (8, 9, 10)])
check(all(len(ours_ip(n)) == (1 if n == 9 else 0) for n in (8, 9, 10)), "三个不合法的帧里认得出的 IP 包：只有第 9 帧那个合法子帧（与 tshark 一致），残片不被当成 IP 包")
text = "\n".join(m for _l, m in records)
check(any(l == logging.WARNING and "3 个帧的 A-MSDU 帧体不合法" in m and "帧 8、9、10" in m for l, m in records), "日志里说了：3 个帧的 A-MSDU 帧体不合法，例子是帧 8、9、10（WARNING）")
check(any(m == "A-MSDU：9 个帧拆出 18 个子帧" for _l, m in records), "日志里有 A-MSDU 的汇总：9 个帧拆出 18 个子帧")
st = {}
pl.decrypt_capture(frames, keys, st)
check(st["amsdu"] == {"frames": 9, "subframes": 18, "bad_frames": 3, "examples": [8, 9, 10]}, "stats['amsdu']：%s" % st["amsdu"])
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
