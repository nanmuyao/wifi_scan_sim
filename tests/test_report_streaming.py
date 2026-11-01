#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""命令行报告里的「持续下行」一节：明文抓包里一台设备对一个有规则的应用连续 60 秒、约 100 KB/s 地收数据，另一台只有零星心跳；
检查表格和 json 里的内容，三个 --stream-* 参数的作用和检查，--device 的过滤，以及没有时段时整节不出现。
机制本身的测试见 test_streaming.py；默认参数没有用真实数据标定，这里不证明门槛合适。"""
import json
import logging
import os
import struct
import subprocess
import sys
import tempfile

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, Raw, TCP, conf  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import tls_build as tb  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


RTR = "02:00:00:00:00:fe"
DEV1, DEV2, DEV3 = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"
LAN1, LAN2, LAN3, SRV = "192.168.1.20", "192.168.1.21", "192.168.1.22", "203.0.113.80"
T0 = 1_700_000_000.0


def tcp(dev, lan, port, up, flags, payload, seq=1, ack=1):
    ip = IP(src=lan, dst=SRV) / TCP(sport=port, dport=443, flags=flags, seq=seq, ack=ack) if up else IP(src=SRV, dst=lan) / TCP(sport=443, dport=port, flags=flags, seq=seq, ack=ack)
    return bytes((Ether(src=dev, dst=RTR) if up else Ether(src=RTR, dst=dev)) / ip / Raw(payload))


packets = []
hello = tb.records(tb.hello([tb.sni_ext("v.video.example"), tb.alpn_ext("h2")]))
packets.append((T0, tcp(DEV1, LAN1, 40000, True, "PA", hello)))
seq = 1
for i in range(4300):                                   # 60 秒、每包 1400 字节、约 100 KB/s 的下行
    packets.append((T0 + 0.5 + i * 60.0 / 4300, tcp(DEV1, LAN1, 40000, False, "A", b"v" * 1400, seq=seq)))
    seq += 1400
hello2 = tb.records(tb.hello([tb.sni_ext("v.video.example"), tb.alpn_ext("h2")]))
packets.append((T0, tcp(DEV2, LAN2, 41000, True, "PA", hello2)))
for i in range(12):                                     # 另一台：每 5 秒一个小包的心跳
    packets.append((T0 + 1 + i * 5, tcp(DEV2, LAN2, 41000, False, "A", b"h" * 100)))
# DEV3：同一家公司的两个应用（甲、乙）各约 30 KB/秒，单看都低于默认门槛 50，合起来 60；另有一条没有名字（抓包前就建立）的流约 10 KB/秒
for port, sni in ((42000, "a.co1.example"), (42001, "b.co2.example")):
    packets.append((T0, tcp(DEV3, LAN3, port, True, "PA", tb.records(tb.hello([tb.sni_ext(sni), tb.alpn_ext("h2")])))))
    for i in range(1286):                                 # 60 秒、约 30 KB/秒
        packets.append((T0 + 0.5 + i * 60.0 / 1286, tcp(DEV3, LAN3, port, False, "A", b"v" * 1400, seq=1 + i * 1400)))
for i in range(429):                                      # 60 秒、约 10 KB/秒，没有 ClientHello
    packets.append((T0 + 0.5 + i * 60.0 / 429, tcp(DEV3, LAN3, 42002, False, "A", b"u" * 1400, seq=1 + i * 1400)))
packets.sort(key=lambda p: p[0])

tmp = tempfile.mkdtemp()
cap = os.path.join(tmp, "s.pcap")
out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
for ts, b in packets:
    out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(b), len(b)) + b
open(cap, "wb").write(out)
rules = os.path.join(tmp, "r.json")
APPS = [{"app": "视频应用", "category": "视频", "suffix": ["video.example"]},
        {"app": "甲应用", "category": "视频", "suffix": ["co1.example"], "company": "某公司"}, {"app": "乙应用", "category": "社交", "suffix": ["co2.example"], "company": "某公司"}]
json.dump({"apps": APPS}, open(rules, "w"), ensure_ascii=False)
rules_nocompany = os.path.join(tmp, "r2.json")
json.dump({"apps": [{k: v for k, v in a.items() if k != "company"} for a in APPS]}, open(rules_nocompany, "w"), ensure_ascii=False)
env = dict(os.environ, TZ="UTC", PYTHONPATH=ROOT)


def cli(*args, rules_file=None):
    p = subprocess.run([sys.executable, "-m", "wifi80211.report", "--no-log-file", cap, "--rules", rules_file or rules] + list(args), capture_output=True, text=True, env=env, cwd=ROOT)
    return p.returncode, p.stdout, p.stderr


print("== 表格 ==")
rc, o, e = cli()
check(rc == 0 and "持续下行的时段" in o, "有持续下行：表格里有这一节")
rc1, o1, e1 = cli("--device", DEV1)
sec = o1.split("持续下行的时段")[1].split("\n其它流量")[0] if "持续下行的时段" in o1 else ""
check("视频应用" in sec and "合计 1.0 分钟，1 个时段" in sec, "视频应用：合计 1.0 分钟、1 个时段（60 秒）")
check("2023-11-14T22:13:2" in sec and "平均 1" in sec, "起点是抓包里的时间（UTC），平均速率约 100 KB/秒")
check(o.count("持续下行的时段") == 2, "DEV1 和 DEV3 各有这一节（两台），心跳的 DEV2 没有")
check("持续下行的门槛：" in o and "没有用真实数据标定过" in o, "表格末尾说明门槛和「未标定」")
check("没有名字的流" not in o1, "DEV1 的流都有名字：不写「没有名字的流」那一行")
check("在刷" not in o, "措辞里没有「在刷」之类的结论")

print("== json ==")
rc, o, e = cli("--format", "json")
doc = json.loads(o)
dv = {d["mac"]: d for d in doc["devices"]}
st = dv[DEV1]["streaming"]
check(len(st) == 1 and st[0]["app"] == "视频应用" and st[0]["seconds"] == 60 and len(st[0]["episodes"]) == 1, "json：DEV1 的 streaming 一个应用、60 秒、1 个时段")
ep = st[0]["episodes"][0]
check(ep["seconds"] == 60 and ep["end"] - ep["start"] == 60 and 90000 < ep["avg_rate"] < 115000, "时段起止差 60 秒，平均速率约 100 KB/秒（%.0f）" % ep["avg_rate"])
check("streaming" not in dv[DEV2], "json：心跳的设备没有 streaming")
check(doc["streaming_params"] == {"min_rate": 50000, "min_seconds": 30, "max_gap": 15}, "json：记下了用的参数（默认值）")

print("== 同一家公司合起来 ==")
rc, o, e = cli("--device", DEV3)
sec3 = o.split("持续下行的时段")[1].split("\n其它流量")[0] if "持续下行的时段" in o else ""
check("某公司（乙应用、甲应用）" in sec3 or "某公司（甲应用、乙应用）" in sec3, "两个应用并成一行「某公司（…）」，列出成员")
check("合计 1.0 分钟，1 个时段" in sec3, "合起来 60 秒 1 个时段")
check("没有名字的流" in sec3 and "占这台设备下行的" in sec3, "写出没有名字的流不在统计里，以及它占这台设备下行的比例")
import re  # noqa: E402
m = re.search(r"占这台设备下行的 (\d+)%", sec3)
check(m is not None and 14 <= int(m.group(1)) <= 18, "比例约 1/6（10 / 70 KB/秒）：%s%%" % (m.group(1) if m else None))
rc, o, e = cli("--format", "json")
dv = {d["mac"]: d for d in json.loads(o)["devices"]}
st3 = dv[DEV3]["streaming"]
check(len(st3) == 1 and st3[0]["app"] == "某公司" and st3[0]["apps"] == ["乙应用", "甲应用"] or st3[0]["apps"] == ["甲应用", "乙应用"], "json：app 是公司名，apps 是成员")
check(dv[DEV3]["streaming_unnamed"]["bytes_down"] > 0 and dv[DEV3]["streaming_unnamed"]["total_down"] > dv[DEV3]["streaming_unnamed"]["bytes_down"], "json：streaming_unnamed 有没有名字的下行字节和总下行字节")
check(dv[DEV1]["streaming"][0]["apps"] == ["视频应用"], "没写 company 的应用，apps 就是它自己")
rc, o, e = cli("--format", "json", rules_file=rules_nocompany)
dv = {d["mac"]: d for d in json.loads(o)["devices"]}
check("streaming" not in dv[DEV3] and "streaming" in dv[DEV1], "规则里不写 company：甲、乙各自单看都不够门槛，DEV3 没有时段（DEV1 照旧）")

print("== 参数 ==")
rc, o, e = cli("--stream-rate", "500")
check(rc == 0 and "持续下行的时段" not in o and "持续下行的门槛" not in o, "--stream-rate 500（KB/秒）：门槛高过了，整节不出现")
rc, o, e = cli("--stream-min-seconds", "90")
check(rc == 0 and "持续下行的时段" not in o, "--stream-min-seconds 90：60 秒的不够长，整节不出现")
rc, o, e = cli("--stream-rate", "0.02", "--stream-min-seconds", "20", "--device", DEV2)
check(rc == 0 and "持续下行的时段" in o and DEV1 not in o and DEV3 not in o, "门槛放得很低 + --device：只看心跳那台，它也成了时段，别的设备不出现")
rc, o, e = cli("--device", DEV2)
check(rc == 0 and "持续下行" not in o, "--device 只看没有时段的那台：另一台的时段不会让整节或门槛说明出现")
for args in (("--stream-rate", "0"), ("--stream-min-seconds", "0"), ("--stream-gap", "-1")):
    rc, o, e = cli(*args)
    check(rc == 2 and "--stream" in e and not o, "%s：退出码 2，说明原因" % " ".join(args))

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(1 if failures else 0)
