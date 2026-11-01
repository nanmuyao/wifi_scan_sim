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
DEV1, DEV2 = "02:00:00:00:00:01", "02:00:00:00:00:02"
LAN1, LAN2, SRV = "192.168.1.20", "192.168.1.21", "203.0.113.80"
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
packets.sort(key=lambda p: p[0])

tmp = tempfile.mkdtemp()
cap = os.path.join(tmp, "s.pcap")
out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
for ts, b in packets:
    out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(b), len(b)) + b
open(cap, "wb").write(out)
rules = os.path.join(tmp, "r.json")
json.dump({"apps": [{"app": "视频应用", "category": "视频", "suffix": ["video.example"]}]}, open(rules, "w"), ensure_ascii=False)
env = dict(os.environ, TZ="UTC", PYTHONPATH=ROOT)


def cli(*args):
    p = subprocess.run([sys.executable, "-m", "wifi80211.report", "--no-log-file", cap, "--rules", rules] + list(args), capture_output=True, text=True, env=env, cwd=ROOT)
    return p.returncode, p.stdout, p.stderr


print("== 表格 ==")
rc, o, e = cli()
check(rc == 0 and "持续下行的时段" in o, "有持续下行：表格里有这一节")
sec = o.split("持续下行的时段")[1].split("\n其它流量")[0] if "持续下行的时段" in o else ""
check("视频应用" in sec and "合计 1.0 分钟，1 个时段" in sec, "视频应用：合计 1.0 分钟、1 个时段（60 秒）")
check("2023-11-14T22:13:2" in sec and "平均 1" in sec, "起点是抓包里的时间（UTC），平均速率约 100 KB/秒")
check(o.count("持续下行的时段") == 1, "只有 DEV1 有这一节，心跳的 DEV2 没有")
check("持续下行的门槛：" in o and "没有用真实数据标定过" in o, "表格末尾说明门槛和「未标定」")
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

print("== 参数 ==")
rc, o, e = cli("--stream-rate", "500")
check(rc == 0 and "持续下行的时段" not in o and "持续下行的门槛" not in o, "--stream-rate 500（KB/秒）：门槛高过了，整节不出现")
rc, o, e = cli("--stream-min-seconds", "90")
check(rc == 0 and "持续下行的时段" not in o, "--stream-min-seconds 90：60 秒的不够长，整节不出现")
rc, o, e = cli("--stream-rate", "0.02", "--stream-min-seconds", "20", "--device", DEV2)
check(rc == 0 and "持续下行的时段" in o and DEV1 not in o, "门槛放得很低 + --device：只看心跳那台，它也成了时段，另一台不出现")
rc, o, e = cli("--device", DEV2)
check(rc == 0 and "持续下行" not in o, "--device 只看没有时段的那台：另一台的时段不会让整节或门槛说明出现")
for args in (("--stream-rate", "0"), ("--stream-min-seconds", "0"), ("--stream-gap", "-1")):
    rc, o, e = cli(*args)
    check(rc == 2 and "--stream" in e and not o, "%s：退出码 2，说明原因" % " ".join(args))

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(1 if failures else 0)
