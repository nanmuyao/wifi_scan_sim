#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""密钥文件（keyfile80211）和一条命令出报告（report80211）：解析与报错、汇总（排序、过滤、按设备）、三种输出格式、命令行的退出码与错误信息；
最后在真实样例 wpa-Induction 上把 CLI 当子进程跑一遍（口令对 / 错、--device、--rules、三种格式）。"""
import collections
import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import logging

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests", "oracle"))
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, conf, wrpcap  # noqa: E402
from wifi80211 import apps, keyfile, report  # noqa: E402

conf.verb = 0
import fetch_samples  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


print("== 密钥文件 ==")
t = '# 注释\n\n"wpa-pwd","pass:SSID"\n  "wpa-psk","%s"  \n"msk","%s"\n"wep","1234567890"\n"tk","%s"\n"wpa-pwd","a,b"\n' % ("ab" * 32, "cd" * 64, "ef" * 16)
check(keyfile.parse_text(t) == [("wpa-pwd", "pass:SSID"), ("wpa-psk", "ab" * 32), ("msk", "cd" * 64), ("wep", "1234567890"), ("tk", "ef" * 16), ("wpa-pwd", "a,b")], "五种类型都认；注释、空行、行首尾空白忽略；口令里可以有逗号和冒号")
check(keyfile.summary(keyfile.parse_text(t)) == {"wpa-pwd": 2, "wpa-psk": 1, "msk": 1, "wep": 1, "tk": 1} and keyfile.parse_text("") == [], "summary 只给类型和个数；空文件是空表")
for bad, line, why in (('"wpa-pwd","x"\nnonsense\n', 2, "不是 \"类型\",\"值\" 的行"), ('"wpa-pwd","x"\n"foo","bar"\n', 2, "不认识的类型"), ('"wep",""\n', 1, "空值"),
                       ('\n\n"wpa-psk","zz"\n', 3, "十六进制类型里有非十六进制字符"), ('"tk","abc"\n', 1, "奇数个十六进制字符")):
    try:
        keyfile.parse_text(bad)
        check(False, "拒绝：%s" % why)
    except ValueError as e:
        check("第 %d 行" % line in str(e), "拒绝：%s（报第 %d 行）" % (why, line))
try:
    keyfile.parse_text('"wpa-pwd","x" trailing\n')
    check(False, "拒绝：值后面还有别的内容")
except ValueError as e:
    check("第 1 行" in str(e), "拒绝：值后面还有别的内容（报第 1 行）")
try:
    keyfile.parse_text('"wpa-psk","SECRETVALUE"\n')
except ValueError as e:
    check("SECRETVALUE" not in str(e), "错误信息里不出现密钥的值")
try:
    keyfile.parse_text('"wpa-pwd","SECRETPASS"\nSECRETLINE\n')
except ValueError as e:
    check("SECRET" not in str(e), "格式不对的行，错误信息只报行号，不回显内容")

print("== 汇总 ==")
S1, S2, S3 = "02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"
ev = lambda ts, name, kind="dns", st=S1: {"ts": ts, "station": st, "kind": kind, "name": name, "frame": int(ts)}       # noqa: E731
R = apps.Rules()
R.add({"apps": [{"app": "甲", "category": "视频", "suffix": ["a.test"]}, {"app": "乙", "category": "社交", "suffix": ["b.test"]}]})
events = [ev(0, "x.a.test"), ev(10, "y.a.test", "tls"), ev(100, "z.b.test"), ev(101, "unk1.test"), ev(102, "unk1.test"), ev(103, "unk2.test"), ev(5, "w.a.test", "http", S2), ev(6, "q.test", "quic", S3), ev(7, "q.test", "quic", S3),
          ev(8, "r.local", "mdns", S3)]
rep = report.build(events, R, gap=60)
check([d["mac"] for d in rep["devices"]] == [S1, S3, S2] and [d["events"] for d in rep["devices"]] == [6, 3, 1], "设备按事件数降序（同数按 MAC）")
d1 = rep["devices"][0]
check([(r["app"], r["sessions"], r["events"], r["seconds"]) for r in d1["apps"]] == [("甲", 1, 2, 10.0), ("乙", 1, 1, 0.0)], "应用按估计秒数降序；0 秒的排后面")
check(d1["unlabelled"] == [["unk1.test", 2], ["unk2.test", 1]] and d1["kinds"] == {"dns": 5, "tls": 1}, "没有规则的域名按次数降序；各种事件的个数")
check(rep["devices"][1]["kinds"] == {"mdns": 1, "quic": 2} and rep["devices"][1]["unlabelled"] == [["q.test", 2]] and rep["devices"][1]["apps"] == [], "未知的事件种类（http / quic / mdns）照样显示；mdns 不进没规则的域名")
check([d["mac"] for d in report.build(events, R, device=S2)["devices"]] == [S2], "--device 只留这台")
check([d["mac"] for d in report.build(events, R, min_events=3)["devices"]] == [S1, S3] and len(report.build(events, R, min_events=7)["devices"]) == 0, "--min-events：少于 N 个事件的设备不显示（等于 N 的保留）")
check(len(report.build(events, R, top_unmatched=1)["devices"][0]["unlabelled"]) == 1 and report.build(events, R, top_unmatched=0)["devices"][0]["unlabelled"] == [], "--unmatched N 截断；0 就不列")
check([r["sessions"] for r in report.build(events, R, gap=5)["devices"][0]["apps"] if r["app"] == "甲"] == [2], "--gap 5：0 秒和 10 秒的两次访问分成两段")
check(report.norm_mac("02-00-00-00-00-AA") == "02:00:00:00:00:aa" and report.norm_mac("0200.0000.00aa") == "02:00:00:00:00:aa" and report.norm_mac("zz") is None and report.norm_mac("02:00:00:00:00") is None, "MAC 写法：冒号 / 横线 / 点、大小写都行；长度不对 None")

ev2 = [ev(0, "a.t1"), ev(0, "b.t2"), ev(0, "b.t2"), ev(0, "c.t3"), ev(0, "d.t4")]
R2 = apps.Rules()
R2.add({"apps": [{"app": "丁", "category": "c", "suffix": ["t4"]}, {"app": "丙", "category": "c", "suffix": ["t3"]}, {"app": "乙", "category": "c", "suffix": ["t2"]}, {"app": "甲", "category": "c", "suffix": ["t1"]}]})
check([r["app"] for r in report.build(ev2, R2, gap=10)["devices"][0]["apps"]] == ["乙", "丁", "丙", "甲"], "应用排序：秒数相同看事件数（乙有 2 个事件排第一），再相同按名字（丁 < 丙 < 甲）——不取决于事件出现的先后")
tie = [ev(0, "x.test", st=S3), ev(1, "y.test", st=S3), ev(0, "x.test", st=S1), ev(1, "y.test", st=S1)]
check([d["mac"] for d in report.build(tie, R)["devices"]] == [S1, S3], "设备排序：事件数相同按 MAC")
kinds = report.build([ev(0, "a.test", "tls"), ev(1, "a.test", "dns"), ev(2, "a.test", "quic")], R)["devices"][0]["kinds"]
check(list(kinds) == ["dns", "quic", "tls"], "事件种类按名字排好，输出稳定")
check(report.iso(1.5) == "1970-01-01T00:00:01" and report.iso(0) == "1970-01-01T00:00:00", "时间只到秒，不带小数")

print("== 输出格式 ==")
stats = {"frames": 9, "protected": 7, "decrypted": 6}
os.environ["TZ"] = "UTC"
import time  # noqa: E402
time.tzset()
tab = report.render_table(rep, stats)
check("7 个受保护的数据帧，解开 6 个" in tab and S1 in tab and "甲" in tab and "视频" in tab and "1970-01-01T00:00:00" in tab and "unk1.test" in tab, "表格：解密个数、设备、应用、类别、本地时间、没规则的域名")
check("没有能归到应用的域名" in tab and "没有规则的域名" in tab and "没有规则的域名" not in report.render_table(report.build(events, R, top_unmatched=0), stats), "没有应用的设备写明；没有「没规则的域名」时不印那一节标题")
check(tab.rstrip().endswith(report.LIMITS) and "不是屏幕使用时间" in tab and "DoH" in tab, "表格末尾有一句话说明局限")
check("没有看到任何设备" in report.render_table({"devices": []}, stats), "没有设备时说清楚")
j = json.loads(report.render_json(rep, stats))
check(j["frames"] == stats and j["limits"] == report.LIMITS and j["devices"][0]["mac"] == S1 and j["devices"][0]["apps"][0]["first_time"] == "1970-01-01T00:00:00" and j["devices"][0]["apps"][0]["first"] == 0 and j["devices"][0]["apps"][0]["last_time"] == "1970-01-01T00:00:10", "json：帧统计、局限、设备、应用（原始时间戳和本地时间都有）")
rows = list(csv.reader(io.StringIO(report.render_csv(rep, stats))))
check(rows[0] == ["device", "row", "name", "category", "sessions", "events", "seconds", "first", "last"] and rows[1][:2] == [S1, "app"] and rows[1][6] == "10" and any(r[1] == "unlabelled" and r[2] == "unk1.test" and r[5] == "2" for r in rows), "csv：固定列；app 行和 unlabelled 行")
check(all(len(r) == 9 for r in rows), "csv 每行 9 列")

print("== 命令行（假 argv）==")
tmp = tempfile.mkdtemp()
kf = os.path.join(tmp, "keys.txt")
open(kf, "w").write('"wpa-pwd","SECRETPASS:SSID"\n')


def run(argv):
    out, err, so, se = io.StringIO(), io.StringIO(), sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        rc = report.main(argv)
    finally:
        sys.stdout, sys.stderr = so, se
    return rc, out.getvalue(), err.getvalue()


rc, o, e = run([os.path.join(tmp, "nope.pcap"), "--keys", kf])
check(rc == 2 and "读不了抓包文件" in e and o == "", "抓包文件不存在：退出码 2，中文错误")
junk = os.path.join(tmp, "junk.pcap")
open(junk, "wb").write(b"not a capture at all")
rc, o, e = run([junk, "--keys", kf])
check(rc == 2 and "读不了抓包文件" in e, "不是抓包文件：退出码 2")
tiny = os.path.join(tmp, "beacon.pcap")
wrpcap(tiny, [Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="02:00:00:00:00:aa", addr3="02:00:00:00:00:aa") / Dot11Beacon() / Dot11Elt(ID=0, info=b"net")], linktype=105)
rc, o, e = run([tiny, "--keys", kf])
check(rc == 0 and "没有看到任何设备" in o and "提示：抓包里没有受保护的数据帧" in e and "0 个受保护" in o, "只有信标、没有受保护的数据帧：退出码 0，提示一句，不当成密钥错")
seen = {}
orig_build = report.build
report.build = lambda events, rules, gap, device, min_events, top: seen.update(gap=gap, device=device, min_events=min_events, top=top) or orig_build(events, rules, gap, device, min_events, top)
run([tiny, "--keys", kf])
check(seen == {"gap": 60.0, "device": None, "min_events": 1, "top": 15}, "默认值：gap 60、不过滤设备、min-events 1、每台设备列 15 个没规则的域名")
run([tiny, "--keys", kf, "--gap", "7.5", "--device", "02-00-00-00-00-AA", "--min-events", "0", "--unmatched", "0"])
report.build = orig_build
check(seen == {"gap": 7.5, "device": "02:00:00:00:00:aa", "min_events": 0, "top": 0}, "选项传到汇总：--gap、--device（规范成小写冒号）、--min-events 0 和 --unmatched 0 都合法")
rc, o, e = run([junk, "--keys", os.path.join(tmp, "nokeys")])
check(rc == 2 and "读不了密钥文件" in e, "密钥文件不存在：退出码 2")
open(os.path.join(tmp, "bad.txt"), "w").write("SECRETLINE\n")
rc, o, e = run([junk, "--keys", os.path.join(tmp, "bad.txt")])
check(rc == 2 and "第 1 行" in e and "SECRET" not in e, "密钥文件格式不对：报行号，不回显内容")
open(os.path.join(tmp, "empty.txt"), "w").write("# 空\n")
rc, o, e = run([junk, "--keys", os.path.join(tmp, "empty.txt")])
check(rc == 2 and "里没有密钥" in e, "密钥文件里一把密钥也没有：退出码 2")
rc, o, e = run([junk, "--keys", kf, "--rules", os.path.join(tmp, "nope.json")])
check(rc == 2 and "读不了规则文件" in e, "规则文件不存在：退出码 2")
open(os.path.join(tmp, "badrules.json"), "w").write('{"apps": [{"app": "x"}]}')
rc, o, e = run([junk, "--keys", kf, "--rules", os.path.join(tmp, "badrules.json")])
check(rc == 2 and "读不了规则文件" in e, "规则文件内容不合法：退出码 2")
for argv, why in (([tiny, "--keys", kf, "--gap", "0"], "--gap 0"), ([tiny, "--keys", kf, "--unmatched", "-1"], "--unmatched 负数"), ([tiny, "--keys", kf, "--min-events", "-1"], "--min-events 负数"),
                  ([tiny, "--keys", kf, "--device", "xyz"], "--device 不是 MAC"), ([tiny, "--keys", kf, "--format", "xml"], "--format 不认识"), ([tiny], "没给 --keys")):
    rc, o, e = run(argv)
    check(rc == 2 and o == "", "参数错误退出码 2：%s" % why)
rc, o, e = run(["--help"])
check(rc == 0, "--help 退出码 0")

print("== 真实样例 wpa-Induction（CLI 子进程）==")
fetch_samples.fetch()
sample = os.path.join(fetch_samples.SAMPLE_DIR, "wpa-Induction.pcap.gz")
good = os.path.join(tmp, "good.txt")
open(good, "w").write('# Induction 样例的口令\n"wpa-pwd","Induction"\n')
wrong = os.path.join(tmp, "wrong.txt")
open(wrong, "w").write('"wpa-pwd","NotTheRightPassphrase"\n')
rules = os.path.join(tmp, "mine.json")
json.dump({"apps": [{"app": "维基", "category": "百科", "suffix": ["wikipedia.org", "wikimedia.org"]}]}, open(rules, "w"), ensure_ascii=False)
env = dict(os.environ, TZ="UTC", PYTHONPATH=ROOT)


def cli(*args):
    p = subprocess.run([sys.executable, "-m", "wifi80211.report", sample] + list(args), capture_output=True, text=True, env=env, cwd=ROOT)
    return p.returncode, p.stdout, p.stderr


rc, o, e = cli("--keys", good, "--format", "json", "--unmatched", "100")
doc = json.loads(o) if rc == 0 else {}
check(rc == 0 and doc.get("frames", {}).get("protected") == 280 and doc["frames"]["decrypted"] == 276, "口令对：退出码 0，280 个受保护的数据帧解开 276 个")
dev = doc["devices"][0]
names = {n for n, _ in dev["unlabelled"]}
check(len(doc["devices"]) == 1 and dev["mac"] == "00:0d:93:82:36:3a" and dev["events"] == 28 and dev["kinds"] == {"dns": 13, "mdns": 4, "http": 11}, "1 台设备，28 个事件（13 个 DNS、4 个 mDNS、11 个 HTTP 请求），和 test_activity_diff / test_http_diff 的表一致")
check(len(names) == 11 and sum(n for _, n in dev["unlabelled"]) == 24 and "en.wikipedia.org" in names and dev["apps"] == [], "没有规则时：13 个 DNS 查询 + 11 个 HTTP 请求共 24 次、11 个不同的名字，全部在「没有规则」里")
rc, o, e = cli("--keys", good, "--rules", rules, "--format", "json")
d2 = json.loads(o)["devices"][0]
check(rc == 0 and [(r["app"], r["category"], r["events"]) for r in d2["apps"]] == [("维基", "百科", 4)] and "en.wikipedia.org" not in {n for n, _ in d2["unlabelled"]}, "--rules：自己的规则把 en.wikipedia.org、upload.wikimedia.org 归到「维基」，不再出现在没规则的列表里")
rc, o, e = cli("--keys", good, "--device", "00:0D:93:82:36:3A")
check(rc == 0 and "00:0d:93:82:36:3a" in o, "--device（大写也行）：留下这台")
rc, o, e = cli("--keys", good, "--device", "02:00:00:00:00:99")
check(rc == 0 and "没有看到任何设备" in o, "--device 是别的设备：没有设备，不报错")
rc, o, e = cli("--keys", good, "--min-events", "29")
check(rc == 0 and "没有看到任何设备" in o, "--min-events 29：这台设备只有 28 个事件，不显示")
rc, o, e = cli("--keys", good)
check(rc == 0 and "设备 00:0d:93:82:36:3a：28 个访问事件" in o and report.LIMITS in o, "默认表格：设备行和局限说明")
rc, o, e = cli("--keys", good, "--format", "csv", "--unmatched", "100")
rows = list(csv.reader(io.StringIO(o)))
kinds = collections.Counter(r[1] for r in rows[1:])
check(rc == 0 and rows[0][:2] == ["device", "row"] and rows[0][-3:] == ["bytes_up", "bytes_down", "flows"] and kinds == {"unlabelled": 11, "traffic_other": 10} and report.LIMITS in e and report.LIMITS not in o, "csv：表头多三列流量，11 行没规则的域名 + 10 行其它流量（默认留 10 个）；局限说明走 stderr，csv 保持干净")
rc, o, e = cli("--keys", wrong)
check(rc == 3 and o == "" and "280 个受保护的数据帧，一个也没解开" in e and "口令或 SSID 不对" in e and "wpa-pwd 1 把" in e and "NotTheRight" not in e, "口令错：退出码 3，说出 280 个帧一个也没解开，只报类型和个数，不泄露口令")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
