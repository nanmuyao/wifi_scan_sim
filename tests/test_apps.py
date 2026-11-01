#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apps80211（域名 -> 应用）：匹配规则（标签边界、最长后缀、完全匹配、自己的规则优先、大小写与结尾的点）、规则文件的校验、使用估计；
再检查已提交的 rules/apps.json 的结构和几个不会变的抽查点，以及 tools/build_app_rules.py 的清单解析（不联网）。"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
from wifi80211 import apps  # noqa: E402
import build_app_rules as gen  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def rules(*docs):
    r = apps.Rules()
    for d in docs:
        r.add(d)
    return r


A = {"apps": [{"app": "甲", "category": "视频", "suffix": ["example.com", "cdn.example.net"], "full": ["login.example.org"]},
              {"app": "乙", "category": "社交", "suffix": ["deep.example.com", "other.org"]}]}
r = rules(A)
print("== 匹配 ==")
check(r.label("example.com") == {"app": "甲", "category": "视频", "how": "suffix", "rule": "example.com"}, "域名本身命中后缀规则")
check(r.label("a.b.example.com")["app"] == "甲" and r.label("a.b.example.com")["rule"] == "example.com", "子域名命中，rule 是命中的那条规则")
check(r.label("notexample.com") is None and r.label("example.com.evil.net") is None, "后缀必须落在标签边界上；规则域名出现在名字中间不算")
check(r.label("x.deep.example.com")["app"] == "乙", "多条规则都能命中时取最长的后缀（deep.example.com 比 example.com 长）")
check(r.label("login.example.org")["how"] == "full" and r.label("x.login.example.org") is None and r.label("example.org") is None, "full 规则只匹配这个名字本身")
check(r.label("EXAMPLE.Com.")["app"] == "甲", "大小写不分，结尾的点去掉")
check(rules({"apps": [{"app": "顶", "category": "c", "suffix": ["tld"]}]}).label("a.b.tld")["rule"] == "tld", "只有一个标签的后缀规则（顶级域）也能命中")
check(r.label("") is None and r.label(None) is None and r.label("com") is None and r.label("local") is None, "空名字 / None / 只有顶级域：没有规则就是 None")
check(rules({"apps": [{"app": "全", "category": "c", "full": ["a.test"], "suffix": ["a.test"]}]}).label("a.test")["how"] == "full", "full 和后缀同时命中：完全匹配优先")

print("== 自己的规则与优先级 ==")
mine = {"apps": [{"app": "公司", "category": "办公", "suffix": ["example.com"]}]}
r = apps.Rules()
r.add(mine)
r.add(A)
check(r.label("a.example.com")["app"] == "公司" and r.label("x.deep.example.com")["app"] == "乙", "先加入的规则先占：同一个域名以自己的为准，别的域名不受影响")
dup = rules({"apps": [{"app": "先", "category": "c", "suffix": ["dup.test"]}, {"app": "后", "category": "c", "suffix": ["dup.test"]}]})
check(dup.label("dup.test")["app"] == "先", "同一份文件里重复的域名：排在前面的应用先占")
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "mine.json")
    json.dump(mine, open(p, "w"))
    r = apps.load(p)
    check(r.label("www.example.com")["app"] == "公司" and r.label("www.douyin.com")["app"] == "抖音", "load(自己的文件)：自己的优先，自带的照常可用")
    check(apps.load(p, bundled=None).label("www.douyin.com") is None, "bundled=None：只用自己的规则")

print("== 规则文件校验 ==")
for bad, why in (([], "不是对象"), ({}, "没有 apps"), ({"apps": [{"category": "c"}]}, "缺 app"), ({"apps": [{"app": "x"}]}, "缺 category"),
                 ({"apps": [{"app": "x", "category": "c", "suffix": [".lead.test"]}]}, "前导点"), ({"apps": [{"app": "x", "category": "c", "suffix": ["*.wild.test"]}]}, "通配符"),
                 ({"apps": [{"app": "x", "category": "c", "suffix": [""]}]}, "空域名"), ({"apps": ["str"]}, "应用不是对象")):
    try:
        apps.Rules().add(bad)
        check(False, "拒绝非法规则：%s" % why)
    except ValueError:
        check(True, "拒绝非法规则：%s" % why)

print("== 事件标注与使用估计 ==")
ev = lambda ts, name, kind="dns", st="s1": {"ts": ts, "station": st, "kind": kind, "name": name, "frame": int(ts)}       # noqa: E731
events = [ev(0, "a.example.com"), ev(10, "b.example.com", "tls"), ev(15, "unknown.test"), ev(200, "a.example.com"), ev(30, "x.other.org"), ev(5, "a.example.com", st="s2"),
          ev(7, "a.example.com", "mdns")]
an = apps.annotate(r_ := rules(A), events)
check([e["app"] for e in an] == ["甲", "甲", None, "甲", "乙", "甲", None] and an[0]["category"] == "视频" and "app" not in events[0], "annotate：加 app / category，不改原事件；mdns 不标")
u = apps.usage(r_, events, gap=60)
check(u["s1"]["甲"] == {"category": "视频", "events": 3, "sessions": 2, "seconds": 10.0, "first": 0, "last": 200}, "usage：0 和 10 秒是一段（10 秒），200 秒另起一段（0 秒）")
check(u["s1"]["乙"]["seconds"] == 0 and u["s2"]["甲"]["events"] == 1 and set(u) == {"s1", "s2"}, "一次事件的段是 0 秒；设备分开；没规则的域名和 mdns 不计")
check(apps.usage(r_, events, gap=5)["s1"]["甲"]["sessions"] == 3, "gap 参数：5 秒时 0 和 10 就分开了")
check(apps.usage(r_, [ev(0, "a.example.com"), ev(0, "b.example.org"), ev(30, "c.example.com")], gap=60)["s1"]["甲"]["seconds"] == 30.0, "同一应用不同域名的事件合在一起算")
u2 = apps.usage(r_, list(reversed(events)), gap=60)
check(u2["s1"]["甲"]["first"] == 0 and u2["s1"]["甲"]["last"] == 200 and u2["s1"]["甲"]["seconds"] == 10.0, "事件不按时间顺序给也行：先排序再分段")
check(apps.unmatched(r_, events) == [("unknown.test", 1)], "unmatched：没规则的域名（mdns 除外）")
check(apps.unmatched(r_, events + [ev(1, "unknown.test"), ev(2, "zzz.test"), ev(3, "aaa.test")]) == [("unknown.test", 2), ("aaa.test", 1), ("zzz.test", 1)], "unmatched 按次数降序、同次数按名字")

print("== 清单解析（tools/build_app_rules.py，不联网）==")
s, f, inc, sk = gen.parse_list("# 注释\n\nExample.COM\ndomain:Dom.test @cn\nfull:Exact.Test\ninclude:other\nkeyword:kw\nregexp:^x$\nads.example.com @ads\nattr.test @!cn @cn\n  spaced.test   # 行尾注释\n")
check(s == ["example.com", "dom.test", "attr.test", "spaced.test"] and f == ["exact.test"] and inc == ["other"] and sk == {"keyword": 1, "regexp": 1, "ads": 1}, "后缀 / domain: / full: / include: / 属性 / 注释 / 行尾注释；keyword、regexp、@ads 跳过并计数")
files = {"main": b"main.test\ninclude:sub\ninclude:loop\n", "sub": b"sub.test\nfull:s.sub.test\n", "loop": b"loop.test\ninclude:main\n", "first": b"main.test\nfirst.test\n"}
old = gen.APPS
gen.APPS = [("甲", "c", ["first"]), ("乙", "c", ["main"])]
out = gen.build(lambda n: files[n])
gen.APPS = old
a, b = out["apps"]
check(a["suffix"] == ["first.test", "main.test"] and b["suffix"] == ["loop.test", "sub.test"] and b["full"] == ["s.sub.test"] and out["conflicts"] == 1, "include 递归（环不会死循环）；同一域名排前面的应用先占，冲突计 1")
check(set(out["source"]["files"]) == {"first", "main", "sub", "loop"} and all(len(h) == 64 for h in out["source"]["files"].values()), "记录用到的每个清单文件的 sha256")
check(gen.dump(out) == gen.dump(json.loads(gen.dump(out))), "生成的 JSON 经过一次读写后不变（--check 靠这个比较）")

print("== 已提交的 rules/apps.json ==")
doc = json.load(open(apps.DEFAULT, encoding="utf-8"))
check(doc["format"] == 1 and doc["source"]["commit"] == gen.COMMIT and doc["source"]["license"] == "MIT" and len(doc["source"]["files"]) >= 100, "格式版本、来源提交、许可证、用到的清单文件")
check(all(len(h) == 64 for h in doc["source"]["files"].values()), "每个清单文件都有 sha256")
names = [a["app"] for a in doc["apps"]]
check(len(names) == len(set(names)) == len(gen.APPS) and names == [a for a, _, _ in gen.APPS], "应用与生成脚本里的表一一对应，顺序一致")
seen, dupes, bad = {}, 0, 0
for a in doc["apps"]:
    for kind in ("suffix", "full"):
        for d in a[kind]:
            bad += d != d.lower() or d.startswith(".") or "*" in d or " " in d or not d
            dupes += (kind, d) in seen
            seen[(kind, d)] = a["app"]
check(bad == 0 and dupes == 0, "域名都是小写、无前导点 / 通配符 / 空格，同一种匹配里没有重复（%d 条）" % len(seen))
real = apps.load()
spots = {"v26-web.douyinvod.com": "抖音", "www.tiktok.com": "TikTok", "rr3---sn-x.googlevideo.com": "YouTube", "api.ksapisrv.com": "快手", "www.bilibili.com": "哔哩哔哩",
         "occ-0-1.nflxvideo.net": "Netflix", "www.baidu.com": "百度", "static.xx.fbcdn.net": "Facebook", "t.me": "Telegram", "a.example.invalid": None, "en.wikipedia.org": None}
got = {k: (real.label(k) or {}).get("app") for k in spots}
check(got == spots, "几个常见域名的归属（%s）" % {k: v for k, v in got.items() if v != spots[k]})
enc = {k: (real.label(k) or {}).get("category") for k in ("dns.google", "cloudflare-dns.com", "one.one.one.one", "dns.quad9.net", "dns.adguard-dns.com", "dns.alidns.com", "www.google.com", "x.dns.google")}
check(enc == {"dns.google": "加密 DNS", "cloudflare-dns.com": "加密 DNS", "one.one.one.one": "加密 DNS", "dns.quad9.net": "加密 DNS", "dns.adguard-dns.com": "加密 DNS", "dns.alidns.com": "加密 DNS", "www.google.com": "系统与云", "x.dns.google": "系统与云"},
      "加密 DNS 服务器域名归「加密 DNS」（完全匹配优先于 Google 的后缀规则）；只匹配完全相同的名字，别的 google 域名不受影响")
check(apps.load(bundled=None).label("dns.google") is not None and apps.load(bundled=None, encrypted_dns=None).label("dns.google") is None, "encrypted_dns 可以单独关掉")
ed = json.load(open(apps.ENCRYPTED_DNS, encoding="utf-8"))
check(all(a.get("source", "").startswith("https://") and a["category"] == "加密 DNS" and not a.get("suffix") for a in ed["apps"]) and len(ed["apps"]) == 5, "加密 DNS 文件：每一项有来源网址，只有完全匹配")
check(real.label("www.youtube.com")["app"] == "YouTube" and real.label("www.google.com")["app"] == "Google", "youtube 排在 google 前面：YouTube 的域名不被 Google 的清单抢走")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
