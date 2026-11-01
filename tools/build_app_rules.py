#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 v2fly/domain-list-community（MIT）固定提交里取域名清单，按下面的 APPS 表归到「应用 / 类别」，生成 rules/apps.json。
  python3 tools/build_app_rules.py            下载（逐个文件核对 sha256）并写出 rules/apps.json
  python3 tools/build_app_rules.py --check    重新生成，和已提交的 rules/apps.json 比，不一致就失败
清单格式：每行一条，`域名`或 `domain:域名` 是后缀匹配，`full:域名` 是完全匹配，`include:别的清单` 引入另一个清单，
`keyword:` / `regexp:` 不支持（跳过并计数），带 @ads 属性的是广告 / 统计域名（跳过，不算应用本身），其余 @属性忽略，# 开头是注释。
同一个域名被多个应用的清单收录时，APPS 里排在前面的应用先占；冲突个数记在输出的 conflicts 里。
"""
import hashlib
import json
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "rules", "apps.json")
REPO = "v2fly/domain-list-community"
COMMIT = "c6adacf29cc4fb05e04651fcf03e00989ef9f797"                      # 2026-10-09 的提交（取数时已超过两周）
BASE = "https://raw.githubusercontent.com/%s/%s/data/" % (REPO, COMMIT)

# （应用, 类别, [清单名...]）。顺序有意义：更具体的应用放在更笼统的前面（youtube 在 google 之前，primevideo 在 amazon 之前，acfun 在 kuaishou 之前）。
APPS = [
    ("抖音", "短视频", ["douyin"]),
    ("TikTok", "短视频", ["tiktok"]),
    ("AcFun", "视频", ["acfun"]),
    ("快手", "短视频", ["kuaishou"]),
    ("哔哩哔哩", "视频", ["bilibili"]),
    ("YouTube", "视频", ["youtube"]),
    ("Netflix", "视频", ["netflix"]),
    ("Disney+", "视频", ["disney"]),
    ("Prime Video", "视频", ["primevideo"]),
    ("爱奇艺", "视频", ["iqiyi"]),
    ("优酷", "视频", ["youku"]),
    ("小红书", "社交", ["xiaohongshu"]),
    ("Instagram", "社交", ["instagram"]),
    ("Facebook", "社交", ["facebook"]),
    ("X / Twitter", "社交", ["twitter"]),
    ("Telegram", "通讯", ["telegram"]),
    ("WhatsApp", "通讯", ["whatsapp"]),
    ("Discord", "通讯", ["discord"]),
    ("LINE", "通讯", ["line"]),
    ("KakaoTalk", "通讯", ["kakao"]),
    ("Zoom", "会议", ["zoom"]),
    ("Twitch", "直播", ["twitch"]),
    ("虎牙", "直播", ["huya"]),
    ("斗鱼", "直播", ["douyu"]),
    ("Spotify", "音乐", ["spotify"]),
    ("Steam", "游戏", ["steam"]),
    ("米哈游", "游戏", ["mihoyo"]),
    ("腾讯游戏", "游戏", ["tencent-games"]),
    ("网易", "网易系", ["netease"]),
    ("腾讯（微信 / QQ / 腾讯视频等）", "腾讯系", ["tencent"]),
    ("字节跳动其它", "字节系", ["bytedance"]),
    ("淘宝 / 阿里", "购物", ["alibaba"]),
    ("京东", "购物", ["jd"]),
    ("拼多多", "购物", ["pinduoduo"]),
    ("美团", "生活服务", ["meituan"]),
    ("百度", "搜索与 AI", ["baidu"]),
    ("OpenAI", "搜索与 AI", ["openai"]),
    ("GitHub", "开发", ["github"]),
    ("小米", "设备厂商", ["xiaomi"]),
    ("华为", "设备厂商", ["huawei"]),
    ("Apple", "系统与云", ["apple"]),
    ("Microsoft", "系统与云", ["microsoft"]),
    ("Amazon", "系统与云", ["amazon"]),
    ("Google", "系统与云", ["google"]),
]


def fetch(name):
    with urllib.request.urlopen(BASE + name, timeout=60) as r:
        return r.read()


def parse_list(text):
    """-> (后缀 [...], 完全匹配 [...], 引入的清单 [...], 跳过的 {原因: 个数})。"""
    suffix, full, inc, skipped = [], [], [], {"keyword": 0, "regexp": 0, "ads": 0}
    for raw in text.split("\n"):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        entry, attrs = parts[0], parts[1:]
        if any(a == "@ads" for a in attrs):
            skipped["ads"] += 1
            continue
        if entry.startswith("include:"):
            inc.append(entry[8:])
        elif entry.startswith("keyword:"):
            skipped["keyword"] += 1
        elif entry.startswith("regexp:"):
            skipped["regexp"] += 1
        elif entry.startswith("full:"):
            full.append(entry[5:].lower())
        else:
            suffix.append((entry[7:] if entry.startswith("domain:") else entry).lower())
    return suffix, full, inc, skipped


def build(getter=fetch):
    files, cache = {}, {}

    def load(name, seen=()):
        if name in seen:
            return [], [], {}
        if name not in cache:
            data = getter(name)
            files[name] = hashlib.sha256(data).hexdigest()
            cache[name] = parse_list(data.decode("utf-8"))
        s, f, inc, sk = cache[name]
        s, f, sk = list(s), list(f), dict(sk)
        for i in inc:
            s2, f2, sk2 = load(i, seen + (name,))
            s += s2
            f += f2
            for k, v in sk2.items():
                sk[k] = sk.get(k, 0) + v
        return s, f, sk

    claimed, apps, conflicts, skipped = {}, [], 0, {"keyword": 0, "regexp": 0, "ads": 0}
    for app, cat, lists in APPS:
        suf, ful, sk = [], [], {}
        for ln in lists:
            s, f, k = load(ln)
            suf += s
            ful += f
            for a, b in k.items():
                sk[a] = sk.get(a, 0) + b
        for a, b in sk.items():
            skipped[a] += b
        mine_s, mine_f = [], []
        for kind, items, out in (("suffix", suf, mine_s), ("full", ful, mine_f)):
            for d in sorted(set(items)):
                if (kind, d) in claimed:
                    conflicts += claimed[(kind, d)] != app
                    continue
                claimed[(kind, d)] = app
                out.append(d)
        apps.append({"app": app, "category": cat, "lists": lists, "suffix": mine_s, "full": mine_f})
    return {"format": 1,
            "source": {"repo": REPO, "commit": COMMIT, "license": "MIT", "files": dict(sorted(files.items()))},
            "note": "由 tools/build_app_rules.py 生成，不要手改；自己的规则写在另一个文件里（见 rules/README.md）。",
            "conflicts": conflicts, "skipped": skipped, "apps": apps}


def dump(rules):
    return json.dumps(rules, ensure_ascii=False, indent=0, separators=(",", ":")) + "\n"


if __name__ == "__main__":
    text = dump(build())
    if "--check" in sys.argv:
        ok = os.path.exists(OUT) and open(OUT, encoding="utf-8").read() == text
        print("rules/apps.json 与重新生成的%s" % ("一致" if ok else "不一致"))
        sys.exit(0 if ok else 1)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    r = json.loads(text)
    print("写出 %s：%d 个应用，后缀 %d 条，完全匹配 %d 条，冲突 %d，跳过 %s，清单文件 %d 个" % (OUT, len(r["apps"]), sum(len(a["suffix"]) for a in r["apps"]), sum(len(a["full"]) for a in r["apps"]), r["conflicts"], r["skipped"], len(r["source"]["files"])))
