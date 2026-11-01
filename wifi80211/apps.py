# -*- coding: utf-8 -*-
"""
域名 -> 应用 / 类别：把 activity 里读出的域名对上一份规则文件（rules/apps.json，由 tools/build_app_rules.py 从 v2fly/domain-list-community 生成；
自己的规则放另一个文件，优先级更高）。纯标准库。

匹配：名字转小写、去掉结尾的点；先找完全匹配，再从最长的后缀找起（a.b.example.com -> b.example.com -> example.com -> com），
后缀必须落在标签边界上（notdouyin.com 不匹配 douyin.com）。同一个域名多个应用都有规则时，自己的规则优先，其次是排在前面的应用。

规则文件格式（自己的规则也是这个格式，只需要 apps 一项）：
  {"apps": [{"app": "公司内网", "category": "办公", "suffix": ["corp.example.com"], "full": ["intranet.example.net"]}]}
"""
import collections
import json
import logging
import os

from . import activity

log = logging.getLogger(__name__)

DEFAULT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "apps.json")
ENCRYPTED_DNS = os.path.join(os.path.dirname(DEFAULT), "encrypted_dns.json")      # 手写的加密 DNS 服务器域名（完全匹配，优先于后缀规则：dns.google 归「加密 DNS」而不是 Google）
SKIP_KINDS = ("mdns",)                                                   # 局域网服务发现的名字不是「访问了什么」


class Rules:
    def __init__(self):
        self.suffix, self.full, self.apps = {}, {}, []
        self.sources = []                                                # 加载过的规则文件路径（日志用）

    def add(self, doc, priority_over_existing=False):
        """加入一份规则文档。已有的规则默认优先（先加入的先占）；priority_over_existing=True 时新规则覆盖已有的同名条目。"""
        if not isinstance(doc, dict) or not isinstance(doc.get("apps"), list):
            raise ValueError("规则文件需要一个 apps 列表")
        for a in doc["apps"]:
            if not isinstance(a, dict) or not a.get("app") or not a.get("category"):
                raise ValueError("每个应用需要 app 和 category：%r" % (a,))
            self.apps.append((a["app"], a["category"]))
            for table, key in ((self.suffix, "suffix"), (self.full, "full")):
                for d in a.get(key, []):
                    d = _norm(d)
                    if not d or d.startswith(".") or "*" in d:
                        raise ValueError("域名不合法（不要带前导点或通配符）：%r" % (d,))
                    if priority_over_existing or d not in table:
                        table[d] = (a["app"], a["category"])

    def label(self, name):
        """-> {"app", "category", "how": "full" | "suffix", "rule": 命中的规则域名} 或 None。"""
        n = _norm(name)
        if not n or not isinstance(name, str):
            return None
        hit = self.full.get(n)
        if hit:
            return {"app": hit[0], "category": hit[1], "how": "full", "rule": n}
        labels = n.split(".")
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            hit = self.suffix.get(cand)
            if hit:
                return {"app": hit[0], "category": hit[1], "how": "suffix", "rule": cand}
        return None


def _norm(name):
    return name.strip().lower().rstrip(".") if isinstance(name, str) else ""


def load(*extra_paths, bundled=DEFAULT, encrypted_dns=ENCRYPTED_DNS):
    """加载规则：自己的（extra_paths）优先，其次是加密 DNS 服务器，最后是自带的 apps.json（加密 DNS 都是完全匹配，本来就优先于后缀规则，先后顺序不影响结果）。bundled=None 不用自带的，encrypted_dns=None 不用加密 DNS 那份。"""
    r = Rules()
    for p in list(extra_paths) + [x for x in (encrypted_dns, bundled) if x]:
        with open(p, encoding="utf-8") as f:
            r.add(json.load(f))
        r.sources.append(p)
        log.debug("规则文件 %s：累计 %d 个应用，后缀 %d 条，完全匹配 %d 条", p, len(r.apps), len(r.suffix), len(r.full))
    log.info("规则：%d 个文件（自己的 %d 个），%d 个应用，后缀 %d 条、完全匹配 %d 条", len(r.sources), len(extra_paths), len(r.apps), len(r.suffix), len(r.full))
    return r


def annotate(rules, events):
    """每个事件加上 app / category（没规则的是 None），返回新列表；mdns 事件不标。"""
    out = []
    for e in events:
        hit = None if e["kind"] in SKIP_KINDS else rules.label(e["name"])
        out.append(dict(e, app=hit["app"] if hit else None, category=hit["category"] if hit else None))
    return out


def usage(rules, events, gap=60.0):
    """每台设备每个应用的使用估计：{设备: {应用: {"category", "events", "sessions", "seconds", "first", "last"}}}。
    同一设备同一应用的事件，相邻不超过 gap 秒算同一段，seconds 是各段「第一个事件到最后一个事件」的时间之和。
    这是从网络活动推出的下界式估计（后台同步、预加载会多算，只看了一眼没有后续连接的会少算），不是屏幕使用时间。没有规则的域名、mdns 事件不计。"""
    by = {}
    for e in annotate(rules, events):
        if e["app"]:
            by.setdefault((e["station"], e["app"]), []).append(e)
    out = {}
    for (st, app), evs in by.items():
        evs.sort(key=lambda e: e["ts"])
        sess = activity.sessions([dict(e, name=app) for e in evs], gap)
        out.setdefault(st, {})[app] = {"category": evs[0]["category"], "events": len(evs), "sessions": len(sess), "seconds": sum(s["end"] - s["start"] for s in sess),
                                       "first": evs[0]["ts"], "last": evs[-1]["ts"]}
    return out


def unmatched(rules, events):
    """没有规则的域名及次数（按次数降序）：拿来看哪些常见域名该补进自己的规则里。mdns 事件不计。"""
    c = {}
    for e in annotate(rules, events):
        if e["app"] is None and e["kind"] not in SKIP_KINDS:
            c[e["name"]] = c.get(e["name"], 0) + 1
    return sorted(c.items(), key=lambda x: (-x[1], x[0]))


def log_coverage(rules, events, hint_min=10):
    """写进日志：有多少事件（mdns 除外）归到了应用、多少没有规则；最常见的没规则的名字（DEBUG）；没规则的占多数时提示怎么补规则。返回 (归类的, 总数)。"""
    total = labelled = 0
    names = collections.Counter()
    for e in annotate(rules, events):
        if e["kind"] in SKIP_KINDS:
            continue
        total += 1
        if e["app"]:
            labelled += 1
        else:
            names[e["name"]] += 1
    if total:
        log.info("应用归类：%d 个事件（mdns 除外）里 %d 个（%.0f%%）归到了应用，%d 个没有规则（%d 个不同的名字）", total, labelled, 100 * labelled / total, total - labelled, len(names))
    if names:
        log.debug("没规则的名字前 10：%s", "、".join("%s×%d" % kv for kv in sorted(names.items(), key=lambda x: (-x[1], x[0]))[:10]))
    if total >= hint_min and (total - labelled) / total > 0.5:
        log.warning("超过一半的事件（%d/%d）没有规则认出来：规则没认出这些域名，见 apps.unmatched，可以写进自己的规则（rules/README.md；--rules 加载）", total - labelled, total)
    return labelled, total
