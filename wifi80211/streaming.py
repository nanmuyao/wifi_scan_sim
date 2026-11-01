# -*- coding: utf-8 -*-
"""
持续下行的时段：每台设备、每个应用，什么时候连续地在往下收数据——这是「像在看视频」的线索，不是结论。纯标准库。

做的事很简单：流量按 activity.BIN_SECONDS（5 秒）一格累计下行字节；某一格的下行速率不低于 min_rate 就算「活跃」；
活跃的格子之间空着不超过 max_gap 秒就连成一段；一段至少要 min_seconds 秒才算一个时段。
短视频的样子是下行反复地一块一块拉（每隔十几秒一块），所以允许中间有空格；待机的心跳、偶尔的小请求速率不够，不会成段。

诚实的地方：
  - 这只看流量的形状，不看内容；下载更新、同步网盘、看直播、听在线音乐也是「持续下行」。报告里写「持续下行」，不写「在刷短视频」。
  - 三个参数的默认值是第一次的猜测（DEFAULTS），**没有用真实数据标定过**，不要当成准确的门槛；拿到真实抓包（刷视频、看直播、发消息、放着不动各一段）之后再调，调的依据要记下来。
  - 不按域名的名字猜「这是视频 CDN」：域名角色没有真实抓包支持之前不分。应用只用规则能认出的那一级（apps.Rules.label）。
  - 下行速率按 L3 字节算（含 IP / TCP 头和重传），口径同 traffic.py。
"""
from . import activity

DEFAULTS = {"min_rate": 50000, "min_seconds": 30, "max_gap": 15}          # 字节 / 秒、秒、秒：未标定，见上


def app_series(rules, flow_list):
    """flow_list：traffic.flows(result, with_bins=True) 的结果 -> {(设备, 应用): {格: 下行字节}}。
    只统计有名字、规则认识的流（和 traffic.aggregate 的 apps 同一口径）；没规则的、没名字的不在里面。"""
    out = {}
    for f in flow_list:
        hit = rules.label(f["name"]) if f["name"] else None
        if not hit:
            continue
        for b, (_up, down) in f["bins"].items():
            if down:
                series = out.setdefault((f["station"], hit["app"]), {})
                series[b] = series.get(b, 0) + down
    return out


def episodes(bins, min_rate=DEFAULTS["min_rate"], min_seconds=DEFAULTS["min_seconds"], max_gap=DEFAULTS["max_gap"], bin_seconds=activity.BIN_SECONDS):
    """bins：{格: 下行字节} -> 时段列表（按时间排序）：
    {"start", "end"（格的边界，Unix 时间）, "seconds", "bytes_down"（整段里所有格的合计，含中间安静的格）, "avg_rate"（字节 / 秒）, "active_seconds"（活跃的格合计多少秒）}。"""
    if min_rate <= 0 or min_seconds <= 0 or max_gap < 0 or bin_seconds <= 0:
        raise ValueError("min_rate / min_seconds 要大于 0，max_gap 不能是负数")
    active = sorted(b for b, n in bins.items() if n / float(bin_seconds) >= min_rate)
    out, i = [], 0
    while i < len(active):
        j = i
        while j + 1 < len(active) and (active[j + 1] - active[j] - 1) * bin_seconds <= max_gap:
            j += 1
        first, last = active[i], active[j]
        seconds = (last - first + 1) * bin_seconds
        if seconds >= min_seconds:
            total = sum(n for b, n in bins.items() if first <= b <= last)
            out.append({"start": first * bin_seconds, "end": (last + 1) * bin_seconds, "seconds": seconds, "bytes_down": total,
                        "avg_rate": total / float(seconds), "active_seconds": (j - i + 1) * bin_seconds})
        i = j + 1
    return out


def summary(rules, flow_list, **params):
    """-> {(设备, 应用): {"episodes": [...], "seconds": 各时段合计秒数, "bytes_down": 各时段合计字节}}，只含至少有一个时段的。params 是 episodes 的三个参数。"""
    out = {}
    for key, bins in app_series(rules, flow_list).items():
        eps = episodes(bins, **params)
        if eps:
            out[key] = {"episodes": eps, "seconds": sum(e["seconds"] for e in eps), "bytes_down": sum(e["bytes_down"] for e in eps)}
    return out
