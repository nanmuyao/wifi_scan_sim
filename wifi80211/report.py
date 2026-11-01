# -*- coding: utf-8 -*-
"""
一条命令出报告：抓包文件 + 密钥文件 -> 解密 -> 每台设备访问了什么（DNS / TLS / QUIC ...）-> 归到应用 -> 使用估计和上下行流量。纯标准库。
  python3 -m wifi80211.report capture.pcap --keys keys.txt [--rules my.json] [--gap 60] [--format table|json|csv]
                              [--unmatched 15] [--device MAC] [--min-events N] [--top N]
抓包文件是 802.11（监听网卡抓的空口）时要 --keys；是以太网 / Linux cooked（在网关或局域网一侧抓的明文）时不需要 --keys，给了也忽略（wifi80211/plain.py 说明怎么认设备）。
--top N：每台设备的应用表按流量（上行 + 下行）从大到小只留前 N 个，「其它流量」也只留前 N 个；不给就保持按估计秒数排序，其它流量留 10 个。
退出码：0 正常；2 参数 / 文件 / 密钥文件有问题；3 抓包里有受保护的数据帧，但一个也没解开（多半是口令或 SSID 不对，或者没抓到完整的四次握手）。
"""
import argparse
import csv
import datetime
import io
import json
import logging
import os
import re
import sys

from . import activity, apps, capture, frames, health, keyfile, logs, pipeline, plain, streaming, traffic

LIMITS = "注意：使用时长是从网络活动推出的估计，不是屏幕使用时间；DoH / DoT / ECH 加密的访问看不到，只能看见明文 DNS、TLS 的 SNI 和 QUIC 的 SNI。"
TRAFFIC_NOTE = "流量 = 抓到的 IP 包的字节（含 IP / TCP / UDP 头和重传），不是应用层数据量；名字来自这条连接的 SNI / Host，或这台设备 DNS 应答里的 IP -> 域名。"
EXIT_USAGE, EXIT_NO_DECRYPT = 2, 3
HANDSHAKE_TEXT = {"verified": "已验证", "no_handshake": "没抓到", "only_m1": "只有 M1", "m2_without_m1": "缺 M1", "mic_mismatch": "MIC 对不上", "no_candidates": "无候选密钥", "unsupported": "不支持", "incomplete": "不全"}
OTHER_DEFAULT = 10


def iso(ts):
    return datetime.datetime.fromtimestamp(ts).isoformat(timespec="seconds")


def norm_mac(s):
    h = re.sub(r"[^0-9a-f]", "", s.lower())
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else None


def build(events, rules, gap=60.0, device=None, min_events=1, top_unmatched=15):
    """-> {"devices": [{"mac", "events", "kinds": {种类: 个数}, "apps": [{app, category, sessions, events, seconds, first, last}], "unlabelled": [[名字, 次数]]}]}。
    设备按事件数降序；应用按 seconds 降序（同样按事件数、名字）。"""
    by = {}
    for e in events:
        by.setdefault(e["station"], []).append(e)
    devices = []
    for mac, evs in by.items():
        if (device and mac != device) or len(evs) < min_events:
            continue
        kinds = {}
        for e in evs:
            kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
        use = apps.usage(rules, evs, gap).get(mac, {})
        rows = [dict(app=a, category=u["category"], sessions=u["sessions"], events=u["events"], seconds=u["seconds"], first=u["first"], last=u["last"]) for a, u in use.items()]
        rows.sort(key=lambda r: (-r["seconds"], -r["events"], r["app"]))
        devices.append({"mac": mac, "events": len(evs), "kinds": dict(sorted(kinds.items())), "apps": rows, "unlabelled": [list(x) for x in apps.unmatched(rules, evs)[:top_unmatched]]})
    devices.sort(key=lambda d: (-d["events"], d["mac"]))
    return {"devices": devices}


def attach_traffic(rep, agg, top=None):
    """把 traffic.aggregate 的结果并进 build() 的报告：应用行加上 bytes_up / bytes_down / flows（没有流量是 0），只在流量里出现的应用补一行（事件 0）；
    每台设备加 "traffic"（总计）和 "other_traffic"（没规则或没名字的流量）；top 给了就按流量取前 N。rep["traffic"] 置 True（渲染时才印流量列）。"""
    rep["traffic"] = True
    for d in rep["devices"]:
        t = agg.get(d["mac"], {"apps": {}, "other": {}})
        rows = {r["app"]: r for r in d["apps"]}
        for app, b in t["apps"].items():
            r = rows.get(app)
            if r is None:
                r = rows[app] = dict(app=app, category=b["category"], sessions=0, events=0, seconds=0.0, first=b["first"], last=b["last"])
                d["apps"].append(r)
        for r in d["apps"]:
            b = t["apps"].get(r["app"], {})
            r.update(bytes_up=b.get("bytes_up", 0), bytes_down=b.get("bytes_down", 0), flows=b.get("flows", 0))
        if top is not None:
            d["apps"].sort(key=lambda r: (-(r["bytes_up"] + r["bytes_down"]), -r["seconds"], r["app"]))
            del d["apps"][top:]
        else:
            d["apps"].sort(key=lambda r: (-r["seconds"], -r["events"], r["app"]))
        other = [dict(name=k, named=v["named"], flows=v["flows"], bytes_up=v["bytes_up"], bytes_down=v["bytes_down"]) for k, v in t["other"].items()]
        other.sort(key=lambda o: (-(o["bytes_up"] + o["bytes_down"]), o["name"]))
        d["other_traffic"] = other[:OTHER_DEFAULT if top is None else top]
        allb = list(t["apps"].values()) + list(t["other"].values())
        d["traffic"] = {"bytes_up": sum(b["bytes_up"] for b in allb), "bytes_down": sum(b["bytes_down"] for b in allb), "flows": sum(b["flows"] for b in allb)}
    return rep


STREAM_EPISODES = 3                                                      # 每个应用在表格里列最长的几个时段


def attach_streaming(rep, summary, params, unnamed=None):
    """把 streaming.summary 的结果并进报告：每台有持续下行时段的设备加 "streaming"：[{"app", "seconds", "bytes_down", "episodes": [...]}]，按合计秒数从多到少；
    rep["streaming_params"] 记下用的参数（rep["streaming"] 为 True 时表格才印这一节）。"""
    rep["streaming_params"] = dict(params)
    unnamed = unnamed or {}
    rep["streaming"] = bool(summary)
    for d in rep["devices"]:
        rows = [dict(app=app, apps=v["apps"], seconds=v["seconds"], bytes_down=v["bytes_down"], episodes=v["episodes"])
                for (st, app), v in summary.items() if st == d["mac"]]
        rows.sort(key=lambda r: (-r["seconds"], r["app"]))
        if rows:
            d["streaming"] = rows
            u, t = unnamed.get(d["mac"], (0, 0))
            d["streaming_unnamed"] = {"bytes_down": u, "total_down": t}


def streaming_lines(d, params):
    """表格里一台设备的「持续下行」一节。"""
    out = ["  持续下行的时段（下行连续不断地在收数据；看视频是这个样子，下载、直播也是，不是结论）："]
    for r in d["streaming"]:
        label = r["app"] if r["apps"] == [r["app"]] else "%s（%s）" % (r["app"], "、".join(r["apps"]))
        out.append("    %-24s 合计 %.1f 分钟，%d 个时段，下行 %s" % (label, r["seconds"] / 60.0, len(r["episodes"]), traffic.human(r["bytes_down"])))
        for e in sorted(r["episodes"], key=lambda e: -e["seconds"])[:STREAM_EPISODES]:
            out.append("      %s  %4.1f 分钟  平均 %s/秒" % (iso(e["start"]), e["seconds"] / 60.0, traffic.human(e["avg_rate"])))
        if len(r["episodes"]) > STREAM_EPISODES:
            out.append("      …还有 %d 个更短的时段" % (len(r["episodes"]) - STREAM_EPISODES))
    u = d.get("streaming_unnamed")
    if u and u["total_down"] and u["bytes_down"]:
        out.append("    没有名字的流（不在上面的统计里，可能漏掉了一部分）：下行 %s，占这台设备下行的 %.0f%%" % (traffic.human(u["bytes_down"]), 100.0 * u["bytes_down"] / u["total_down"]))
    return out


def attach_health(rep, quality, device=None):
    """把 health.build 的结果并进报告：rep["health"] 是全部（含没有访问事件的设备）；每台有事件的设备再带一份自己的 "health"。--device 只留这台设备。"""
    if device:
        quality = dict(quality, stations=[s for s in quality["stations"] if s["mac"] == device])
    rep["health"] = quality
    by = {s["mac"]: s for s in quality["stations"]}
    for d in rep["devices"]:
        if d["mac"] in by:
            d["health"] = by[d["mac"]]


def health_lines(quality):
    """表格里的「抓包质量」一节。"""
    o = quality["overall"]
    loss = "-" if o["loss"] is None else "%.1f%%" % (100 * o["loss"])
    out = ["", "抓包质量（由 802.11 序号缺口估计，是估计不是精确值）：总计丢帧 %s（听到 %d、缺口 %d），断档 %d 处，校验和不对的帧 %d 个。" % (loss, o["seen"], o["missing"], o["outages"], o["bad_fcs"])]
    for s in quality["stations"]:
        q = s["seq"]
        out.append("  设备 %s：受保护 %d 个，解开 %d 个；握手 %s；丢帧 %s；重传 %s" % (
            s["mac"], s["protected"], s["decrypted"], HANDSHAKE_TEXT.get(s["handshake"], "-"), "-" if q["loss"] is None else "%.1f%%" % (100 * q["loss"]),
            "-" if q["retry_rate"] is None else "%.0f%%" % (100 * q["retry_rate"])))
        out += ["    提示：" + n for n in s["notes"]]
    return out


def log_result(rep, stats, rules, events, flow_list):
    """日志的收尾：应用归类、流量的小结，再加一段自成一体的「结果」——日志文件拉到最后就能看到这次跑出了什么。"""
    labelled, total = apps.log_coverage(rules, events)
    traffic.log_summary(flow_list)
    up = sum(f["bytes_up"] for f in flow_list)
    down = sum(f["bytes_down"] for f in flow_list)
    names = {r["app"] for d in rep["devices"] for r in d["apps"]}
    log.info("结果：模式 %s，帧 / 包 %d 个%s；设备 %d 台；事件 %d 个；认出 %d 个应用；上行 %s、下行 %s；没规则的事件占 %s",
             stats.get("mode"), stats.get("frames", 0), "，受保护 %d 个解开 %d 个" % (stats["protected"], stats["decrypted"]) if stats.get("mode") == "dot11" else "",
             len(rep["devices"]), len(events), len(names), traffic.human(up), traffic.human(down), "%.0f%%" % (100 * (total - labelled) / total) if total else "-")
    if not rep["devices"]:
        log.warning("报告里没有设备：事件为 0，或者被 --device / --min-events 滤掉了")


def render_table(rep, stats):
    if stats.get("mode") == "plain":
        out = ["抓包：%d 个包（明文，无需解密）；设备 %d 台。" % (stats["frames"], len(rep["devices"]))]
    else:
        out = ["抓包：%d 个受保护的数据帧，解开 %d 个；设备 %d 台。" % (stats["protected"], stats["decrypted"], len(rep["devices"]))]
    tr = rep.get("traffic")
    if rep.get("health") and rep["health"]["stations"]:
        out += health_lines(rep["health"])
    for d in rep["devices"]:
        out += ["", "设备 %s：%d 个访问事件（%s）" % (d["mac"], d["events"], "，".join("%s %d" % kv for kv in d["kinds"].items()))]
        if tr:
            out.append("  流量合计：上行 %s，下行 %s，%d 条流" % (traffic.human(d["traffic"]["bytes_up"]), traffic.human(d["traffic"]["bytes_down"]), d["traffic"]["flows"]))
        if d["apps"]:
            out.append("  %-24s %-10s %6s %6s %9s  %-19s  %-19s%s" % ("应用", "类别", "段数", "事件", "估计秒数", "首次", "最后", ("  %10s %10s %5s" % ("上行", "下行", "流")) if tr else ""))
            for r in d["apps"]:
                out.append("  %-24s %-10s %6d %6d %9.0f  %-19s  %-19s%s" % (r["app"], r["category"], r["sessions"], r["events"], r["seconds"], iso(r["first"]), iso(r["last"]),
                                                                          ("  %10s %10s %5d" % (traffic.human(r["bytes_up"]), traffic.human(r["bytes_down"]), r["flows"])) if tr else ""))
        else:
            out.append("  没有能归到应用的域名。")
        if d.get("streaming"):
            out += streaming_lines(d, rep["streaming_params"])
        if tr and d["other_traffic"]:
            out.append("  其它流量（没规则或没有名字，按流量取前 %d 个）：" % len(d["other_traffic"]))
            out += ["    %10s %10s %5d  %s" % (traffic.human(o["bytes_up"]), traffic.human(o["bytes_down"]), o["flows"], o["name"]) for o in d["other_traffic"]]
        if d["unlabelled"]:
            out.append("  没有规则的域名（前 %d 个，可以补进自己的规则）：" % len(d["unlabelled"]))
            out += ["    %5d  %s" % (n, name) for name, n in d["unlabelled"]]
    if not rep["devices"]:
        out += ["", "没有看到任何设备的 DNS / TLS / QUIC 访问（解开了数据帧，但里面没有这些）。"]
    sp = rep.get("streaming_params")
    note_s = ["持续下行的门槛：每 5 秒一格，下行速率不低于 %s/秒算活跃，活跃格之间空着不超过 %g 秒连成一段，一段至少 %g 秒；默认值是没有用真实数据标定过的猜测，可以用 --stream-rate / --stream-gap / --stream-min-seconds 调。"
              % (traffic.human(sp["min_rate"]), sp["max_gap"], sp["min_seconds"])] if rep.get("streaming") else []
    return "\n".join(out + [""] + ([TRAFFIC_NOTE] if tr else []) + note_s + [LIMITS]) + "\n"


def render_json(rep, stats):
    doc = dict(rep, frames=stats, limits=LIMITS)
    doc["devices"] = [dict(d, apps=[dict(r, first_time=iso(r["first"]), last_time=iso(r["last"])) for r in d["apps"]]) for d in rep["devices"]]
    if rep.get("traffic"):
        doc["traffic_note"] = TRAFFIC_NOTE
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def render_csv(rep, stats):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    tr = rep.get("traffic")
    w.writerow(["device", "row", "name", "category", "sessions", "events", "seconds", "first", "last"] + (["bytes_up", "bytes_down", "flows"] if tr else []))
    for d in rep["devices"]:
        for r in d["apps"]:
            w.writerow([d["mac"], "app", r["app"], r["category"], r["sessions"], r["events"], "%.0f" % r["seconds"], iso(r["first"]), iso(r["last"])] + ([r["bytes_up"], r["bytes_down"], r["flows"]] if tr else []))
        for name, n in d["unlabelled"]:
            w.writerow([d["mac"], "unlabelled", name, "", "", n, "", "", ""] + (["", "", ""] if tr else []))
        for o in d.get("other_traffic", []) if tr else []:
            w.writerow([d["mac"], "traffic_other", o["name"], "", "", "", "", "", "", o["bytes_up"], o["bytes_down"], o["flows"]])
    return buf.getvalue()


RENDER = {"table": render_table, "json": render_json, "csv": render_csv}


log = logging.getLogger("wifi80211.report")                      # 不用 __name__：python -m 运行时它是 __main__，就不在 wifi80211 的日志树里了
EXIT_INTERNAL = 70
FILE_ONLY = {"file_only": True}                                          # 已经打印给人看的提示：日志文件里记一份，屏幕上不再重复


def main(argv=None):
    """命令行入口：装好日志，再跑 _main；没料到的异常写进日志并给出日志路径，退出码 70。"""
    argv = list(sys.argv[1:] if argv is None else argv)
    path = logs_setup(argv)
    try:
        return _main(argv)
    except KeyboardInterrupt:
        log.warning("被中断")
        return 130
    except Exception:                                                            # noqa: BLE001 —— 最外层兜底，目的就是记下来
        log.exception("内部错误")
        print("内部错误（不是你的用法问题）。日志：%s" % (path or "没有写日志文件，请加 --log-file 重跑"), file=sys.stderr)
        return EXIT_INTERNAL


def note(level, msg):
    """给人看的提示：写进日志，也打到屏幕（stderr）。"""
    log.log(level, "%s", msg, extra=FILE_ONLY)
    print(msg, file=sys.stderr)


def logs_setup(argv):
    """只看日志相关的几个参数（完整的解析在 _main 里）。返回日志文件路径或 None。"""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--log-level", choices=sorted(logs.LEVELS), default="warning")
    p.add_argument("--log-file")
    p.add_argument("--no-log-file", action="store_true")
    p.add_argument("--redact", action="store_true")
    a, _ = p.parse_known_args(argv)
    path = None if a.no_log_file else (a.log_file or logs.default_log_path())
    try:
        logs.setup(a.log_level, path, a.redact)
    except OSError as e:
        logs.setup(a.log_level, None, a.redact)
        log.warning("日志文件写不了（%s），只输出到屏幕", e)
        path = None
    inputs = [x for x in argv if not x.startswith("-") and os.path.exists(x) and x != path]                  # 日志文件自己不是输入
    logs.run_header(log, argv, inputs)
    if path:
        print("日志文件：%s" % path, file=sys.stderr)
    return path


def _main(argv):
    p = argparse.ArgumentParser(prog="python3 -m wifi80211.report", description="解密抓包并报告每台设备访问了什么（只用于自己的网络）。")
    p.add_argument("capture", help="抓包文件（pcap / pcapng，可以是 .gz）")
    p.add_argument("--keys", metavar="FILE", help="密钥文件（Wireshark 的 \"类型\",\"值\" 格式，见 wifi80211/keyfile.py）；802.11 抓包必须给，以太网 / cooked 抓包不需要")
    p.add_argument("--rules", action="append", default=[], metavar="FILE", help="自己的域名 -> 应用规则（可以多次给），优先于自带规则")
    p.add_argument("--gap", type=float, default=60.0, metavar="SECONDS", help="相邻访问不超过这么多秒算同一段使用（默认 60）")
    p.add_argument("--format", choices=sorted(RENDER), default="table")
    p.add_argument("--unmatched", type=int, default=15, metavar="N", help="每台设备列出没有规则的域名前 N 个（默认 15）")
    p.add_argument("--device", metavar="MAC", help="只看这台设备")
    p.add_argument("--min-events", type=int, default=1, metavar="N", help="事件数少于 N 的设备不显示")
    p.add_argument("--log-level", choices=sorted(logs.LEVELS), default="warning", help="屏幕上的日志级别（默认 warning；日志文件固定记到 debug，trace 才逐帧）")
    p.add_argument("--log-file", metavar="FILE", help="日志文件（默认当前目录的 wifi80211-时间.log）")
    p.add_argument("--no-log-file", action="store_true", help="不写日志文件")
    p.add_argument("--redact", action="store_true", help="日志里的 MAC、IP、域名换成短标记（要把日志发给别人之前用；报告本身不受影响）")
    p.add_argument("--stream-rate", type=float, default=streaming.DEFAULTS["min_rate"] / 1000.0, metavar="KB/S", help="下行速率不低于多少 KB/秒（1000 字节）才算「在持续下行」（默认 %g；没有用真实数据标定过）" % (streaming.DEFAULTS["min_rate"] / 1000.0))
    p.add_argument("--stream-min-seconds", type=float, default=streaming.DEFAULTS["min_seconds"], metavar="SECONDS", help="持续下行至少多少秒才列出（默认 %g）" % streaming.DEFAULTS["min_seconds"])
    p.add_argument("--stream-gap", type=float, default=streaming.DEFAULTS["max_gap"], metavar="SECONDS", help="活跃之间空着不超过多少秒算连着（默认 %g；一块一块拉的视频中间会有空）" % streaming.DEFAULTS["max_gap"])
    p.add_argument("--top", type=int, metavar="N", help="每台设备的应用表按流量取前 N 个，其它流量也只留前 N 个（不给：应用按估计秒数排序，其它流量留 10 个）")
    try:
        a = p.parse_args(argv)
    except SystemExit as e:
        return EXIT_USAGE if e.code else 0
    err = lambda m: (log.error("%s", m, extra=FILE_ONLY), print("错误：" + m, file=sys.stderr), EXIT_USAGE)[2]               # noqa: E731
    if a.stream_rate <= 0 or a.stream_min_seconds <= 0 or a.stream_gap < 0:
        return err("--stream-rate、--stream-min-seconds 要大于 0，--stream-gap 不能是负数")
    if a.gap <= 0 or a.unmatched < 0 or a.min_events < 0 or (a.top is not None and a.top < 0):
        return err("--gap 要大于 0，--unmatched、--min-events 和 --top 不能是负数")
    mac = None
    if a.device:
        mac = norm_mac(a.device)
        if mac is None:
            return err("--device 不是 MAC 地址：%r" % a.device)
    keys = None
    if a.keys:
        try:
            keys = keyfile.parse(a.keys)
        except (OSError, ValueError) as e:
            return err("读不了密钥文件 %s：%s" % (a.keys, e))
        if not keys:
            return err("密钥文件 %s 里没有密钥" % a.keys)
    try:
        rules = apps.load(*a.rules)
    except (OSError, ValueError) as e:
        return err("读不了规则文件：%s" % e)
    try:
        cap = capture.read_capture(a.capture)
        mode = plain.kind(cap)
    except (OSError, ValueError, EOFError) as e:
        return err("读不了抓包文件 %s：%s" % (a.capture, e))
    if mode is None:
        return err("抓包文件 %s 的链路类型不支持（认 802.11 / radiotap、以太网、Linux cooked）" % a.capture)
    if mode == "plain":
        if keys:
            note(logging.WARNING, "提示：这是明文抓包（以太网 / cooked），不需要密钥，--keys 被忽略。")
        result = plain.analyze(plain.iter_packets(cap))
        stats = {"frames": len(cap.packets), "protected": 0, "decrypted": 0, "mode": "plain"}
    else:
        if not keys:
            return err("802.11 抓包需要 --keys（密钥文件）")
        fr = list(frames.iter_frames(cap))
        cap.packets = []                    # 原始包不再用了（帧里有自己的数据），先放掉，大抓包省下一份内存
        protected = sum(1 for f in fr if f.h["type"] == 2 and f.h["protected"])
        dstats = {}
        dec = pipeline.decrypt_capture(fr, keys, dstats)
        stats = {"frames": len(fr), "protected": protected, "decrypted": len(dec), "mode": "dot11"}
        if protected and not dec:
            note(logging.ERROR, "错误：抓包里有 %d 个受保护的数据帧，一个也没解开。读到的密钥：%s。多半是口令或 SSID 不对，或者没有抓到完整的四次握手（要抓到设备连接的那一刻）。" %
                 (protected, "，".join("%s %d 把" % kv for kv in keyfile.summary(keys).items())))
            for line in pipeline.explain(dstats):
                note(logging.ERROR, "  原因分析：" + line)
            return EXIT_NO_DECRYPT
        if not protected:
            note(logging.WARNING, "提示：抓包里没有受保护的数据帧（没抓到数据，或者是开放网络——开放网络的明文暂不支持）。")
        result = activity.analyze(fr, dec)
        quality = health.build(fr, dec, dstats["handshake"].get("pairs", []))
        health.log_summary(quality)
    rep = build(result.events, rules, a.gap, mac, a.min_events, a.unmatched)
    if mode != "plain":
        attach_health(rep, quality, mac)
    flow_list = traffic.flows(result, with_bins=True)
    attach_traffic(rep, traffic.aggregate(rules, flow_list), a.top)
    sparams = {"min_rate": int(a.stream_rate * 1000), "min_seconds": a.stream_min_seconds, "max_gap": a.stream_gap}
    sres = {k: v for k, v in streaming.summary(rules, flow_list, **sparams).items() if mac is None or k[0] == mac}
    attach_streaming(rep, sres, sparams, streaming.unnamed_share(flow_list))
    log.info("持续下行：%d 个设备应用组合有时段，共 %d 个时段（门槛 %s/秒、至少 %g 秒、空格 %g 秒）", len(sres), sum(len(v["episodes"]) for v in sres.values()),
             traffic.human(sparams["min_rate"]), sparams["min_seconds"], sparams["max_gap"])
    log_result(rep, stats, rules, result.events, flow_list)
    sys.stdout.write(RENDER[a.format](rep, stats))
    if a.format == "csv":
        print(LIMITS, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
