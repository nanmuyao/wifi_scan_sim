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
import re
import sys

from . import activity, apps, capture, frames, keyfile, pipeline, plain, traffic

LIMITS = "注意：使用时长是从网络活动推出的估计，不是屏幕使用时间；DoH / DoT / ECH 加密的访问看不到，只能看见明文 DNS、TLS 的 SNI 和 QUIC 的 SNI。"
TRAFFIC_NOTE = "流量 = 抓到的 IP 包的字节（含 IP / TCP / UDP 头和重传），不是应用层数据量；名字来自这条连接的 SNI / Host，或这台设备 DNS 应答里的 IP -> 域名。"
EXIT_USAGE, EXIT_NO_DECRYPT = 2, 3
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


def render_table(rep, stats):
    if stats.get("mode") == "plain":
        out = ["抓包：%d 个包（明文，无需解密）；设备 %d 台。" % (stats["frames"], len(rep["devices"]))]
    else:
        out = ["抓包：%d 个受保护的数据帧，解开 %d 个；设备 %d 台。" % (stats["protected"], stats["decrypted"], len(rep["devices"]))]
    tr = rep.get("traffic")
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
        if tr and d["other_traffic"]:
            out.append("  其它流量（没规则或没有名字，按流量取前 %d 个）：" % len(d["other_traffic"]))
            out += ["    %10s %10s %5d  %s" % (traffic.human(o["bytes_up"]), traffic.human(o["bytes_down"]), o["flows"], o["name"]) for o in d["other_traffic"]]
        if d["unlabelled"]:
            out.append("  没有规则的域名（前 %d 个，可以补进自己的规则）：" % len(d["unlabelled"]))
            out += ["    %5d  %s" % (n, name) for name, n in d["unlabelled"]]
    if not rep["devices"]:
        out += ["", "没有看到任何设备的 DNS / TLS / QUIC 访问（解开了数据帧，但里面没有这些）。"]
    return "\n".join(out + [""] + ([TRAFFIC_NOTE] if tr else []) + [LIMITS]) + "\n"


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


def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m wifi80211.report", description="解密抓包并报告每台设备访问了什么（只用于自己的网络）。")
    p.add_argument("capture", help="抓包文件（pcap / pcapng，可以是 .gz）")
    p.add_argument("--keys", metavar="FILE", help="密钥文件（Wireshark 的 \"类型\",\"值\" 格式，见 wifi80211/keyfile.py）；802.11 抓包必须给，以太网 / cooked 抓包不需要")
    p.add_argument("--rules", action="append", default=[], metavar="FILE", help="自己的域名 -> 应用规则（可以多次给），优先于自带规则")
    p.add_argument("--gap", type=float, default=60.0, metavar="SECONDS", help="相邻访问不超过这么多秒算同一段使用（默认 60）")
    p.add_argument("--format", choices=sorted(RENDER), default="table")
    p.add_argument("--unmatched", type=int, default=15, metavar="N", help="每台设备列出没有规则的域名前 N 个（默认 15）")
    p.add_argument("--device", metavar="MAC", help="只看这台设备")
    p.add_argument("--min-events", type=int, default=1, metavar="N", help="事件数少于 N 的设备不显示")
    p.add_argument("--top", type=int, metavar="N", help="每台设备的应用表按流量取前 N 个，其它流量也只留前 N 个（不给：应用按估计秒数排序，其它流量留 10 个）")
    try:
        a = p.parse_args(argv)
    except SystemExit as e:
        return EXIT_USAGE if e.code else 0
    err = lambda m: (print("错误：" + m, file=sys.stderr), EXIT_USAGE)[1]               # noqa: E731
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
            print("提示：这是明文抓包（以太网 / cooked），不需要密钥，--keys 被忽略。", file=sys.stderr)
        result = plain.analyze(plain.iter_packets(cap))
        stats = {"frames": len(cap.packets), "protected": 0, "decrypted": 0, "mode": "plain"}
    else:
        if not keys:
            return err("802.11 抓包需要 --keys（密钥文件）")
        fr = list(frames.iter_frames(a.capture))
        protected = sum(1 for f in fr if f.h["type"] == 2 and f.h["protected"])
        dec = pipeline.decrypt_capture(fr, keys)
        stats = {"frames": len(fr), "protected": protected, "decrypted": len(dec), "mode": "dot11"}
        if protected and not dec:
            print("错误：抓包里有 %d 个受保护的数据帧，一个也没解开。读到的密钥：%s。多半是口令或 SSID 不对，或者没有抓到完整的四次握手（要抓到设备连接的那一刻）。" %
                  (protected, "，".join("%s %d 把" % kv for kv in keyfile.summary(keys).items())), file=sys.stderr)
            return EXIT_NO_DECRYPT
        if not protected:
            print("提示：抓包里没有受保护的数据帧（没抓到数据，或者是开放网络——开放网络的明文暂不支持）。", file=sys.stderr)
        result = activity.analyze(fr, dec)
    rep = build(result.events, rules, a.gap, mac, a.min_events, a.unmatched)
    attach_traffic(rep, traffic.aggregate(rules, traffic.flows(result)), a.top)
    sys.stdout.write(RENDER[a.format](rep, stats))
    if a.format == "csv":
        print(LIMITS, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
