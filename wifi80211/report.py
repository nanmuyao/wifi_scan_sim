# -*- coding: utf-8 -*-
"""
一条命令出报告：抓包文件 + 密钥文件 -> 解密 -> 每台设备访问了什么（DNS / TLS / QUIC ...）-> 归到应用 -> 使用估计。纯标准库。
  python3 -m wifi80211.report capture.pcap --keys keys.txt [--rules my.json] [--gap 60] [--format table|json|csv]
                              [--unmatched 15] [--device MAC] [--min-events N]
退出码：0 正常；2 参数 / 文件 / 密钥文件有问题；3 抓包里有受保护的数据帧，但一个也没解开（多半是口令或 SSID 不对，或者没抓到完整的四次握手）。
"""
import argparse
import csv
import datetime
import io
import json
import re
import sys

from . import activity, apps, frames, keyfile, pipeline

LIMITS = "注意：使用时长是从网络活动推出的估计，不是屏幕使用时间；DoH / DoT / ECH 加密的访问看不到，只能看见明文 DNS、TLS 的 SNI 和 QUIC 的 SNI。"
EXIT_USAGE, EXIT_NO_DECRYPT = 2, 3


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


def render_table(rep, stats):
    out = ["抓包：%d 个受保护的数据帧，解开 %d 个；设备 %d 台。" % (stats["protected"], stats["decrypted"], len(rep["devices"]))]
    for d in rep["devices"]:
        out += ["", "设备 %s：%d 个访问事件（%s）" % (d["mac"], d["events"], "，".join("%s %d" % kv for kv in d["kinds"].items()))]
        if d["apps"]:
            out.append("  %-24s %-10s %6s %6s %9s  %-19s  %s" % ("应用", "类别", "段数", "事件", "估计秒数", "首次", "最后"))
            for r in d["apps"]:
                out.append("  %-24s %-10s %6d %6d %9.0f  %-19s  %s" % (r["app"], r["category"], r["sessions"], r["events"], r["seconds"], iso(r["first"]), iso(r["last"])))
        else:
            out.append("  没有能归到应用的域名。")
        if d["unlabelled"]:
            out.append("  没有规则的域名（前 %d 个，可以补进自己的规则）：" % len(d["unlabelled"]))
            out += ["    %5d  %s" % (n, name) for name, n in d["unlabelled"]]
    if not rep["devices"]:
        out += ["", "没有看到任何设备的 DNS / TLS / QUIC 访问（解开了数据帧，但里面没有这些）。"]
    return "\n".join(out + ["", LIMITS]) + "\n"


def render_json(rep, stats):
    doc = dict(rep, frames=stats, limits=LIMITS)
    doc["devices"] = [dict(d, apps=[dict(r, first_time=iso(r["first"]), last_time=iso(r["last"])) for r in d["apps"]]) for d in rep["devices"]]
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def render_csv(rep, stats):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["device", "row", "name", "category", "sessions", "events", "seconds", "first", "last"])
    for d in rep["devices"]:
        for r in d["apps"]:
            w.writerow([d["mac"], "app", r["app"], r["category"], r["sessions"], r["events"], "%.0f" % r["seconds"], iso(r["first"]), iso(r["last"])])
        for name, n in d["unlabelled"]:
            w.writerow([d["mac"], "unlabelled", name, "", "", n, "", "", ""])
    return buf.getvalue()


RENDER = {"table": render_table, "json": render_json, "csv": render_csv}


def main(argv=None):
    p = argparse.ArgumentParser(prog="python3 -m wifi80211.report", description="解密抓包并报告每台设备访问了什么（只用于自己的网络）。")
    p.add_argument("capture", help="抓包文件（pcap / pcapng，可以是 .gz）")
    p.add_argument("--keys", required=True, metavar="FILE", help="密钥文件（Wireshark 的 \"类型\",\"值\" 格式，见 wifi80211/keyfile.py）")
    p.add_argument("--rules", action="append", default=[], metavar="FILE", help="自己的域名 -> 应用规则（可以多次给），优先于自带规则")
    p.add_argument("--gap", type=float, default=60.0, metavar="SECONDS", help="相邻访问不超过这么多秒算同一段使用（默认 60）")
    p.add_argument("--format", choices=sorted(RENDER), default="table")
    p.add_argument("--unmatched", type=int, default=15, metavar="N", help="每台设备列出没有规则的域名前 N 个（默认 15）")
    p.add_argument("--device", metavar="MAC", help="只看这台设备")
    p.add_argument("--min-events", type=int, default=1, metavar="N", help="事件数少于 N 的设备不显示")
    try:
        a = p.parse_args(argv)
    except SystemExit as e:
        return EXIT_USAGE if e.code else 0
    err = lambda m: (print("错误：" + m, file=sys.stderr), EXIT_USAGE)[1]               # noqa: E731
    if a.gap <= 0 or a.unmatched < 0 or a.min_events < 0:
        return err("--gap 要大于 0，--unmatched 和 --min-events 不能是负数")
    mac = None
    if a.device:
        mac = norm_mac(a.device)
        if mac is None:
            return err("--device 不是 MAC 地址：%r" % a.device)
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
        fr = list(frames.iter_frames(a.capture))
    except (OSError, ValueError, EOFError) as e:
        return err("读不了抓包文件 %s：%s" % (a.capture, e))
    protected = sum(1 for f in fr if f.h["type"] == 2 and f.h["protected"])
    dec = pipeline.decrypt_capture(fr, keys)
    stats = {"frames": len(fr), "protected": protected, "decrypted": len(dec)}
    if protected and not dec:
        print("错误：抓包里有 %d 个受保护的数据帧，一个也没解开。读到的密钥：%s。多半是口令或 SSID 不对，或者没有抓到完整的四次握手（要抓到设备连接的那一刻）。" %
              (protected, "，".join("%s %d 把" % kv for kv in keyfile.summary(keys).items())), file=sys.stderr)
        return EXIT_NO_DECRYPT
    if not protected:
        print("提示：抓包里没有受保护的数据帧（没抓到数据，或者是开放网络——开放网络的明文暂不支持）。", file=sys.stderr)
    rep = build(activity.build(fr, dec), rules, a.gap, mac, a.min_events, a.unmatched)
    sys.stdout.write(RENDER[a.format](rep, stats))
    if a.format == "csv":
        print(LIMITS, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
