#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
差分测试：同一个抓包，tshark（标准答案）与本项目解析器逐帧对比。

用法（在容器里，见 tests/docker.sh）：
    python3 tests/oracle/diff.py FILE [FILE...]      对比指定抓包
    python3 tests/oracle/diff.py --samples            对比 tests/oracle/samples/ 里的全部公开样例

每个字段给出三种结果：一致 / 不一致 / 我们没解析出来（tshark 有值而我们没有）。
tshark 没有值的字段（例如控制帧没有序号）不参与对比。
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

# 对比的字段：名字 -> tshark 字段
FIELDS = [
    ("type_subtype", "wlan.fc.type_subtype"),
    ("ra", "wlan.ra"),
    ("ta", "wlan.ta"),
    ("seq", "wlan.seq"),
    ("retry", "wlan.fc.retry"),
    ("protected", "wlan.fc.protected"),
    ("tods", "wlan.fc.tods"),
    ("fromds", "wlan.fc.fromds"),
    ("duration", "wlan.duration"),
    ("frag", "wlan.frag"),
    ("morefrag", "wlan.fc.frag"),
    ("pwrmgt", "wlan.fc.pwrmgt"),
    ("moredata", "wlan.fc.moredata"),
    ("order", "wlan.fc.order"),
    ("da", "wlan.da"),
    ("sa", "wlan.sa"),
    ("bssid", "wlan.bssid"),
    ("priority", "wlan.qos.priority"),
    ("ackpolicy", "wlan.qos.ack"),
    ("amsdu", "wlan.qos.amsdupresent"),
    ("htc", "wlan.htc"),
    ("llc_dsap", "llc.dsap"),      # tshark 在帧体里找到的 LLC：我们的头长度错了，读到的首字节就对不上
]
TSHARK_EXTRA = [("tags", "wlan.tag.number"), ("ext_tags", "wlan.ext_tag.number")]
TSHARK_MAJOR_MINOR = "4.4"


def tshark_version():
    out = subprocess.run(["tshark", "--version"], capture_output=True, text=True).stdout
    return out.split("\n", 1)[0].split()[-1].rstrip(".")


def _norm(name, v):
    """tshark 的字符串 -> 与 ours_frames 相同的规范形式；空字符串表示这个帧没有这个字段。"""
    if v == "":
        return None
    if name == "type_subtype":
        return int(v, 16)
    if name in ("seq", "duration", "frag", "priority"):
        return int(v)
    if name in ("ackpolicy", "htc", "llc_dsap"):
        return int(v, 0)
    if name in ("retry", "protected", "tods", "fromds", "morefrag", "pwrmgt", "moredata", "order", "amsdu"):
        return v == "True"
    return v


def tshark_frames(path):
    """tshark 对每一帧的解析结果：[{字段名: 值或 None, "tags": [...], "ext_tags": [...]}]"""
    cols = FIELDS + TSHARK_EXTRA
    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    for _, f in FIELDS:
        cmd += ["-e", f]
    # 信息元素编号一帧里有很多个：单独取全部出现
    cmd2 = ["tshark", "-r", path, "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a",
            "-E", "aggregator=,", "-e", "wlan.tag.number", "-e", "wlan.ext_tag.number"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    r2 = subprocess.run(cmd2, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("tshark 失败: " + r.stderr.strip()[:200])
    frames = []
    lines2 = r2.stdout.split("\n")
    for i, line in enumerate(r.stdout.split("\n")):
        if line == "" and i >= len(r.stdout.rstrip("\n").split("\n")):
            continue
        parts = line.split("\t")
        parts += [""] * (len(FIELDS) - len(parts))
        fr = {name: _norm(name, parts[j]) for j, (name, _) in enumerate(FIELDS)}
        p2 = (lines2[i].split("\t") if i < len(lines2) else []) + ["", ""]
        fr["tags"] = [int(x) for x in p2[0].split(",") if x]
        fr["ext_tags"] = [int(x) for x in p2[1].split(",") if x]
        frames.append(fr)
    return frames


def ours_frames(path):
    """本项目解析器对每一帧的解析结果，字段与 tshark_frames 对齐。读不开的文件抛异常。"""
    import wifi_frame_parser as w
    _, recs = w.parse_pcap_file(path)
    out = []
    for r in recs:
        has_type = "ftype" in r
        out.append({
            "type_subtype": (r["ftype"] << 4 | r["fsubtype"]) if has_type else None,
            "ra": r.get("addr1", r.get("ra")),
            "ta": r.get("addr2", r.get("ta")),
            "seq": r.get("seq_num"),
            "retry": None if "retry" not in r else bool(r["retry"]),
            "protected": None if "protected" not in r else bool(r["protected"]),
            "tods": None if "to_ds" not in r else bool(r["to_ds"]),
            "fromds": None if "from_ds" not in r else bool(r["from_ds"]),
            "duration": r.get("duration"),
            "frag": r.get("frag_num"),
            "morefrag": None if "more_frag" not in r else bool(r["more_frag"]),
            "pwrmgt": None if "pwr_mgmt" not in r else bool(r["pwr_mgmt"]),
            "moredata": None if "more_data" not in r else bool(r["more_data"]),
            "order": None if "order" not in r else bool(r["order"]),
            "da": r.get("da"),
            "sa": r.get("sa"),
            "bssid": r.get("bssid"),
            "priority": None if r.get("qos_tid") is None else r["qos_tid"] & 7,   # tshark 的 Priority 是 TID 的低 3 位
            "ackpolicy": r.get("qos_ack_policy"),
            "amsdu": None if "qos_amsdu" not in r else bool(r["qos_amsdu"]),
            "htc": r.get("htc"),
            "llc_dsap": r.get("llc_dsap"),
        })
    return out


def compare(oracle, ours):
    """返回 {字段: {"ok": n, "diff": n, "missing": n}} 和不一致明细 [(帧号, 字段, 标准答案, 我们)]。"""
    stats = {name: {"ok": 0, "diff": 0, "missing": 0} for name, _ in FIELDS}
    details = []
    for i, o in enumerate(oracle):
        u = ours[i] if i < len(ours) else {}
        for name, _ in FIELDS:
            want, got = o[name], u.get(name)
            if want is None:
                continue
            if got is None:
                stats[name]["missing"] += 1
            elif got == want:
                stats[name]["ok"] += 1
            else:
                stats[name]["diff"] += 1
                details.append((i + 1, name, want, got))
    return stats, details


def diff_file(path):
    """对比一个抓包。返回 dict：frames、ours_frames、error（读不开时）、stats、details。"""
    oracle = tshark_frames(path)
    res = {"path": path, "frames": len(oracle), "error": None, "ours_frames": 0, "stats": None, "details": []}
    try:
        ours = ours_frames(path)
    except Exception as exc:                       # 读不开（格式不支持等）
        res["error"] = "%s: %s" % (type(exc).__name__, exc)
        return res
    res["ours_frames"] = len(ours)
    res["stats"], res["details"] = compare(oracle, ours)
    return res


def print_report(results, show_details=5):
    total = {name: {"ok": 0, "diff": 0, "missing": 0} for name, _ in FIELDS}
    opened = 0
    for r in results:
        name = os.path.basename(r["path"])
        if r["error"]:
            print("%-42s tshark %5d 帧  无法读取: %s" % (name, r["frames"], r["error"][:60]))
            continue
        opened += 1
        s = r["stats"]
        cells = " ".join("%s=%d/%d/%d" % (n, s[n]["ok"], s[n]["diff"], s[n]["missing"]) for n, _ in FIELDS)
        print("%-42s tshark %5d 帧  我们 %5d 帧  %s" % (name, r["frames"], r["ours_frames"], cells))
        for n, _ in FIELDS:
            for k in total[n]:
                total[n][k] += s[n][k]
        for d in r["details"][:show_details]:
            print("      帧 %d %s: tshark=%r 我们=%r" % d)
    print("\n能打开 %d / %d 个抓包。字段统计（一致/不一致/我们没解析）：" % (opened, len(results)))
    for n, _ in FIELDS:
        print("  %-13s %d / %d / %d" % (n, total[n]["ok"], total[n]["diff"], total[n]["missing"]))


def main(argv):
    if tshark_version().split(".")[:2] != TSHARK_MAJOR_MINOR.split("."):
        print("注意：tshark 版本是 %s，本工具按 %s.x 写的" % (tshark_version(), TSHARK_MAJOR_MINOR))
    if argv[:1] == ["--samples"]:
        d = os.path.join(ROOT, "tests", "oracle", "samples")
        files = sorted(os.path.join(d, f) for f in os.listdir(d)) if os.path.isdir(d) else []
        if not files:
            print("没有样例：先运行 python3 tests/oracle/fetch_samples.py")
            return 1
    else:
        files = argv
    if not files:
        print(__doc__)
        return 1
    print_report([diff_file(f) for f in files])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
