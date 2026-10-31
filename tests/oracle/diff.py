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
    ("rt_length", "radiotap.length"),
    ("mactime", "radiotap.mactime"),
    ("rt_flags", "radiotap.flags"),
    ("datarate", "radiotap.datarate"),
    ("freq", "radiotap.channel.freq"),
    ("chan_flags", "radiotap.channel.flags"),
    ("antsignal", "radiotap.dbm_antsignal"),
    ("antnoise", "radiotap.dbm_antnoise"),
    ("antenna", "radiotap.antenna"),
    ("rxflags", "radiotap.rxflags"),
    ("db_antsignal", "radiotap.db_antsignal"),
    ("quality", "radiotap.quality"),
    ("mcs_index", "radiotap.mcs.index"),
    ("ampdu_ref", "radiotap.ampdu.reference"),
    ("rt_ts", "radiotap.timestamp.ts"),
    ("fcs", "wlan.fcs"),
    ("fcs_ok", "wlan.fcs.status"),
    ("llc_dsap", "llc.dsap"),      # tshark 在帧体里找到的 LLC：我们的头长度错了，读到的首字节就对不上
    ("ssid", "wlan.ssid"),
    ("ds_channel", "wlan.ds.current_channel"),
    ("dtim_count", "wlan.tim.dtim_count"),
    ("dtim_period", "wlan.tim.dtim_period"),
    ("tim_multicast", "wlan.tim.bmapctl.multicast"),
    ("tim_offset", "wlan.tim.bmapctl.offset"),
    ("tim_bitmap", "wlan.tim.partial_virtual_bitmap"),
    ("country", "wlan.country_info.code"),
    ("country_env", "wlan.country_info.environment"),
    ("erp", "wlan.erp_info"),
    ("erp_present", "wlan.erp_info.erp_present"),
    ("erp_protection", "wlan.erp_info.use_protection"),
    ("erp_barker", "wlan.erp_info.barker_preamble_mode"),
    ("rsn_version", "wlan.rsn.version"),
    ("rsn_gcs", "wlan.rsn.gcs.type"),
    ("rsn_gcs_oui", "wlan.rsn.gcs.oui"),
    ("rsn_caps", "wlan.rsn.capabilities"),
    ("rsn_mfpr", "wlan.rsn.capabilities.mfpr"),
    ("rsn_mfpc", "wlan.rsn.capabilities.mfpc"),
    ("rsn_pmkid_count", "wlan.rsn.pmkid.count"),
    ("rsn_gmcs", "wlan.rsn.gmcs.type"),
]
# 元素内容字段只对管理帧比较：数据帧里 EAPOL-Key 的 Key Data 也带元素，那个缺口已经在「tags」一行单独登记（阶段 D）
CONTENT_FIELDS = {"ssid", "ds_channel", "dtim_count", "dtim_period", "tim_multicast", "tim_offset", "tim_bitmap", "country",
                  "country_env", "erp", "erp_present", "erp_protection", "erp_barker", "rsn_version", "rsn_gcs",
                  "rsn_gcs_oui", "rsn_caps", "rsn_mfpr", "rsn_mfpc", "rsn_pmkid_count", "rsn_gmcs",
                  "rates", "ext_rates", "country_fcn", "country_nc", "country_mtpl", "rsn_pcs", "rsn_akm"}
# 一帧里出现多次的字段（每个元素的内容是一串值）：整个列表按顺序比较
TSHARK_EXTRA = [("tags", "wlan.tag.number"), ("ext_tags", "wlan.ext_tag.number"),
                ("rates", "wlan.supported_rates"), ("ext_rates", "wlan.extended_supported_rates"),
                ("country_fcn", "wlan.country_info.fnm.fcn"), ("country_nc", "wlan.country_info.fnm.nc"),
                ("country_mtpl", "wlan.country_info.fnm.mtpl"),
                ("rsn_pcs", "wlan.rsn.pcs.type"), ("rsn_akm", "wlan.rsn.akms.type")]
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
    if name in ("seq", "duration", "frag", "priority", "rt_length", "mactime", "freq", "antsignal", "antnoise",
                "antenna", "db_antsignal", "quality", "mcs_index", "ampdu_ref", "rt_ts", "ds_channel", "dtim_count",
                "dtim_period", "country_env", "rsn_version", "rsn_gcs", "rsn_pmkid_count", "rsn_gmcs"):
        return int(v)
    if name in ("ackpolicy", "htc", "llc_dsap", "rt_flags", "chan_flags", "rxflags", "fcs", "tim_offset", "erp", "rsn_caps", "rsn_gcs_oui"):
        return int(v, 0)
    if name in ("ssid", "tim_bitmap"):
        return b"" if v == "<MISSING>" else bytes.fromhex(v)      # 长度为 0 的字节串，tshark 写成 <MISSING>
    if name == "country":
        return v
    if name == "datarate":
        return float(v)
    if name == "fcs_ok":                 # tshark 的校验状态：1 = 通过，0 = 不通过，其它 = 没校验
        return {"1": True, "0": False}.get(v)
    if name in ("retry", "protected", "tods", "fromds", "morefrag", "pwrmgt", "moredata", "order", "amsdu",
                "tim_multicast", "erp_present", "erp_protection", "erp_barker", "rsn_mfpr", "rsn_mfpc"):
        return v == "True"
    return v


def tshark_frames(path):
    """tshark 对每一帧的解析结果：[{字段名: 值或 None, "tags": [...], "ext_tags": [...]}]"""
    cols = FIELDS + TSHARK_EXTRA
    cmd = ["tshark", "-r", path, "-o", "wlan.check_checksum:TRUE", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    for _, f in FIELDS:
        cmd += ["-e", f]
    # 一帧里出现多次的字段（信息元素编号、速率列表等）：单独取全部出现
    cmd2 = ["tshark", "-r", path, "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    for _, f in TSHARK_EXTRA:
        cmd2 += ["-e", f]
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
        p2 = (lines2[i].split("\t") if i < len(lines2) else []) + [""] * len(TSHARK_EXTRA)
        for j, (name, _) in enumerate(TSHARK_EXTRA):
            fr[name] = [int(x, 0) for x in p2[j].split(",") if x]
        if (fr["type_subtype"] or 0) >> 4 != 0 or fr["type_subtype"] is None:
            for name in CONTENT_FIELDS:
                fr[name] = None if name in fr and not isinstance(fr[name], list) else []
        frames.append(fr)
    return frames


def _ie(rec, name, key):
    """rec["ie"][name][key]；这一帧没有解码出这个元素时 None。"""
    d = rec.get("ie")
    if d is None:
        return None
    e = d.get(name)
    return None if e is None else e[key]


def _suite_part(rec, key, i):
    """RSN 元素里某个套件的 OUI(i=0) 或类型(i=1)；没有时 None。"""
    s = _ie(rec, "rsn", key)
    return None if s is None else s[i]


def _suite_list(rec, key):
    """RSN 元素里成对密码 / AKM 套件列表的类型；没有时 None。"""
    s = _ie(rec, "rsn", key)
    return None if s is None else [t for _, t in s]


def _triplets(rec, key):
    """国家元素里（起始信道, 信道数, 最大功率）三元组的某一项，全部按顺序；没有国家元素时 None。"""
    c = (rec.get("ie") or {}).get("country")
    if c is None:
        return None
    return [t[key] for t in c["triplets"] if key in t]


def ours_frames(path):
    """本项目解析器对每一帧的解析结果，字段与 tshark_frames 对齐。读不开的文件抛异常。"""
    import radiotap
    import wifi_frame_parser as w
    _, recs = w.parse_pcap_file(path)
    out = []
    for r in recs:
        rt = r.get("radiotap") or {}
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
            "tags": r.get("ie_ids"),
            "ext_tags": r.get("ie_ext_ids"),
            "rates": _ie(r, "rates", "rates"),
            "ext_rates": _ie(r, "ext_rates", "rates"),
            "country_fcn": _triplets(r, "first_channel"),
            "country_nc": _triplets(r, "num_channels"),
            "country_mtpl": _triplets(r, "max_power"),
            "ssid": _ie(r, "ssid", "ssid"),
            "ds_channel": _ie(r, "ds", "channel"),
            "dtim_count": _ie(r, "tim", "dtim_count"),
            "dtim_period": _ie(r, "tim", "dtim_period"),
            "tim_multicast": _ie(r, "tim", "multicast"),
            "tim_offset": _ie(r, "tim", "offset"),
            "tim_bitmap": _ie(r, "tim", "bitmap"),
            "country": _ie(r, "country", "code"),
            "country_env": _ie(r, "country", "environment"),
            "erp": _ie(r, "erp", "value"),
            "erp_present": _ie(r, "erp", "non_erp_present"),
            "erp_protection": _ie(r, "erp", "use_protection"),
            "erp_barker": _ie(r, "erp", "barker_preamble"),
            "rsn_version": _ie(r, "rsn", "version"),
            "rsn_gcs": _suite_part(r, "group", 1),
            "rsn_gcs_oui": _suite_part(r, "group", 0),
            "rsn_caps": _ie(r, "rsn", "caps"),
            "rsn_mfpr": _ie(r, "rsn", "mfpr"),
            "rsn_mfpc": _ie(r, "rsn", "mfpc"),
            "rsn_pmkid_count": None if _ie(r, "rsn", "pmkids") is None else len(_ie(r, "rsn", "pmkids")),
            "rsn_gmcs": _suite_part(r, "group_mgmt", 1),
            "rsn_pcs": _suite_list(r, "pairwise"),
            "rsn_akm": _suite_list(r, "akm"),
            "rt_length": rt.get("length"),
            "mactime": rt.get("tsft"),
            "rt_flags": rt.get("flags"),
            "datarate": radiotap.data_rate_mbps(rt) if rt else None,
            "freq": (rt.get("channel") or {}).get("freq"),
            "chan_flags": (rt.get("channel") or {}).get("flags"),
            "antsignal": rt.get("antsignal"),
            "antnoise": rt.get("antnoise"),
            "antenna": rt.get("antenna"),
            "rxflags": rt.get("rx_flags"),
            "db_antsignal": rt.get("db_antsignal"),
            "quality": rt.get("lock_quality"),
            "mcs_index": (rt.get("mcs") or {}).get("index"),
            "ampdu_ref": (rt.get("ampdu") or {}).get("reference"),
            "rt_ts": (rt.get("timestamp") or {}).get("ts"),
            "fcs": r.get("fcs"),
            "fcs_ok": r.get("fcs_ok"),
        })
    return out


LIST_FIELDS = [name for name, _ in TSHARK_EXTRA]       # 信息元素编号列表：按顺序整个比较


def compare(oracle, ours):
    """返回 {字段: {"ok": n, "diff": n, "missing": n}} 和不一致明细 [(帧号, 字段, 标准答案, 我们)]。"""
    names = [n for n, _ in FIELDS] + LIST_FIELDS
    stats = {name: {"ok": 0, "diff": 0, "missing": 0} for name in names}
    details = []
    for i, o in enumerate(oracle):
        u = ours[i] if i < len(ours) else {}
        for name in names:
            want, got = o.get(name), u.get(name)
            if name in LIST_FIELDS and not want:
                if got:                       # tshark 没列出元素，我们却列出来了（例如把加密的帧体当元素解析）
                    stats[name]["diff"] += 1
                    details.append((i + 1, name, want, got))
                continue
            if want is None:
                continue
            if got is None:
                stats[name]["missing"] += 1
            elif got == want or (isinstance(want, float) and abs(got - want) < 1e-3):    # tshark 把浮点数四舍五入到 6 位有效数字
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
    names = [n for n, _ in FIELDS] + LIST_FIELDS
    total = {name: {"ok": 0, "diff": 0, "missing": 0} for name in names}
    opened = 0
    for r in results:
        name = os.path.basename(r["path"])
        if r["error"]:
            print("%-42s tshark %5d 帧  无法读取: %s" % (name, r["frames"], r["error"][:60]))
            continue
        opened += 1
        s = r["stats"]
        cells = " ".join("%s=%d/%d/%d" % (n, s[n]["ok"], s[n]["diff"], s[n]["missing"]) for n in names)
        print("%-42s tshark %5d 帧  我们 %5d 帧  %s" % (name, r["frames"], r["ours_frames"], cells))
        for n in names:
            for k in total[n]:
                total[n][k] += s[n][k]
        for d in r["details"][:show_details]:
            print("      帧 %d %s: tshark=%r 我们=%r" % d)
    print("\n能打开 %d / %d 个抓包。字段统计（一致/不一致/我们没解析）：" % (opened, len(results)))
    for n in names:
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
