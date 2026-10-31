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
    ("ht_caps", "wlan.ht.capabilities"),
    ("ht_ampdu", "wlan.ht.ampduparam"),
    ("ht_mcs0", "wlan.ht.mcsset.rxbitmask.0to7"),
    ("ht_txdef", "wlan.ht.mcsset.txsetdefined"),
    ("ht_rate", "wlan.ht.mcsset.highestdatarate"),
    ("ht_primary", "wlan.ht.info.primarychannel"),
    ("ht_secoff", "wlan.ht.info.secchanoffset"),
    ("ht_width", "wlan.ht.info.chanwidth"),
    ("ht_rifs", "wlan.ht.info.rifs"),
    ("ht_prot", "wlan.ht.info.ht_protection"),
    ("ht_txrxneq", "wlan.ht.mcsset.txrxmcsnotequal"),
    ("ht_txunequal", "wlan.ht.mcsset.txunequalmod"),
]
# HT 能力信息里的单个位：我们的键 -> tshark 的字段名后缀；逐位对照，位号表写错就会被抓到
HT_FLAG_FIELDS = {"ldpc": "ldpccoding", "width40": "width", "greenfield": "green", "short_gi20": "short20",
                  "short_gi40": "short40", "tx_stbc": "txstbc", "delayed_ba": "delayedblockack", "max_amsdu_7935": "amsdu",
                  "dsss_cck_40": "dsscck", "psmp": "psmp", "forty_intolerant": "40mhzintolerant", "lsig_txop": "lsig"}
FIELDS += [("htcap_" + k, "wlan.ht.capabilities." + v) for k, v in HT_FLAG_FIELDS.items()]
# 厂商元素：WMM（信息 / 参数）与 WPA
FIELDS += [("wmm_subtype", "wlan.wfa.ie.wme.subtype"), ("wmm_version", "wlan.wfa.ie.wme.version"),
           ("wmm_qos", "wlan.wfa.ie.wme.qos_info"), ("wmm_uapsd", "wlan.wfa.ie.wme.qos_info.ap.u_apsd"),
           ("wmm_psc", "wlan.wfa.ie.wme.qos_info.ap.parameter_set_count"),
           ("wpa_version", "wlan.wfa.ie.wpa.version"), ("wpa_mcs", "wlan.wfa.ie.wpa.mcs.type")]
# 快速切换（移动域）、BSS 最大空闲周期、RSN 扩展元素
FIELDS += [("mdid", "wlan.mobility_domain.mdid"), ("mde_ft_capab", "wlan.mobility_domain.ft_capab"),
           ("mde_ft_over_ds", "wlan.mobility_domain.ft_capab.ft_over_ds"), ("mde_resource", "wlan.mobility_domain.ft_capab.resource_req"),
           ("idle_period", "wlan.bss_max_idle.period"), ("idle_options", "wlan.bss_max_idle.options"),
           ("idle_protected", "wlan.bss_max_idle.options.protected"),
           ("rsnx", "wlan.rsnx"), ("rsnx_len", "wlan.rsnx.length"), ("rsnx_twt", "wlan.rsnx.protected_twt_operations_support"),
           ("rsnx_h2e", "wlan.rsnx.sae_hash_to_element"), ("rsnx_pk", "wlan.rsnx.sae_pk")]
# Multi-Link（802.11be）：控制类型、公共信息长度、MLD MAC、链路 ID（第一个出现的）
FIELDS += [("ml_type", "wlan.eht.multi_link.control.type"), ("ml_common_len", "wlan.eht.multi_link.common_info.length"),
           ("ml_mld_mac", "wlan.eht.multi_link.common_info.mld_mac_address"),
           ("ml_link_id", "wlan.eht.multi_link.common_info.link_id_subfield.link_id")]
# HE（802.11ax）能力 / 操作：原始值、MCS 表、操作的主要字段
FIELDS += [("he_mac", "wlan.ext_tag.he_mac_caps"), ("he_chanwidth", "wlan.ext_tag.he_phy_cap.fbytes"),
           ("he_rx80", "wlan.ext_tag.he_mcs_map.rx_he_mcs_map_lte_80"), ("he_tx80", "wlan.ext_tag.he_mcs_map.tx_he_mcs_map_lte_80"),
           ("he_rx160", "wlan.ext_tag.he_mcs_map.rx_he_mcs_map_160"), ("he_tx160", "wlan.ext_tag.he_mcs_map.tx_he_mcs_map_160"),
           ("he_rx8080", "wlan.ext_tag.he_mcs_map.rx_he_mcs_map_80_80"), ("he_tx8080", "wlan.ext_tag.he_mcs_map.tx_he_mcs_map_80_80"),
           ("heop_params", "wlan.ext_tag.he_operation.params"), ("heop_pe", "wlan.ext_tag.he_operation.default_pe_duration"),
           ("heop_twt", "wlan.ext_tag.he_operation.twt_required"), ("heop_vht", "wlan.ext_tag.he_operation.vht_op_info_present"),
           ("heop_basic", "wlan.ext_tag.he_operation.basic_he_mcs_and_nss")]
WMM_AC = ("be", "bk", "vi", "vo")
for _ac in WMM_AC:
    FIELDS += [("wmm_aifsn_" + _ac, "wlan.wfa.ie.wme.acp.aifsn_" + _ac), ("wmm_acm_" + _ac, "wlan.wfa.ie.wme.acp.acm_" + _ac),
               ("wmm_ecwmin_" + _ac, "wlan.wfa.ie.wme.acp.ecw.min_" + _ac), ("wmm_ecwmax_" + _ac, "wlan.wfa.ie.wme.acp.ecw.max_" + _ac),
               ("wmm_txop_" + _ac, "wlan.wfa.ie.wme.acp.txop_limit_" + _ac)]
# 元素内容字段只对管理帧比较：数据帧里 EAPOL-Key 的 Key Data 也带元素，那个缺口已经在「tags」一行单独登记（阶段 D）
CONTENT_FIELDS = {"ssid", "ds_channel", "dtim_count", "dtim_period", "tim_multicast", "tim_offset", "tim_bitmap", "country",
                  "country_env", "erp", "erp_present", "erp_protection", "erp_barker", "rsn_version", "rsn_gcs",
                  "rsn_gcs_oui", "rsn_caps", "rsn_mfpr", "rsn_mfpc", "rsn_pmkid_count", "rsn_gmcs",
                  "ht_caps", "ht_ampdu", "ht_mcs0", "ht_txdef", "ht_rate", "ht_primary", "ht_secoff", "ht_width", "ht_rifs",
                  "ht_prot", "extcap_bits", "mdid", "mde_ft_capab", "mde_ft_over_ds", "mde_resource", "idle_period", "idle_options", "idle_protected", "rsnx",
                  "rsnx_len", "rsnx_twt", "rsnx_h2e", "rsnx_pk", "he_mac", "he_chanwidth", "he_rx80", "he_tx80", "he_rx160", "he_tx160", "he_rx8080", "he_tx8080", "heop_params", "heop_pe",
                  "heop_twt", "heop_vht", "heop_basic", "vendor_oui", "wfa_type", "wpa_ucs", "wpa_akm", "ml_type", "ml_common_len", "ml_mld_mac", "ml_link_id", "ml_sta_ctrl",
                  "ml_sta_link_ids", "wmm_subtype", "wmm_version", "wmm_qos",
                  "wmm_uapsd", "wmm_psc", "wpa_version", "wpa_mcs", *["wmm_%s_%s" % (k, ac) for ac in WMM_AC for k in ("aifsn", "acm", "ecwmin", "ecwmax", "txop")], "ht_txrxneq", "ht_txunequal", *["htcap_" + k for k in HT_FLAG_FIELDS],
                  "rates", "ext_rates", "country_fcn", "country_nc", "country_mtpl", "rsn_pcs", "rsn_akm"}
# 一帧里出现多次的字段（每个元素的内容是一串值）：整个列表按顺序比较
TSHARK_EXTRA = [("tags", "wlan.tag.number"), ("ext_tags", "wlan.ext_tag.number"),
                ("rates", "wlan.supported_rates"), ("ext_rates", "wlan.extended_supported_rates"),
                ("country_fcn", "wlan.country_info.fnm.fcn"), ("country_nc", "wlan.country_info.fnm.nc"),
                ("country_mtpl", "wlan.country_info.fnm.mtpl"),
                ("rsn_pcs", "wlan.rsn.pcs.type"), ("rsn_akm", "wlan.rsn.akms.type"),
                ("vendor_oui", "wlan.tag.oui"), ("wfa_type", "wlan.wfa.ie.type"),
                ("wpa_ucs", "wlan.wfa.ie.wpa.ucs.type"), ("wpa_akm", "wlan.wfa.ie.wpa.akms"),
                ("ml_sta_ctrl", "wlan.eht.multi_link.sta_profile.sta_control"),
                ("ml_sta_link_ids", "wlan.eht.multi_link.sta_profile.sta_control.link_id")]    # akms.type 在 Wireshark 里被登记成了 wlan.wfa.ie.wpa.type，取不到；用完整的 32 位套件值（OUI << 8 | 类型）
TSHARK_MAJOR_MINOR = "4.4"


_EXTCAP_BITS = []


def extcap_bool_bits():
    """tshark 为扩展能力定义了单独布尔字段（wlan.extcap.bN）的位号；多位字段、保留位不在其中。"""
    if not _EXTCAP_BITS:
        out = subprocess.run(["tshark", "-G", "fields"], capture_output=True, text=True).stdout
        for line in out.split("\n"):
            p = line.split("\t")
            if len(p) >= 4 and p[2].startswith("wlan.extcap.b") and p[3] == "FT_BOOLEAN":
                _EXTCAP_BITS.append(int(p[2][len("wlan.extcap.b"):]))
        _EXTCAP_BITS.sort()
    return _EXTCAP_BITS


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
                "dtim_period", "country_env", "ml_type", "ml_common_len", "ml_link_id", "idle_period", "rsnx_len", "wmm_subtype", "wmm_version", "wpa_version", "wpa_mcs",
                *["wmm_%s_%s" % (k, ac) for ac in WMM_AC for k in ("aifsn", "ecwmin", "ecwmax", "txop")], "rsn_version", "rsn_gcs", "rsn_pmkid_count", "rsn_gmcs", "ht_rate",
                "ht_primary", "heop_pe"):
        return int(v, 16) if v.startswith("0x") else int(v)      # tshark 对有掩码的位字段按十六进制显示
    if name in ("ackpolicy", "htc", "llc_dsap", "rt_flags", "chan_flags", "rxflags", "fcs", "tim_offset", "erp", "rsn_caps", "rsn_gcs_oui", "ht_caps", "ht_ampdu", "ht_mcs0", "ht_secoff", "ht_prot", "wmm_qos", "wmm_psc", "mdid", "mde_ft_capab", "idle_options", "rsnx",
                "he_mac", "he_chanwidth", "he_rx80", "he_tx80", "he_rx160", "he_tx160", "he_rx8080", "he_tx8080", "heop_params", "heop_basic"):
        return int(v, 0)
    if name in ("ssid", "tim_bitmap"):
        return b"" if v == "<MISSING>" else bytes.fromhex(v)      # 长度为 0 的字节串，tshark 写成 <MISSING>
    if name == "country":
        return v
    if name in ("heop_twt", "heop_vht"):
        return v == "True"
    if name in ("mde_ft_over_ds", "mde_resource", "idle_protected"):      # 带掩码的位字段，显示成「掩码后的值」：非 0 就是置位
        return int(v, 0) != 0
    if name == "datarate":
        return float(v)
    if name == "fcs_ok":                 # tshark 的校验状态：1 = 通过，0 = 不通过，其它 = 没校验
        return {"1": True, "0": False}.get(v)
    if name in ("retry", "protected", "tods", "fromds", "morefrag", "pwrmgt", "moredata", "order", "amsdu",
                "tim_multicast", "erp_present", "erp_protection", "erp_barker", "rsn_mfpr", "rsn_mfpc", "ht_txdef", "ht_width", "ht_rifs", "ht_txrxneq", "ht_txunequal", "rsnx_twt", "rsnx_h2e", "rsnx_pk", "wmm_uapsd", *["wmm_acm_" + ac for ac in WMM_AC],
                "htcap_ldpc", "htcap_width40", "htcap_greenfield", "htcap_short_gi20", "htcap_short_gi40", "htcap_tx_stbc",
                "htcap_delayed_ba", "htcap_max_amsdu_7935", "htcap_dsss_cck_40", "htcap_psmp", "htcap_forty_intolerant",
                "htcap_lsig_txop"):
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
    bits = extcap_bool_bits()
    cmd3 = ["tshark", "-r", path, "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    for n in bits:
        cmd3 += ["-e", "wlan.extcap.b%d" % n]
    r = subprocess.run(cmd, capture_output=True, text=True)
    r2 = subprocess.run(cmd2, capture_output=True, text=True)
    r3 = subprocess.run(cmd3, capture_output=True, text=True)
    lines3 = r3.stdout.split("\n")
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
        p3 = (lines3[i].split("\t") if i < len(lines3) else []) + [""] * len(bits)
        fr["extcap_bits"] = [n for n, v in zip(bits, p3) if v == "True"]
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


def _flat(rec, key):
    """Multi-Link 嵌套展开之后，全部同类元素的内容串起来（速率等）；这一帧没解码元素时 None。"""
    f = rec.get("ie_flat")
    return None if f is None else f[key]


def _ml(rec, key):
    """这一帧第一个 Multi-Link 元素的某个字段；没有 Multi-Link 时 None。"""
    f = rec.get("ie_flat")
    if f is None or not f["multi_link"] or f["multi_link"][0] is None:
        return None
    return f["multi_link"][0][key]


def _ml_stas(rec, key):
    """第一个 Multi-Link 元素里每个站点配置的某个字段（按出现顺序）。"""
    f = rec.get("ie_flat")
    if f is None or not f["multi_link"] or f["multi_link"][0] is None:
        return None
    return [s[key] for s in f["multi_link"][0]["stas"]]


def _vendors(rec, value, keep=lambda v: True):
    """所有厂商元素（含 Multi-Link 嵌套的）的某个值，按出现顺序；这一帧没解码元素时 None。"""
    f = rec.get("ie_flat")
    if f is None:
        return None
    return [value(v) for v in f["vendors"] if v and keep(v)]


def _suite_list_of(rec, name, key):
    s = _ie(rec, name, key)
    return None if s is None else [t for _, t in s]


def _suite_values(rec, name, key):
    """套件列表里每个套件的完整 32 位值（OUI << 8 | 类型）；没有时 None。"""
    s = _ie(rec, name, key)
    return None if s is None else [oui << 8 | t for oui, t in s]


def _wmm_ac(rec, ac, key):
    ac_d = _ie(rec, "wmm", "ac")
    return None if ac_d is None else ac_d[ac][key]


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
    import ie
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
            "rates": _flat(r, "rates"),
            "ext_rates": _flat(r, "ext_rates"),
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
            "ht_caps": _ie(r, "ht_cap", "caps"),
            "ht_ampdu": _ie(r, "ht_cap", "ampdu_param"),
            "ht_mcs0": None if _ie(r, "ht_cap", "rx_mcs") is None else _ie(r, "ht_cap", "rx_mcs")[0],
            "ht_txdef": _ie(r, "ht_cap", "tx_defined"),
            "ht_rate": _ie(r, "ht_cap", "highest_rate"),
            "ht_primary": _ie(r, "ht_op", "primary_channel"),
            "ht_secoff": _ie(r, "ht_op", "secondary_offset"),
            "ht_width": _ie(r, "ht_op", "width_any"),
            "ht_rifs": _ie(r, "ht_op", "rifs"),
            "ht_prot": _ie(r, "ht_op", "ht_protection"),
            "he_mac": _ie(r, "he_cap", "mac_caps"),
            "he_chanwidth": None if _ie(r, "he_cap", "phy0") is None else _ie(r, "he_cap", "phy0") >> 1,    # tshark 的「信道宽度集」= PHY 能力第 0 字节的 bit1-7
            "he_rx80": _ie(r, "he_cap", "rx_lte80"),
            "he_tx80": _ie(r, "he_cap", "tx_lte80"),
            "he_rx160": _ie(r, "he_cap", "rx_160"),
            "he_tx160": _ie(r, "he_cap", "tx_160"),
            "he_rx8080": _ie(r, "he_cap", "rx_80p80"),
            "he_tx8080": _ie(r, "he_cap", "tx_80p80"),
            "heop_params": _ie(r, "he_op", "params"),
            "heop_pe": _ie(r, "he_op", "default_pe_duration"),
            "heop_twt": _ie(r, "he_op", "twt_required"),
            "heop_vht": _ie(r, "he_op", "vht_op_present"),
            "heop_basic": _ie(r, "he_op", "basic_mcs_nss"),
            "mdid": _ie(r, "mdie", "mdid"),
            "mde_ft_capab": _ie(r, "mdie", "ft_capab"),
            "mde_ft_over_ds": _ie(r, "mdie", "ft_over_ds"),
            "mde_resource": _ie(r, "mdie", "resource_request"),
            "idle_period": _ie(r, "bss_max_idle", "period"),
            "idle_options": _ie(r, "bss_max_idle", "options"),
            "idle_protected": _ie(r, "bss_max_idle", "protected_keepalive"),
            "rsnx": None if _ie(r, "rsnxe", "octets") is None else _ie(r, "rsnxe", "octets")[0],
            "rsnx_len": _ie(r, "rsnxe", "length_field"),
            "rsnx_twt": _ie(r, "rsnxe", "protected_twt"),
            "rsnx_h2e": _ie(r, "rsnxe", "sae_h2e"),
            "rsnx_pk": _ie(r, "rsnxe", "sae_pk"),
            "vendor_oui": _vendors(r, lambda v: v["oui"]),
            "wfa_type": _vendors(r, lambda v: v["type"], lambda v: v["oui"] == 0x0050F2),
            "ml_type": _ml(r, "type"),
            "ml_common_len": _ml(r, "common_len"),
            "ml_mld_mac": _ml(r, "mld_mac"),
            "ml_link_id": _ml(r, "link_id"),
            "ml_sta_ctrl": _ml_stas(r, "control"),
            "ml_sta_link_ids": _ml_stas(r, "link_id"),
            "wpa_ucs": _suite_list_of(r, "wpa", "pairwise"),
            "wpa_akm": _suite_values(r, "wpa", "akm"),
            "wpa_version": _ie(r, "wpa", "version"),
            "wpa_mcs": None if _ie(r, "wpa", "group") is None else _ie(r, "wpa", "group")[1],
            "wmm_subtype": _ie(r, "wmm", "subtype"),
            "wmm_version": _ie(r, "wmm", "version"),
            "wmm_qos": _ie(r, "wmm", "qos_info"),
            "wmm_uapsd": _ie(r, "wmm", "uapsd"),
            "wmm_psc": _ie(r, "wmm", "param_set_count"),
            **{"wmm_%s_%s" % (k, ac): _wmm_ac(r, ac, v) for ac in WMM_AC
               for k, v in (("aifsn", "aifsn"), ("acm", "acm"), ("ecwmin", "ecw_min"), ("ecwmax", "ecw_max"), ("txop", "txop"))},
            "ht_txrxneq": _ie(r, "ht_cap", "tx_rx_unequal"),
            "ht_txunequal": _ie(r, "ht_cap", "tx_unequal_mod"),
            **{"htcap_" + k: _ie(r, "ht_cap", k) for k in HT_FLAG_FIELDS},
            "extcap_bits": None if _ie(r, "ext_caps", "octets") is None else
                           [n for n in extcap_bool_bits() if ie.ext_cap_bit(_ie(r, "ext_caps", "octets"), n)],
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


LIST_FIELDS = [name for name, _ in TSHARK_EXTRA] + ["extcap_bits"]       # 信息元素编号列表：按顺序整个比较


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
