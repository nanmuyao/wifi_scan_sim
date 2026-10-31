# -*- coding: utf-8 -*-
"""
信息元素（Information Element，tagged parameters）。纯标准库。

管理帧固定部分之后是一串元素：1 字节 ID、1 字节长度、数据。ID 255 是“扩展元素”：数据的第一个字节是扩展 ID。
walk() 按出现顺序返回全部元素（同一 ID 可以出现多次，例如多个厂商元素），不丢弃、不合并；
元素的长度超过剩余字节时，已读到的保留，并报告 truncated。
"""
from collections import namedtuple

Element = namedtuple("Element", "id ext data offset")      # ext：扩展元素的扩展 ID，否则 None

ID_EXTENSION = 255

# 管理帧子类型 -> 固定部分长度（元素从这之后开始）。没有列出的子类型（Action 等）帧体不是元素序列。
FIXED_LEN = {
    0: 4,      # Association Request：能力 2 + 监听间隔 2
    1: 6,      # Association Response：能力 2 + 状态 2 + AID 2
    2: 10,     # Reassociation Request：能力 2 + 监听间隔 2 + 当前 AP 6
    3: 6,      # Reassociation Response：同 Association Response
    4: 0,      # Probe Request
    5: 12,     # Probe Response：时间戳 8 + 信标间隔 2 + 能力 2
    8: 12,     # Beacon：同 Probe Response
    10: 2,     # Disassociation：原因码
    11: 6,     # Authentication：算法 2 + 序号 2 + 状态 2
    12: 2,     # Deauthentication：原因码
}


def walk(buf):
    """返回 ([Element], truncated)。"""
    els, p, n = [], 0, len(buf)
    while p < n:
        if p + 2 > n:
            return els, True                       # 只剩 1 个字节：连长度都没有
        eid, length = buf[p], buf[p + 1]
        if p + 2 + length > n:
            return els, True                       # 长度超过剩余字节
        data = buf[p + 2:p + 2 + length]
        ext = None
        if eid == ID_EXTENSION and length >= 1:
            ext, data = data[0], data[1:]
        els.append(Element(eid, ext, bytes(data), p))
        p += 2 + length
    return els, False


def ids(els):
    """(普通元素 ID 列表, 扩展元素的扩展 ID 列表)，保持出现顺序。"""
    return ([e.id for e in els if e.id != ID_EXTENSION],
            [e.ext for e in els if e.id == ID_EXTENSION and e.ext is not None])


# ---------------------------------------------------------------------------
# 元素内容解码。每个解码函数收元素的数据，返回 dict；数据不合规（太短等）返回 None。
# decode_all() 对每种元素取第一次出现的那个，返回 {名字: 解码结果}。
# ---------------------------------------------------------------------------
def decode_ssid(d):
    return {"ssid": bytes(d)} if len(d) <= 32 else None          # 长度 0 = 广播 / 隐藏 SSID


def decode_rates(d):
    """支持速率：每字节低 7 位是速率（单位 500 kbps），最高位 = 基本速率（BSS 必须支持）。"""
    return {"rates": list(d), "mbps": [(b & 0x7F) / 2.0 for b in d], "basic": [bool(b & 0x80) for b in d]}


def decode_ds(d):
    return {"channel": d[0]} if len(d) >= 1 else None


def decode_tim(d):
    """TIM：DTIM 计数、DTIM 周期、位图控制（bit0 = 组播有缓存，bit1-7 = 位图偏移，单位 2 字节）、部分虚拟位图。"""
    if len(d) < 4:
        return None
    return {"dtim_count": d[0], "dtim_period": d[1], "multicast": bool(d[2] & 1),
            "offset": d[2] >> 1, "bitmap": bytes(d[3:])}


def decode_country(d):
    """国家：2 个字母 + 环境（空格 = 室内外都行，'O' 室外，'I' 室内），之后是 3 字节一组的三元组。
    第一个字节 < 201 是（起始信道，信道数，最大发射功率 dBm）；>= 201 是（运行扩展 ID，运行类别，覆盖类别）。
    总长为奇数时末尾有 1 字节填充。"""
    if len(d) < 6:
        return None
    triplets, p = [], 3
    while p + 3 <= len(d):
        a, b, c = d[p], d[p + 1], d[p + 2]
        if a >= 201:
            triplets.append({"operating_ext": a, "operating_class": b, "coverage_class": c})
        else:
            triplets.append({"first_channel": a, "num_channels": b, "max_power": c - 256 if c > 127 else c})
        p += 3
    return {"code": bytes(d[:2]).decode("ascii", "replace"), "environment": d[2], "triplets": triplets}


def decode_erp(d):
    """ERP 信息：bit0 有 non-ERP 站点，bit1 使用保护，bit2 Barker 前导码。"""
    if len(d) < 1:
        return None
    b = d[0]
    return {"value": b, "non_erp_present": bool(b & 1), "use_protection": bool(b & 2), "barker_preamble": bool(b & 4)}


def _suite(b):
    """4 字节套件选择器：3 字节 OUI（0x000fac = IEEE 802.11）+ 1 字节类型。返回 (oui, 类型)。"""
    return (b[0] << 16 | b[1] << 8 | b[2], b[3])


# RSN 能力位（16 位小端）
RSN_CAPS = {"preauth": 0, "no_pairwise": 1, "mfpr": 6, "mfpc": 7, "joint_multi_band": 8, "peerkey": 9,
            "ocvc": 12, "extended_key_id": 13}


def decode_rsn(d):
    """RSN 元素（48）：版本、组密码套件、成对密码套件列表、AKM（认证与密钥管理）套件列表、能力、PMKID 列表、
    组管理密码套件。版本之后的字段都是可选的，元素可以在任何一处结束，缺的字段是 None。
    计数超出剩余长度（元素被截断或损坏）时，保留已经读到的字段，"malformed" 置 True，
    出问题的那个列表及之后的字段是 None（tshark 也是这样：报畸形，但已读到的字段照常给出）。
    不足版本号 2 字节时返回 None。"""
    n = len(d)
    if n < 2:
        return None
    out = {"version": d[0] | d[1] << 8, "group": None, "pairwise": None, "akm": None,
           "caps": None, "pmkids": None, "group_mgmt": None, "ptksa_replay": None, "gtksa_replay": None,
           "malformed": False}
    out.update({k: None for k in RSN_CAPS})          # 没有能力字段时这些位也是 None，键总是齐的
    p = 2
    if n - p >= 4:
        out["group"] = _suite(d[p:p + 4])
        p += 4
        for key in ("pairwise", "akm"):
            if n - p < 2:
                return out
            cnt = d[p] | d[p + 1] << 8
            p += 2
            if p + 4 * cnt > n:
                out["malformed"] = True
                return out
            out[key] = [_suite(d[p + 4 * i:p + 4 * i + 4]) for i in range(cnt)]
            p += 4 * cnt
        if n - p >= 2:
            caps = d[p] | d[p + 1] << 8
            out["caps"] = caps
            out.update({k: bool(caps >> bit & 1) for k, bit in RSN_CAPS.items()})
            out["ptksa_replay"] = caps >> 2 & 3
            out["gtksa_replay"] = caps >> 4 & 3
            p += 2
            if n - p >= 2:
                cnt = d[p] | d[p + 1] << 8
                p += 2
                if p + 16 * cnt > n:
                    out["malformed"] = True
                    return out
                out["pmkids"] = [bytes(d[p + 16 * i:p + 16 * i + 16]) for i in range(cnt)]
                p += 16 * cnt
                if n - p >= 4:
                    out["group_mgmt"] = _suite(d[p:p + 4])
    return out


# HT 能力信息（16 位小端）里的单个位
HT_CAP_BITS = {"ldpc": 0, "width40": 1, "greenfield": 4, "short_gi20": 5, "short_gi40": 6, "tx_stbc": 7,
               "delayed_ba": 10, "max_amsdu_7935": 11, "dsss_cck_40": 12, "psmp": 13, "forty_intolerant": 14,
               "lsig_txop": 15}
HT_CAP_LEN, HT_OP_LEN = 26, 22


def decode_ht_cap(d):
    """HT 能力（45，802.11n），26 字节：能力信息 2 + A-MPDU 参数 1 + 支持的 MCS 集 16 + 扩展能力 2 + 波束成形 4 + 天线选择 1。
    MCS 集：位 0-76 是接收支持的 MCS，位 77-86 最高数据速率（Mbps，0 = 不声明），位 96 发送 MCS 集已定义，
    位 97 发送与接收 MCS 集不同，位 98-99 发送最大空间流数 - 1，位 100 允许不均匀调制。长度不是 26 返回 None。"""
    if len(d) != HT_CAP_LEN:
        return None
    caps = d[0] | d[1] << 8
    mcs = bytes(d[3:19])
    out = {"caps": caps, "sm_ps": caps >> 2 & 3, "rx_stbc": caps >> 8 & 3,
           "ampdu_param": d[2], "ampdu_max_exp": d[2] & 3, "ampdu_density": d[2] >> 2 & 7,
           "rx_mcs": mcs[:10], "highest_rate": (mcs[10] | mcs[11] << 8) & 0x3FF,
           "tx_defined": bool(mcs[12] & 1), "tx_rx_unequal": bool(mcs[12] & 2),
           "tx_max_streams": (mcs[12] >> 2 & 3) + 1, "tx_unequal_mod": bool(mcs[12] & 16),
           "ext_caps": d[19] | d[20] << 8, "txbf": d[21] | d[22] << 8 | d[23] << 16 | d[24] << 24, "asel": d[25]}
    out.update({k: bool(caps >> bit & 1) for k, bit in HT_CAP_BITS.items()})
    return out


def decode_ht_op(d):
    """HT 操作（61），22 字节：主信道 1 + 操作信息 5 + 基本 MCS 集 16。
    操作信息 1：位 0-1 次信道偏移（0 无、1 在主信道之上、3 在之下），位 2 任意信道宽度（1 = 可用 40 MHz），位 3 RIFS；
    信息 2（16 位）：位 0-1 HT 保护，位 2 存在非 greenfield 站点，位 4 OBSS 非 HT 站点；
    信息 3（16 位）：位 6 双信标，位 7 双 CTS，位 8 第二信标，位 9 L-SIG TXOP 保护，位 10 PCO 激活，位 11 PCO 阶段。"""
    if len(d) != HT_OP_LEN:
        return None
    i1, i2, i3 = d[1], d[2] | d[3] << 8, d[4] | d[5] << 8
    return {"primary_channel": d[0], "secondary_offset": i1 & 3, "width_any": bool(i1 >> 2 & 1), "rifs": bool(i1 >> 3 & 1),
            "ht_protection": i2 & 3, "nongreenfield_present": bool(i2 >> 2 & 1), "obss_nonht": bool(i2 >> 4 & 1),
            "dual_beacon": bool(i3 >> 6 & 1), "dual_cts": bool(i3 >> 7 & 1), "secondary_beacon": bool(i3 >> 8 & 1),
            "lsig_protection": bool(i3 >> 9 & 1), "pco_active": bool(i3 >> 10 & 1), "pco_phase": bool(i3 >> 11 & 1),
            "basic_mcs": bytes(d[6:22])}


def decode_ext_caps(d):
    """扩展能力（127）：变长位图，每个字节 8 个能力位，位号 = 字节序号 * 8 + 位。bit(n) 查某一位。"""
    return {"octets": list(d)}


def ext_cap_bit(octets, n):
    """扩展能力的第 n 位；元素没有这么长时视为 0。"""
    return bool(n // 8 < len(octets) and octets[n // 8] >> (n % 8) & 1)


def decode_mobility_domain(d):
    """移动域（54，802.11r 快速切换）：移动域 ID 2 字节（小端）+ FT 能力与策略 1 字节
    （bit0 通过 DS 的 FT，bit1 支持资源请求协议）。长度必须是 3。"""
    if len(d) != 3:
        return None
    return {"mdid": d[0] | d[1] << 8, "ft_capab": d[2], "ft_over_ds": bool(d[2] & 1), "resource_request": bool(d[2] >> 1 & 1)}


def decode_bss_max_idle(d):
    """BSS 最大空闲周期（90）：周期 2 字节（小端，单位 1000 TU）+ 选项 1 字节（bit0 要求受保护的保活帧）。长度必须是 3。"""
    if len(d) != 3:
        return None
    return {"period": d[0] | d[1] << 8, "options": d[2], "protected_keepalive": bool(d[2] & 1)}


# RSNXE 的能力位（整个元素按小端拼成一个整数）：bit0-3 是「后面还有几个字节」的长度字段，不是能力
RSNX_BITS = {"protected_twt": 4, "sae_h2e": 5, "sae_pk": 6}


def decode_rsnxe(d):
    """RSN 扩展元素（244，802.11-2020）：变长的能力位图。bit0-3 = 长度字段（扩展字节数 - 1），
    bit5 = SAE hash-to-element（H2E，WPA3 用新方式派生 SAE 密钥），bit6 = SAE-PK，bit4 = 受保护的 TWT。
    其余位保留原样在 "value" 里，不命名。至少 1 字节。"""
    if len(d) < 1:
        return None
    value = int.from_bytes(bytes(d), "little")
    out = {"length_field": d[0] & 0x0F, "octets": list(d), "value": value}
    out.update({k: bool(value >> bit & 1) for k, bit in RSNX_BITS.items()})
    return out


# ---------------------------------------------------------------------------
# 厂商专用元素（221）：3 字节 OUI + 1 字节厂商自定义类型 + 数据。
# OUI 0x0050f2（Microsoft / Wi-Fi 联盟早期）：类型 1 = WPA（WPA1），2 = WMM，4 = WPS。
# ---------------------------------------------------------------------------
OUI_MICROSOFT, OUI_WFA, OUI_IEEE = 0x0050F2, 0x506F9A, 0x000FAC
VENDOR_WPA, VENDOR_WMM, VENDOR_WPS = 1, 2, 4
AC_ORDER = ("be", "bk", "vi", "vo")          # WMM 参数元素里四个访问类别的顺序


def decode_wmm(data):
    """WMM 信息 / 参数元素（OUI 0x0050f2 类型 2）。data 是 OUI 和类型之后的部分：
    子类型 1 字节（0 = 信息元素，1 = 参数元素，2 = TSPEC）、版本 1 字节、QoS 信息 1 字节；
    参数元素之后是保留 1 字节和四个访问类别（BE、BK、VI、VO）各 4 字节：ACI/AIFSN（bit0-3 AIFSN，bit4 ACM，bit5-6 ACI）、
    ECW（低 4 位 ECWmin，高 4 位 ECWmax）、TXOP 限制（16 位小端，单位 32 us）。
    参数元素的 QoS 信息：bit7 U-APSD，bit0-3 参数集计数。"""
    if len(data) < 2:
        return None
    qos = data[2] if len(data) > 2 else None
    out = {"subtype": data[0], "version": data[1], "qos_info": qos, "ac": None, "uapsd": None, "param_set_count": None}
    if data[0] == 1:
        out["uapsd"] = None if qos is None else bool(qos >> 7 & 1)
        out["param_set_count"] = None if qos is None else qos & 0x0F
        if len(data) >= 20:                  # 子类型 1 + 版本 1 + QoS 信息 1 + 保留 1 + 4 个类别各 4 字节
            out["ac"] = {}
            for i, name in enumerate(AC_ORDER):
                b = data[4 + 4 * i:8 + 4 * i]
                out["ac"][name] = {"aci_aifsn": b[0], "aifsn": b[0] & 0x0F, "acm": bool(b[0] >> 4 & 1), "aci": b[0] >> 5 & 3,
                                   "ecw": b[1], "ecw_min": b[1] & 0x0F, "ecw_max": b[1] >> 4, "txop": b[2] | b[3] << 8}
    return out


def decode_wpa(data):
    """WPA（WPA1）厂商元素（OUI 0x0050f2 类型 1）：布局同 RSN（版本、组密码、成对套件、AKM），套件 OUI 是 0x0050f2，
    没有能力字段。data 是类型之后的部分。"""
    n = len(data)
    if n < 2:
        return None
    out = {"version": data[0] | data[1] << 8, "group": None, "pairwise": None, "akm": None, "malformed": False}
    p = 2
    if n - p >= 4:
        out["group"] = _suite(data[p:p + 4])
        p += 4
        for key in ("pairwise", "akm"):
            if n - p < 2:
                return out
            cnt = data[p] | data[p + 1] << 8
            p += 2
            if p + 4 * cnt > n:
                out["malformed"] = True
                return out
            out[key] = [_suite(data[p + 4 * i:p + 4 * i + 4]) for i in range(cnt)]
            p += 4 * cnt
    return out


def decode_vendor(d):
    """通用解码：{"oui", "type", "data"（类型之后的全部）}，再按 OUI / 类型挂上专用解码："wmm" 或 "wpa"。不足 3 字节 OUI 返回 None。"""
    if len(d) < 3:
        return None
    oui = d[0] << 16 | d[1] << 8 | d[2]
    typ = d[3] if len(d) > 3 else None
    out = {"oui": oui, "type": typ, "data": bytes(d[4:]), "wmm": None, "wpa": None}
    if oui == OUI_MICROSOFT:
        if typ == VENDOR_WMM:
            out["wmm"] = decode_wmm(d[4:])
        elif typ == VENDOR_WPA:
            out["wpa"] = decode_wpa(d[4:])
    return out


def vendor_elements(els):
    """所有厂商元素（221）的解码结果，按出现顺序。数据不合规的元素在列表里是 None，位置不变。"""
    return [decode_vendor(e.data) for e in els if e.id == 221]


# 元素 ID -> (名字, 解码函数)
DECODERS = {
    0: ("ssid", decode_ssid),
    1: ("rates", decode_rates),
    3: ("ds", decode_ds),
    5: ("tim", decode_tim),
    7: ("country", decode_country),
    42: ("erp", decode_erp),
    45: ("ht_cap", decode_ht_cap),
    61: ("ht_op", decode_ht_op),
    127: ("ext_caps", decode_ext_caps),
    48: ("rsn", decode_rsn),
    50: ("ext_rates", decode_rates),
    54: ("mdie", decode_mobility_domain),
    90: ("bss_max_idle", decode_bss_max_idle),
    244: ("rsnxe", decode_rsnxe),
}


def decode_all(els):
    """{名字: 解码结果}，每种元素只取第一次出现的；数据不合规的元素不出现在结果里。"""
    out = {}
    for e in els:
        spec = DECODERS.get(e.id)            # 扩展元素的 ID 是 255，不在这张表里
        if spec and spec[0] not in out:
            r = spec[1](e.data)
            if r is not None:
                out[spec[0]] = r
    vs = vendor_elements(els)
    out["vendors"] = vs                      # 全部厂商元素，按出现顺序
    for key in ("wmm", "wpa"):               # WMM / WPA 取第一个
        first = next((v[key] for v in vs if v and v[key]), None)
        if first is not None:
            out[key] = first
    return out
