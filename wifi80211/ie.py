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


EXT_MULTI_LINK = 107                 # 扩展元素 ID：Multi-Link（802.11be，Wi-Fi 7）
ML_TYPES = {0: "basic", 1: "probe_request", 2: "reconfiguration", 3: "tdls", 4: "priority_access"}
ML_SUBELT_PER_STA, ML_SUBELT_FRAGMENT = 0, 254
# 每站点配置里，STA 信息之后、元素之前，是外层帧自己的固定字段（外层帧子类型 -> 字节数）：
# 关联请求 / 重关联请求：能力 2；关联响应 / 重关联响应：能力 2 + 状态码 2；信标 / 探测响应：能力 2
ML_PROFILE_FIXED = {0: 2, 1: 4, 2: 2, 3: 4, 5: 2, 8: 2}


def decode_multi_link(d, fixed=0):
    """Multi-Link 元素（扩展 ID 107）。d 是扩展 ID 之后的数据。

    Multi-Link 控制 2 字节（小端）：bit0-2 类型（0 basic、1 probe request、2 reconfiguration、3 TDLS、4 priority access），
    其余位是「公共信息里有哪些可选字段」的存在位图；
    公共信息：第一个字节是它自己的长度（含这个字节），所以不看存在位图也能找到后面的链路信息；
    basic 类型的公共信息里紧跟着 MLD MAC 地址（6 字节），存在位图 bit4 置位时再跟链路 ID（1 字节）；
    链路信息：若干子元素（ID 1 字节、长度 1 字节、数据），子元素 0 = 每站点配置（Per-STA Profile）：
        STA 控制 2 字节（bit0-3 链路 ID，bit4 完整配置，bit5 有 MAC 地址，bit6 有信标间隔，bit7 有 TSF 偏移，
        bit8 有 DTIM 信息，bit9 有 NSTR 链路对，bit10 NSTR 位图大小，bit11 有 BSS 参数变化计数）
        + STA 信息（第一个字节是它自己的长度，含这个字节；bit5 置位时紧跟 6 字节 MAC 地址）
        + STA 配置（其余字节，是一串普通信息元素）。
    元素在草案和正式标准之间改过位图的细节，这里只依赖各部分自带的长度字节，不依赖可选字段的具体顺序（MAC 地址除外）。

    fixed 是每站点配置里 STA 信息之后、元素之前的固定字段字节数（见 ML_PROFILE_FIXED，由外层帧的子类型决定），
    这些字节放在每个站点的 "fixed_fields" 里。

    返回 dict；少于 3 字节返回 None。长度字节超出数据范围时 "malformed" 为 True，已读到的保留。"""
    if len(d) < 3:
        return None
    control = d[0] | d[1] << 8
    typ = control & 7
    out = {"control": control, "type": typ, "type_name": ML_TYPES.get(typ), "common_len": d[2], "mld_mac": None,
           "link_id": None, "stas": [], "malformed": False}
    if d[2] < 1 or 2 + d[2] > len(d):
        out["malformed"] = True
        return out
    common = d[2:2 + d[2]]
    if typ == 0 and len(common) >= 7:
        out["mld_mac"] = mac_str(common[1:7])
        if control >> 4 & 1 and len(common) >= 8:
            out["link_id"] = common[7] & 0x0F
    p = 2 + d[2]
    while p + 2 <= len(d):
        sid, slen = d[p], d[p + 1]
        if p + 2 + slen > len(d):
            out["malformed"] = True
            break
        data = d[p + 2:p + 2 + slen]
        p += 2 + slen
        if sid != ML_SUBELT_PER_STA:
            continue
        if len(data) < 3 or len(data) < 2 + data[2]:
            out["malformed"] = True
            continue
        ctl = data[0] | data[1] << 8
        sta_info = data[2:2 + data[2]]
        start = 2 + data[2]
        elements, trunc = walk(data[start + fixed:])
        out["stas"].append({"control": ctl, "link_id": ctl & 0x0F, "complete": bool(ctl >> 4 & 1),
                            "mac": mac_str(sta_info[1:7]) if ctl >> 5 & 1 and len(sta_info) >= 7 else None,
                            "info_len": data[2], "fixed_fields": bytes(data[start:start + fixed]),
                            "elements": elements, "truncated": trunc})
    return out


def mac_str(b):
    return ":".join("%02x" % x for x in b)


def flatten(els, fixed=0):
    """把 Multi-Link 元素里每站点配置的嵌套元素展开，插在 Multi-Link 元素之后（tshark 列出元素编号的顺序）。
    其它元素原样。嵌套里没有 Multi-Link，所以只展开一层。fixed 见 decode_multi_link。"""
    out = []
    for e in els:
        out.append(e)
        if e.id == ID_EXTENSION and e.ext == EXT_MULTI_LINK:
            ml = decode_multi_link(e.data, fixed)
            for sta in (ml["stas"] if ml else ()):
                out.extend(sta["elements"])
    return out


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


def decode_mesh_id(d):
    """Mesh ID（114，802.11s）：网状网名字，0-32 字节（0 字节 = 通配）。超过 32 字节返回 None。"""
    if len(d) > 32:
        return None
    return {"id": bytes(d)}


def decode_mesh_config(d):
    """Mesh Configuration（113）：7 字节——主动路径选择协议、路径度量、拥塞控制、同步方法、认证协议、形成信息、能力。
    形成信息：bit0 连到网关、bit1-6 对等连接数、bit7 连到认证服务器；
    能力：bit0 接受新的对等连接、1 MCCA 支持、2 MCCA 启用、3 转发、4 MBCA 启用、5 TBTT 调整、6 省电级别（bit7 保留）。长度必须是 7。"""
    if len(d) != 7:
        return None
    f, c = d[5], d[6]
    return {"path_protocol": d[0], "path_metric": d[1], "congestion": d[2], "sync": d[3], "auth": d[4], "formation": f, "gate": bool(f & 1), "num_peers": f >> 1 & 0x3F, "as_connected": bool(f >> 7 & 1),
            "cap": c, "accepting": bool(c & 1), "mcca_support": bool(c >> 1 & 1), "mcca_enabled": bool(c >> 2 & 1), "forwarding": bool(c >> 3 & 1), "mbca": bool(c >> 4 & 1),
            "tbtt_adjusting": bool(c >> 5 & 1), "power_save": bool(c >> 6 & 1)}


FT_MIC_LENGTHS = {0: 16, 1: 24, 2: 32}           # MIC Control 的 MIC Length 子字段 -> MIC 字节数
FT_SUBELEMS = {1: "r1kh_id", 2: "gtk", 3: "r0kh_id", 4: "igtk"}


def decode_ft(d):
    """快速切换元素（55，FTE）：MIC Control(2) ‖ MIC(16 / 24 / 32) ‖ ANonce(32) ‖ SNonce(32) ‖ 子元素(ID, 长度, 数据)…
    MIC Control：字节 0 的 bit0 = RSNXE 已用，bit1-3 = MIC 长度编码（0 = 16，1 = 24，2 = 32），字节 1 = 被 MIC 覆盖的元素个数。
    子元素：1 = R1KH-ID（6 字节），2 = GTK，3 = R0KH-ID（1-48 字节），4 = IGTK。其余放在 subelements 里原样给出。
    MIC 长度编码不认识、数据不够长、子元素长度越界，返回 None。"""
    if len(d) < 2:
        return None
    code = d[0] >> 1 & 7
    mic_len = FT_MIC_LENGTHS.get(code)
    if mic_len is None or len(d) < 2 + mic_len + 64:
        return None
    p = 2 + mic_len
    out = {"mic_control": d[0] | d[1] << 8, "rsnxe_used": bool(d[0] & 1), "mic_length": mic_len, "element_count": d[1],
           "mic": bytes(d[2:p]), "anonce": bytes(d[p:p + 32]), "snonce": bytes(d[p + 32:p + 64]), "subelements": []}
    p += 64
    while p < len(d):
        if p + 2 > len(d) or p + 2 + d[p + 1] > len(d):
            return None
        sid, n = d[p], d[p + 1]
        body = bytes(d[p + 2:p + 2 + n])
        out["subelements"].append((sid, body))
        if FT_SUBELEMS.get(sid) and FT_SUBELEMS[sid] not in out:
            out[FT_SUBELEMS[sid]] = body
        p += 2 + n
    out.setdefault("r1kh_id", None)
    out.setdefault("r0kh_id", None)
    return out


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
# HE（802.11ax，Wi-Fi 6）扩展元素：能力 35、操作 36。
# 这里解码原始值、MCS / NSS 表和操作元素的主要字段；MAC 能力（48 位）和 PHY 能力（88 位）里的单个位没有逐个命名。
# ---------------------------------------------------------------------------
EXT_HE_CAP, EXT_HE_OP = 35, 36
HE_MAC_LEN, HE_PHY_LEN = 6, 11
# PHY 能力第 0 字节的信道宽度集：bit1 2.4G 40MHz、bit2 5G 40/80MHz、bit3 5G 160MHz、bit4 5G 160/80+80MHz、bit5/6 242 音 RU
HE_PHY0_160, HE_PHY0_80P80 = 0x08, 0x10


def he_mcs_map(v):
    """HE-MCS 与 NSS 表（16 位）：每个空间流数（1-8）2 位。0 = MCS 0-7，1 = MCS 0-9，2 = MCS 0-11，3 = 不支持。"""
    return [v >> (2 * i) & 3 for i in range(8)]


def decode_he_cap(d):
    """HE 能力（扩展元素 35，数据在扩展 ID 之后）：MAC 能力 6 字节（小端的 48 位整数）+ PHY 能力 11 字节
    + 接收 / 发送 HE-MCS 表（80MHz 及以下，各 2 字节）；PHY 能力第 0 字节置位 160MHz 位时再跟 160MHz 的一对表，
    置位 160/80+80MHz 位时再跟 80+80MHz 的一对表（各 4 字节）；其余是 PPE 门限（原样放在 "ppe" 里，不解）。
    不足 21 字节返回 None。"""
    if len(d) < HE_MAC_LEN + HE_PHY_LEN + 4:
        return None
    out = {"mac_caps": int.from_bytes(d[:6], "little"), "phy_caps": bytes(d[6:17]), "phy0": d[6]}
    p = 17
    out["rx_lte80"], out["tx_lte80"] = d[p] | d[p + 1] << 8, d[p + 2] | d[p + 3] << 8
    p += 4
    out["rx_160"] = out["tx_160"] = out["rx_80p80"] = out["tx_80p80"] = None
    for key, bit in (("160", HE_PHY0_160), ("80p80", HE_PHY0_80P80)):
        if d[6] & bit and p + 4 <= len(d):
            out["rx_" + key], out["tx_" + key] = d[p] | d[p + 1] << 8, d[p + 2] | d[p + 3] << 8
            p += 4
    out["ppe"] = bytes(d[p:])
    return out


def decode_he_op(d):
    """HE 操作（扩展元素 36）：参数 3 字节（小端 24 位：bit0-2 默认 PE 时长，bit3 要求 TWT，bit4-13 TXOP 时长 RTS 门限，
    bit14 有 VHT 操作信息，bit15 共址 BSS，bit16 ER SU 禁用，bit17 有 6GHz 操作信息）+ BSS 颜色信息 1 字节
    （bit0-5 颜色，bit6 部分颜色，bit7 颜色禁用）+ 基本 HE-MCS 与 NSS 表 2 字节；之后按参数位依次可选：
    VHT 操作信息 3 字节、最大共址 BSSID 指示 1 字节、6GHz 操作信息 5 字节。不足 6 字节返回 None。
    BSS 颜色字段没有 tshark 字段可对照，按标准解码。"""
    if len(d) < 6:
        return None
    params = d[0] | d[1] << 8 | d[2] << 16
    out = {"params": params, "default_pe_duration": params & 7, "twt_required": bool(params >> 3 & 1),
           "txop_rts_threshold": params >> 4 & 0x3FF, "vht_op_present": bool(params >> 14 & 1),
           "co_hosted_bss": bool(params >> 15 & 1), "er_su_disable": bool(params >> 16 & 1),
           "six_ghz_present": bool(params >> 17 & 1),
           "bss_color_info": d[3], "bss_color": d[3] & 0x3F, "partial_bss_color": bool(d[3] >> 6 & 1),
           "bss_color_disabled": bool(d[3] >> 7 & 1), "basic_mcs_nss": d[4] | d[5] << 8,
           "vht_op": None, "max_cohosted_bssid": None, "six_ghz": None}
    p = 6
    if out["vht_op_present"] and p + 3 <= len(d):
        out["vht_op"] = {"channel_width": d[p], "seg0": d[p + 1], "seg1": d[p + 2]}
        p += 3
    if out["co_hosted_bss"] and p + 1 <= len(d):
        out["max_cohosted_bssid"] = d[p]
        p += 1
    if out["six_ghz_present"] and p + 5 <= len(d):
        out["six_ghz"] = {"primary_channel": d[p], "control": d[p + 1], "seg0": d[p + 2], "seg1": d[p + 3], "min_rate": d[p + 4]}
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
    55: ("fte", decode_ft),
    113: ("mesh_config", decode_mesh_config),
    114: ("mesh_id", decode_mesh_id),
    90: ("bss_max_idle", decode_bss_max_idle),
    244: ("rsnxe", decode_rsnxe),
}


EXT_OWE_DH = 32                      # 扩展元素 ID：OWE 的 Diffie-Hellman 参数


def decode_owe_dh(d):
    """OWE 的 DH 参数（扩展元素 32，关联请求 / 响应里）：椭圆曲线组(2，小端) ‖ 公钥（只有 x 坐标，19 / 20 / 21 组分别 32 / 48 / 66 字节）。
    长度不足 2 字节返回 None；公钥长度对不对由调用方按组检查。"""
    if len(d) < 2:
        return None
    return {"group": d[0] | d[1] << 8, "public": bytes(d[2:])}


EXT_DECODERS = {EXT_HE_CAP: ("he_cap", decode_he_cap), EXT_HE_OP: ("he_op", decode_he_op), EXT_OWE_DH: ("owe_dh", decode_owe_dh)}


def decode_all(els):
    """{名字: 解码结果}，每种元素只取第一次出现的；数据不合规的元素不出现在结果里。"""
    out = {}
    for e in els:
        spec = EXT_DECODERS.get(e.ext)          # 普通元素的 ext 是 None，查不到
        if spec and spec[0] not in out:
            r = spec[1](e.data)
            if r is not None:
                out[spec[0]] = r
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
