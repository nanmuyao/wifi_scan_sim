# -*- coding: utf-8 -*-
"""
抓包质量：监听网卡抓空口的第一个问题不是「看到了什么」，而是「这一次抓得好不好」。每台设备给出：

  受保护的数据帧有多少、解开多少；握手状态（没有 verified 的握手就给出下一步：让它重连一次）；
  由 802.11 序号缺口估计的丢帧率（我们没听到的 MSDU 占应该听到的多少）；重传帧占比。

丢帧估计（序号计数器）
  每个发送方给它发出的帧编一个 12 位的序号（0..4095 回绕），帧之间序号 +1；两个相邻听到的帧序号差 d > 1，中间有 d - 1 个我们没听到。
  - 一个计数器管哪些帧：非 QoS 数据帧和管理帧共用「发送方」一个计数器；QoS 数据帧每个 TID 一个，单播的再按接收方分开（见下）；组播 / 广播的 QoS 帧按（发送方, TID）。
  - 重传：序号和上一个相同（差 0）的不算新帧，也不算缺口（重传、分片都是这样）；重传位本身只用来算「重传帧占比」。
  - 回绕按模 4096；差超过 2048 当作乱序 / 迟到的旧帧（不更新基准）；连续 RESYNC_AFTER 个都往回走说明发送方的计数器重置了，重新对齐。
  - 缺口上限 MAX_LOSS_GAP = 64：一次缺 64 个以内算丢帧；更大的当作「断档」（我们这边停听了、网卡掉线、设备离开），单独计数，不进丢帧率，免得一处断档把整个估计冲掉。
    依据（24 个样本，不重传的前向缺口）：wpa-Induction 与 wpa3-sae 里所有缺口都不超过 57，90% 不超过 4，缺口间隔约 0.1 秒（信标）；wpa-test-decode 的 637 个缺口里有 561 个大于 64，
    中位数 830，间隔约 1 秒，是稀疏抓包 / 断档。64 是取的，不是推出来的：它只决定一个缺口落进「丢帧」还是「断档」。
  校验和（FCS）没通过的帧不参与：它们的头是坏的，序号是乱的（wpa-Induction 里 7 个这样的帧，子类型都是保留值，tshark 也认不出序号）；只数个数（bad_fcs），监听网卡丢给我们多少坏帧本身就是质量指标。
  丢帧率 = 缺口总数 / (听到的 + 缺口总数)；设备级的只算和这台设备有关的计数器（它发的、发给它的单播、它的管理帧），AP 的信标、组播不归任何设备，只进总计。

QoS 单播的计数器按什么分？（样本不能回答，依据是标准和实现，加上自检）
  24 个样本里没有一个 AP 持续向多台设备发 QoS 数据的抓包（有多个接收方的 (发送方, TID) 只有 3 个、帧数不超过几个），两种分法在样本上结果一样，样本给不出证据。
  标准里 QoS 数据的序号空间是每个（接收方, TID）一个（Block Ack 也是按这个单位），Linux 的 mac80211 也是每个站点每个 TID 一个计数器，所以默认按（发送方, 接收方, TID）。
  但不是所有 AP 都这样：有的 AP 给所有设备共用一个 TID 计数器。分错的后果相反（分细了：每个设备的序号里夹着别人的帧，全是假缺口；分粗了：别人的计数器交错，序号乱跳）。
  所以对「同一个（发送方, TID）发给不止一个接收方」的组，两种分法都算，选序号更连贯的那种（相邻差是 0 或 1 的占比高的）；选的结果写进日志。选了粗的一种时，缺口只进总计，不归设备。
  自检的依据在 tests/test_health.py：合成了两种 AP，选对了。

数据都是线性扫描，一遍完成；不调用 diagnose（那要再解密一遍）。
"""
import collections
import logging

from . import activity

log = logging.getLogger(__name__)

MAX_LOSS_GAP = 64
RESYNC_AFTER = 8
LOSS_WARN = 0.05                 # 丢帧率超过这个就提醒（初定，拿到真实数据后再调，见 docs/路线B实施方案.md §4）
RETRY_WARN = 0.30                # 重传帧占比超过这个就提醒（同上，是初定）
MOD = 4096

ACTIONS = {
    "no_handshake": "没有抓到这台设备的握手：让它断开重连一次（关再开 WiFi），再抓。",
    "only_m1": "只抓到握手的第一个报文：设备的回复没被听到；让它重连一次，并确认监听的信道和 AP 一致。",
    "m2_without_m1": "只抓到握手的 M2：让它重连一次，把握手抓全。",
    "mic_mismatch": "握手的 MIC 对不上：核对口令和 SSID（大小写要一致）。",
    "no_candidates": "握手里没有可用的候选密钥：见日志里的原因。",
    "unsupported": "这台设备的认证方式或密码套件不支持（例如 WPA3-SAE 被动抓包解不开）。",
    "incomplete": "握手报文不全：让它重连一次，把握手抓全。",
}


class _Seq:
    """一个序号计数器上的统计。"""
    __slots__ = ("last", "seen", "missing", "outages", "outage_frames", "dup", "reordered", "run", "steps", "coherent", "frames", "retries")

    def __init__(self):
        self.last = None
        self.seen = self.missing = self.outages = self.outage_frames = self.dup = self.reordered = self.run = self.steps = self.coherent = self.frames = self.retries = 0

    def add(self, sn, retry):
        self.frames += 1
        self.retries += retry
        if self.last is None:
            self.last, self.seen = sn, 1
            return
        d = (sn - self.last) % MOD
        self.steps += 1
        if d <= 1:
            self.coherent += 1
        if d == 0:                                    # 重传 / 分片：和上一个同一个序号
            self.dup += 1
            self.run = 0
            return
        if d > MOD // 2:                              # 往回走：乱序、迟到的旧帧，或者发送方的计数器重置了
            self.reordered += 1
            self.run += 1
            if self.run >= RESYNC_AFTER:
                self.last, self.run = sn, 0
                self.seen += 1
            return
        self.run = 0
        self.seen += 1
        gap = d - 1
        if gap > MAX_LOSS_GAP:
            self.outages += 1
            self.outage_frames += gap
        else:
            self.missing += gap
        self.last = sn

    def as_dict(self):
        return {"frames": self.frames, "seen": self.seen, "missing": self.missing, "outages": self.outages, "outage_frames": self.outage_frames,
                "dup": self.dup, "reordered": self.reordered, "retries": self.retries}


def _group(mac):
    return bool(int(mac[:2], 16) & 1)


def _station_of_frame(h):
    """这个帧「属于」哪台设备：数据帧用 activity.station_of；管理帧取不是 BSSID 的那个单播地址。AP 自己发的信标、组播不归任何设备。"""
    if h["type"] == 2:
        return activity.station_of(h)
    bssid, ta, ra = h["bssid"], h["addr2"], h["addr1"]
    if ta != bssid and not _group(ta):
        return ta
    if ra != bssid and not _group(ra):
        return ra
    return None


def _keys(h):
    """-> (计数器键 "ra" 分法, "tid" 分法)。非 QoS 数据帧和管理帧只有一个键（两种分法一样）。"""
    ta = h["addr2"]
    q = h["qos"]
    if h["type"] == 2 and q is not None:
        tid = q["tid"]
        if _group(h["addr1"]):
            k = ("g", ta, tid)
            return k, k
        return ("q", ta, h["addr1"], tid), ("q", ta, None, tid)
    k = ("t", ta)
    return k, k


def sequence(frames, by="auto"):
    """遍历帧（frames.iter_frames 的结果），返回 {"counters": {键: 统计字典}, "station": {键: 设备 MAC 或 None}, "choice": {(发送方, TID): "ra" / "tid"}}。
    by："ra"（QoS 单播按接收方分）、"tid"（只按发送方和 TID）、"auto"（有多个接收方的组按序号连贯程度选，其余用 "ra"）。
    键的形状：("t", 发送方) 非 QoS 数据和管理帧；("q", 发送方, 接收方 / None, TID)；("g", 发送方, TID) 组播的 QoS。"""
    ra_c, tid_c = {}, {}
    st = {}
    bad_fcs = 0
    groups = collections.defaultdict(set)                        # (发送方, TID) -> 接收方集合
    for f in frames:
        h = f.h
        if h["type"] not in (0, 2):
            continue
        if f.fcs_ok is False:
            bad_fcs += 1
            continue
        k_ra, k_tid = _keys(h)
        sn, retry = h["seq_num"], h["retry"]
        c = ra_c.get(k_ra)
        if c is None:
            c = ra_c[k_ra] = _Seq()
            st[k_ra] = _station_of_frame(h) if k_ra[0] != "t" or k_ra[1] != h["bssid"] else None
        c.add(sn, retry)
        if k_ra[0] == "q":
            groups[(k_ra[1], k_ra[3])].add(k_ra[2])
            t = tid_c.get(k_tid)
            if t is None:
                t = tid_c[k_tid] = _Seq()
            t.add(sn, retry)
    choice = {}
    for g, ras in groups.items():
        if by == "tid" or (by == "auto" and len(ras) > 1):
            ra_steps = sum(c.steps for k, c in ra_c.items() if k[0] == "q" and (k[1], k[3]) == g)
            ra_coh = sum(c.coherent for k, c in ra_c.items() if k[0] == "q" and (k[1], k[3]) == g)
            t = tid_c[("q", g[0], None, g[1])]
            if by == "tid" or (t.steps and (not ra_steps or t.coherent / t.steps > ra_coh / ra_steps)):
                choice[g] = "tid"
                continue
        choice[g] = "ra"
    counters, station = {}, {}
    for k, c in ra_c.items():
        if k[0] == "q" and choice[(k[1], k[3])] == "tid":
            continue
        counters[k], station[k] = c.as_dict(), st[k]
    for g, v in choice.items():
        if v == "tid":
            k = ("q", g[0], None, g[1])
            counters[k], station[k] = tid_c[k].as_dict(), None                # 分粗了：谁的序号都不归，只进总计
    for g, ras in groups.items():
        if len(ras) > 1:
            log.debug("发送方 %s TID %d 发给 %d 个接收方，序号计数器按「%s」分", g[0], g[1], len(ras), "接收方" if choice[g] == "ra" else "只按发送方和 TID")
    return {"counters": counters, "station": station, "choice": choice, "bad_fcs": bad_fcs}


def _sum(cs):
    t = {"frames": 0, "seen": 0, "missing": 0, "outages": 0, "outage_frames": 0, "dup": 0, "reordered": 0, "retries": 0}
    for c in cs:
        for k in t:
            t[k] += c[k]
    miss, seen = t["missing"], t["seen"]
    t["loss"] = miss / (seen + miss) if seen + miss else None
    t["retry_rate"] = t["retries"] / t["frames"] if t["frames"] else None
    return t


def handshake_state(sta, pairs):
    """pairs：handshake.track 的 stats["pairs"]。这台设备的握手状态码：有任何一对 verified 就是 verified；没有任何一对是 "no_handshake"；其余取第一对的状态。"""
    mine = [p for p in pairs if p["sta"] == sta]
    if not mine:
        return "no_handshake"
    if any(p["state"] == "verified" for p in mine):
        return "verified"
    return mine[0]["state"]


def build(frames, decrypted, pairs=None):
    """-> {"overall": {...}, "stations": [{"mac", "protected", "decrypted", "handshake", "seq": {...}, "notes": [...]}], "choice": ...}。
    frames：iter_frames 的结果；decrypted：pipeline.decrypt_capture 的返回值（帧号 -> ...）；pairs：握手的 stats["pairs"]（没给就不报握手状态）。
    stations 只含有受保护数据帧的设备，按受保护帧数降序。"""
    protected, ok = collections.Counter(), collections.Counter()
    for f in frames:
        h = f.h
        if h["type"] == 2 and h["protected"]:
            s = activity.station_of(h)
            if s is not None:
                protected[s] += 1
                if f.n in decrypted:
                    ok[s] += 1
    seq = sequence(frames)
    by_sta = collections.defaultdict(list)
    for k, c in seq["counters"].items():
        s = seq["station"][k]
        if s is not None:
            by_sta[s].append(c)
    stations = []
    for mac, n in sorted(protected.items(), key=lambda kv: (-kv[1], kv[0])):
        sq = _sum(by_sta.get(mac, []))
        hsx = handshake_state(mac, pairs) if pairs is not None else None
        notes = []
        if n > ok[mac]:
            if hsx is not None and hsx != "verified":
                notes.append(ACTIONS.get(hsx, ACTIONS["incomplete"]))
            elif hsx == "verified":
                notes.append("握手验证通过，仍有 %d 个帧没解开：握手之前的帧解不开属正常；其余多半是中途重新握手换了密钥，或帧在传输中损坏。" % (n - ok[mac]))
        if sq["loss"] is not None and sq["loss"] > LOSS_WARN:
            notes.append("丢帧估计 %.1f%%，高于 %d%%。可能的原因（要实测才能确定）：距离太远或有遮挡；网卡的天线路数少于 AP 用的空间流数（例如 1×1 的卡听 2×2 的 AP）；虚拟机的 USB 直通丢包。" % (100 * sq["loss"], round(100 * LOSS_WARN)))
        if sq["retry_rate"] is not None and sq["retry_rate"] > RETRY_WARN:
            notes.append("重传帧占 %.0f%%：链路质量差。" % (100 * sq["retry_rate"]))
        if sq["outages"]:
            notes.append("序号有 %d 处断档（一次缺 %d 个以上，共约 %d 个）：中途停听、网卡掉线或设备离开过。" % (sq["outages"], MAX_LOSS_GAP, sq["outage_frames"]))
        stations.append({"mac": mac, "protected": n, "decrypted": ok[mac], "handshake": hsx, "seq": sq, "notes": notes})
    overall = _sum(seq["counters"].values())
    overall["bad_fcs"] = seq["bad_fcs"]
    return {"overall": overall, "stations": stations, "choice": {"%s/%d" % g: v for g, v in seq["choice"].items()}}


def log_summary(health):
    """每台设备一行 INFO；总计一行。MAC 由日志的 RedactFilter 统一换成标记，不用在这里处理。"""
    o = health["overall"]
    log.info("抓包质量（总计）：序号计数器听到 %d 个、缺口 %d 个，丢帧估计 %s；断档 %d 处；重传帧 %s；校验和不对的帧 %d 个",
             o["seen"], o["missing"], "-" if o["loss"] is None else "%.1f%%" % (100 * o["loss"]), o["outages"], "-" if o["retry_rate"] is None else "%.0f%%" % (100 * o["retry_rate"]), o["bad_fcs"])
    for s in health["stations"]:
        q = s["seq"]
        log.info("抓包质量：设备 %s 受保护 %d 个、解开 %d 个，握手 %s，丢帧估计 %s，断档 %d 处，重传 %s",
                 s["mac"], s["protected"], s["decrypted"], s["handshake"] or "-", "-" if q["loss"] is None else "%.1f%%" % (100 * q["loss"]), q["outages"],
                 "-" if q["retry_rate"] is None else "%.0f%%" % (100 * q["retry_rate"]))
        for n in s["notes"]:
            log.warning("抓包质量：设备 %s：%s", s["mac"], n)
