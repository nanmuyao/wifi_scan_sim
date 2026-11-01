# -*- coding: utf-8 -*-
"""
TCP 流重组：把同一个方向上乱序、重传、重叠的段按序号拼回连续的字节，用来拿到一条连接开头的应用层数据（如 TLS ClientHello）。纯标准库。

只管一个方向的字节流，不做拥塞、窗口、超时：
  - 起点：见过 SYN 就是 SYN 序号 + 1；没见过（抓包从连接中途开始）就取见到的最小序号。
  - 序号是 32 位会回绕：全部换成「相对第一个见到的段」的有符号偏移再比。
  - 重叠 / 重传：内容正常情况下和原来一样；真不一样时以起点靠前的段为准，靠后的段只补它没盖到的字节。
  - 校验和不对的段丢掉（解密或抓包错误产生的垃圾不进流）。
  - 遇到空缺就停，data() 只返回从起点开始连续的那一段；gap 告诉后面还有没有数据。
"""
import logging

log = logging.getLogger(__name__)
SYN, ACK = 0x02, 0x10
MAX_BYTES = 1 << 20                                                    # 每个方向最多存这么多负载字节，防止异常流吃光内存


def _rel(seq, ref):
    """seq 相对 ref 的有符号偏移（模 2^32）。"""
    d = (seq - ref) & 0xFFFFFFFF
    return d - (1 << 32) if d >= 1 << 31 else d


class Direction:
    def __init__(self):
        self.ref = None                                                # 第一个见到的段的序号，所有偏移相对它
        self.syn_at = None                                             # SYN 的偏移（见过 SYN 时）
        self.opener = False                                            # 见过只有 SYN、没有 ACK 的包：这个方向是发起连接的客户端
        self.segs = {}                                                 # 偏移 -> 负载（同一偏移只留先到的、更长的）
        self.stored = 0
        self.packets = 0
        self.first_frame = None
        self.bad = 0                                                   # 因为校验和不对而丢掉的段数
        self.full = False                                              # 存满了 MAX_BYTES：之后的段一律不收（只收一部分会在中间留下假缺口，被当成丢包）

    def add(self, tcp, frame=None):
        if tcp["checksum_ok"] is False:
            self.bad += 1
            return
        if self.ref is None:
            self.ref = tcp["seq"]
            self.first_frame = frame
        self.packets += 1
        off = _rel(tcp["seq"], self.ref)
        if tcp["flags"] & SYN:
            self.syn_at = off if self.syn_at is None else self.syn_at
            self.opener = self.opener or not tcp["flags"] & ACK
            off += 1                                                   # SYN 占一个序号，数据（Fast Open）从下一个开始
        data = tcp["payload"]
        if not data or self.full:
            return
        if self.stored + len(data) > MAX_BYTES:
            self.full = True                                           # 真实抓包里的大下载：存下来的约 1 MiB 之后若再挑小段收，会被当成「缺 N 字节」，其实一个包也没丢
            return
        old = self.segs.get(off)
        if old is None or len(data) > len(old):
            self.stored += len(data) - (len(old) if old else 0)
            self.segs[off] = data

    @property
    def start(self):
        if self.syn_at is not None:
            return self.syn_at + 1
        return min(self.segs) if self.segs else None

    def pieces(self):
        """整个方向按序号排好的内容：[("data", 字节), ("gap", 缺的字节数), ...]，缺口两边的数据不接在一起。重叠部分只取一次。"""
        pos = self.start
        out = []
        if pos is None:
            return out
        for off in sorted(self.segs):
            seg = self.segs[off]
            end = off + len(seg)
            if end <= pos:
                continue                                               # 完全在已有字节之内（重传）
            if off > pos:
                out.append(("gap", off - pos))
                pos = off
            if out and out[-1][0] == "data":
                out[-1] = ("data", out[-1][1] + seg[pos - off:])      # 与已有字节重叠的前部丢掉
            else:
                out.append(("data", seg[pos - off:]))
            pos = end
        return out

    def data(self, limit=None):
        """从起点开始连续的字节（最多 limit 个），遇到缺口就停。起点处就缺的话是空。"""
        first = self.pieces()[:1]
        got = first[0][1] if first and first[0][0] == "data" else b""
        return got if limit is None else got[:limit]

    def missing_bytes(self):
        """缺口一共缺多少字节（不拼接数据，比 pieces() 省内存）。"""
        pos, total = self.start, 0
        if pos is None:
            return 0
        for off in sorted(self.segs):
            end = off + len(self.segs[off])
            if end <= pos:
                continue
            if off > pos:
                total += off - pos
            pos = end
        return total

    @property
    def gap(self):
        """连续部分之后是否还有不连续的段（中间丢了包 / 没抓到）。"""
        return any(k == "gap" for k, _ in self.pieces())


class Flows:
    """按（源 IP, 源端口, 目的 IP, 目的端口）分方向收段。"""

    def __init__(self):
        self.dirs = {}

    def add(self, src, dst, tcp, frame=None):
        key = (src, tcp["sport"], dst, tcp["dport"])
        self.dirs.setdefault(key, Direction()).add(tcp, frame)

    def summary(self):
        """-> {"connections", "directions", "with_data", "with_gap", "missing_bytes", "no_syn", "bad_checksum"}：诊断用的计数。"""
        s = dict.fromkeys(("with_data", "with_gap", "missing_bytes", "no_syn", "bad_checksum"), 0)
        s["connections"], s["directions"] = len(self.pairs()), len(self.dirs)
        for d in self.dirs.values():
            s["bad_checksum"] += d.bad
            if d.segs:
                s["with_data"] += 1
                s["no_syn"] += d.syn_at is None
                m = d.missing_bytes()
                s["with_gap"] += m > 0
                s["missing_bytes"] += m
        return s

    def log_summary(self):
        """TCP 重组的阶段小结：连接数、有缺口的方向和缺的字节数、没抓到 SYN 的方向、因校验和丢掉的段。"""
        if not self.dirs:
            return
        s = self.summary()
        log.info("TCP：%d 条连接（%d 个方向，%d 个方向有数据）", s["connections"], s["directions"], s["with_data"])
        if s["with_gap"]:
            log.warning("TCP：%d 个方向中途缺包，一共缺 %d 字节（抓包机漏抓了包；缺口前面的数据仍可用，缺口之后的 ClientHello / 请求可能读不到）", s["with_gap"], s["missing_bytes"])
        if s["no_syn"]:
            log.info("TCP：%d 个方向没抓到 SYN（抓包从连接中途开始，起点取见到的最小序号）", s["no_syn"])
        if s["bad_checksum"]:
            log.warning("TCP：%d 个段因校验和不对被丢掉（多半是解密不对，或抓包机的校验和卸载造成的假错误）", s["bad_checksum"])

    def pairs(self):
        """每条连接一项：{(a, 端口, b, 端口): {...}}，键取先出现的方向；值含两个方向对象和 client（发 SYN 且没带 ACK 的一方的键；没抓到握手就按先出现的方向）。"""
        out, seen = [], set()
        for key, d in self.dirs.items():
            rev = (key[2], key[3], key[0], key[1])
            if key in seen:
                continue
            seen.update((key, rev))
            r = self.dirs.get(rev)
            client = key
            if r is not None and r.opener and not d.opener:
                client = rev
            out.append({"key": key, "client": client, "fwd": d, "rev": r})
        return out
