# -*- coding: utf-8 -*-
"""
设备在访问什么：把解密后的明文（pipeline.decrypt_capture 的结果）逐帧读成事件——设备查了哪个域名（DNS）、连了哪个服务器的哪个域名（TLS 的 SNI）——
再按设备（MAC）汇总成访问时间线。纯标准库，只做被动识别，不碰 TLS 内容。

事件：{"ts", "station", "kind": "dns" | "mdns" | "tls" | "quic" | "http" | "dot", "transport"（dns / mdns：udp 或 tcp）, "name", "server"（kind 为 tls 时是服务器 IP）, "port", "qtype"（dns）, "via"（tls / quic / http / dot）, "method"、"path"（http）, "frame"}。
一条 TLS 连接只在两个方向之一拿到完整 ClientHello（谁发出它谁就是客户端）时产生事件；ClientHello 缺了开头或被缺口截断（还没读到 SNI）的连接没有事件，
名字没有 SNI 时用这台设备先前 DNS 应答里的 IP -> 域名 补一个（kind 仍是 tls，字段 via 为 "dns"，SNI 的是 "sni"）。
还读三种明文：TCP 上的 HTTP/1.x 请求（kind=http，名字是 Host 头，via 为 "host"，没有 Host 才用 DNS 应答补，每个请求一个事件）、
TCP 53 端口上的 DNS（kind=dns，transport=tcp；它的应答也进 IP -> 域名表）、853 端口上的 TLS（DNS over TLS，kind=dot，只记连了哪台服务器：名字取 SNI，没有就用服务器 IP，via 为 "ip"）。
"""
import collections
import logging
import re

from . import dns as dns80211
from . import net
from . import quic
from . import tcpstream
from . import tls as tls80211

log = logging.getLogger(__name__)
MDNS_PORT = 5353
QUIC_MIN = 1200
DOT_PORT = 853
HTTP_WINDOW = 64 * 1024                                              # 一条连接的客户端方向只看开头这么多字节里的请求
HTTP_PATH_MAX = 200
HTTP_REQUEST = re.compile(rb"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) (\S+) HTTP/\d\.\d$")


def http_requests(data):
    """客户端方向的字节里依次出现的 HTTP/1.x 请求：[{"method", "path", "host"（没有 Host 头是 None）}]。
    只认头部完整（有 \\r\\n\\r\\n）的请求；Content-Length 给出的请求体跳过，跳不过去（体没到齐 / 后面不是请求行）就停。只看开头 HTTP_WINDOW 字节；
    传入的是一段连续的字节（缺口两侧要分开传）。"""
    data, pos, out = data[:HTTP_WINDOW], 0, []
    while pos < len(data):
        end = data.find(b"\r\n\r\n", pos)
        if end < 0:
            break
        lines = data[pos:end].split(b"\r\n")
        m = HTTP_REQUEST.match(lines[0])
        if m is None:
            break
        host, clen = None, 0
        for ln in lines[1:]:
            name, _, val = ln.partition(b":")
            name = name.strip().lower()
            if name == b"host" and host is None:
                host = _host_name(val.strip().decode("latin-1"))
            elif name == b"content-length" and val.strip().isdigit():
                clen = int(val.strip())
        out.append({"method": m.group(1).decode(), "path": m.group(2).decode("latin-1")[:HTTP_PATH_MAX], "host": host})
        pos = end + 4 + clen
    return out


def _host_name(v):
    """Host 头的值 -> 小写域名 / IP，去掉端口（[IPv6]:端口 也处理）；空值是 None。"""
    v = v.lower()
    if v.startswith("["):
        v = v[1:v.find("]")] if "]" in v else v[1:]
    elif v.count(":") == 1:
        h, _, port = v.partition(":")
        v = h if port.isdigit() or port == "" else v
    return v or None


def dns_over_tcp(data):
    """TCP 上的 DNS（每条消息前有 2 字节长度）-> 解出的消息列表；最后一条没到齐就丢掉，解不出的消息跳过但长度照算。"""
    out, pos = [], 0
    while len(data) - pos >= 2:
        n = int.from_bytes(data[pos:pos + 2], "big")
        if len(data) - pos - 2 < n:
            break
        q = dns80211.parse(data[pos + 2:pos + 2 + n])
        if q is not None:
            out.append(q)
        pos += 2 + n
    return out


def station_of(h):
    """数据帧里「不是接入点」的那个设备：发往 AP 的取源地址，AP 发来的取目的地址；WDS / IBSS 不确定，返回 None。
    AP 发出的组播 / 广播帧（目的地址是组地址）不归任何设备：多半是 AP 把某台设备发来的组播转发出去的副本，那台设备自己的那一帧已经算过了。"""
    if h["to_ds"] and not h["from_ds"]:
        return h["sa"]
    if h["from_ds"] and not h["to_ds"]:
        return None if int(h["da"][:2], 16) & 1 else h["da"]
    return None


class Collector:
    """逐个 MSDU 喂进来（feed），最后 finish() 得到事件；同时按流累计包数和字节（flow_stats），记下每条连接认出的名字（names）和 DNS 应答里的 IP -> 域名（answers），给 traffic 用。
    802.11 的 build 和明文以太网的 plain.analyze 共用它：区别只是「这个 MSDU 属于哪台设备、是不是设备发出的」怎么定。"""

    def __init__(self):
        self.flows = tcpstream.Flows()
        self.owner, self.first_ts = {}, {}                           # 连接方向 -> 设备 MAC / 第一个段的时间
        self.events = []
        self.udp = {}                                                # (设备, 源 IP, 源端口, 目的 IP, 目的端口) -> {"ts", "frame", "datagrams": [...]}：可能是 QUIC Initial 的数据报
        self.answers = {}                                            # (设备, 服务器 IP) -> 设备查过的域名（最近一次）
        self.flow_stats = {}                                         # (设备, 协议, 设备 IP, 设备端口, 对端 IP, 对端端口) -> 包数 / L3 字节（上下行）/ 首末时间
        self.names = {}                                              # (设备, 协议, 客户端 IP, 客户端端口, 服务器 IP, 服务器端口) -> (名字, 来源 via, 事件种类)
        self.stats = collections.Counter()                           # 诊断用的计数（finish 时写进日志）：msdu / unparsed / no_device / bad_checksum / fragment / dns_malformed
        self.stacks = collections.Counter()                          # 协议层组合 -> 个数
        self.excluded = collections.Counter()                        # 不归任何设备的原因 -> 个数（analyze 填）

    def _count(self, ts, st, ip, proto, sport, dport, up):
        length = ip["total_length"] if "total_length" in ip else 40 + ip["payload_length"]              # IPv4 头里的总长度 / IPv6 的 40 + 负载长度（和 tshark 的 ip.len / ipv6.plen 同一口径）
        key = (st, proto, ip["src"], sport, ip["dst"], dport) if up else (st, proto, ip["dst"], dport, ip["src"], sport)
        a = self.flow_stats.get(key)
        if a is None:
            a = self.flow_stats[key] = {"packets_up": 0, "packets_down": 0, "bytes_up": 0, "bytes_down": 0, "first": ts, "last": ts}
        a["packets_up" if up else "packets_down"] += 1
        a["bytes_up" if up else "bytes_down"] += length
        a["first"], a["last"] = min(a["first"], ts), max(a["last"], ts)

    def feed(self, n, ts, st, msdus, up=None):
        """n：帧 / 包号；ts：时间；st：设备（None 不算）；msdus：[LLC/SNAP 开头的字节]；up：True 设备发出的、False 发给设备的、None 不清楚（不计流量）。"""
        if st is None:
            self.stats["no_device"] += 1
            return
        for m in msdus:
            self.stats["msdu"] += 1
            ds = net.describe(m)
            if not ds:
                self.stats["unparsed"] += 1
                continue
            layers = ds["layers"]
            self.stacks[tuple(layers)] += 1
            if False in ds["checks"]:
                self.stats["bad_checksum"] += 1
            if "ip" not in ds:
                continue
            ip = ds["ip"]
            if "udp" in ds and "dns" not in layers and "dhcp" not in layers and (ds["udp"]["sport"] in net.DNS_PORTS or ds["udp"]["dport"] in net.DNS_PORTS):
                self.stats["dns_malformed"] += 1
            elif len(layers) == 2 and ip.get("frag_offset", 0) | ip.get("flags", 0) & 1:            # 只有 snap + ipv4：分片（describe 在分片处就停了）
                self.stats["fragment"] += 1
            if up is not None and ("udp" in ds or "tcp" in ds):
                t = ds.get("udp") or ds["tcp"]
                self._count(ts, st, ip, "udp" if "udp" in ds else "tcp", t["sport"], t["dport"], up)
            if "dns" in ds["layers"]:
                q, u = ds["dns"], ds["udp"]
                if not q["response"] and q["questions"] and u["dport"] in (53, MDNS_PORT):
                    qq = q["questions"][0]
                    self.events.append({"ts": ts, "station": st, "kind": "mdns" if u["dport"] == MDNS_PORT else "dns", "name": qq["name"], "qtype": qq["type"],
                                        "server": ip["dst"], "port": u["dport"], "transport": "udp", "frame": n})
                elif q["response"] and u["sport"] == 53 and q["questions"]:
                    for a in q["answers"]:
                        if a["type"] in (1, 28) and isinstance(a["data"], str):
                            self.answers[(st, a["data"])] = q["questions"][0]["name"]
            elif "udp" in ds and len(ds["udp"]["payload"]) >= QUIC_MIN and ds["udp"]["payload"][0] & 0xC0 == 0xC0:       # 客户端 Initial 数据报至少 1200 字节，长包头
                u = ds["udp"]
                c = self.udp.setdefault((st, ip["src"], u["sport"], ip["dst"], u["dport"]), {"ts": ts, "frame": n, "datagrams": []})
                c["datagrams"].append(u["payload"])
            elif "tcp" in ds:
                t = ds["tcp"]
                key = (ip["src"], t["sport"], ip["dst"], t["dport"])
                self.flows.add(ip["src"], ip["dst"], t, n)
                self.owner.setdefault(key, st)
                self.first_ts.setdefault(key, ts)

    @staticmethod
    def _why_unread(d, data):
        """这个方向有数据，但读不出 ClientHello 也读不出 HTTP 请求：归到哪一类（诊断用）。"""
        why, _ = tls80211.diagnose(data)
        if why in ("not_hello", "truncated"):
            if why == "not_hello" and data[5] == 2:                      # ServerHello：服务器方向，正常
                return "server_side"
            return "tls_" + why
        if d.gap:                                                        # 开头读不出，但缺口之后有没有 ClientHello？
            for kind, piece in d.pieces():
                if kind == "data" and piece[:2] == b"\x16\x03" and len(piece) > 5 and piece[5] == 1:
                    return "hello_after_gap"
            if not data:
                return "gap_first"
        return "other_tcp"

    def _log_summary(self, c, qstats=None):
        """读完之后写阶段小结：包的协议层、没解开 / 丢掉的、TCP 重组、TLS / HTTP / QUIC 的结果、每台设备的事件。"""
        st = self.stats
        if st["msdu"] or st["no_device"]:
            top = "，".join("%s %d" % ("/".join(k), n) for k, n in self.stacks.most_common(12))
            log.info("明文包 %d 个（另有 %d 个不归任何设备）；协议层：%s", st["msdu"], st["no_device"], top or "无")
        if st["unparsed"]:
            log.info("%d 个 MSDU 不是 LLC/SNAP，没有解析（生成树以外的 LLC、或解密出的内容不对）", st["unparsed"])
        if st["bad_checksum"]:
            share = st["bad_checksum"] / max(1, st["msdu"])
            msg = "%d 个包（%.0f%%）的校验和不对：多半是解密不对（口令 / 密钥错、重放），或抓包机的校验和卸载造成的假错误（在发送方抓包时常见）" % (st["bad_checksum"], 100 * share)
            (log.warning if share >= 0.05 else log.info)("%s", msg)
        if st["fragment"]:
            log.info("%d 个 IPv4 分片没有重组（分片里没有完整的上层数据，不读 DNS / TLS）", st["fragment"])
        if st["dns_malformed"]:
            log.info("%d 个发往 DNS 端口的 UDP 包解不出 DNS 报文（格式不对或被截断）", st["dns_malformed"])
        for why, n in sorted(self.excluded.items()):
            log.info("%d 个帧不归任何设备：%s", n, why)
        self.flows.log_summary()
        if c["hello"] or c["http"] or c["quic_conn"]:
            log.info("TLS：读到 %d 个 ClientHello（其中 DoT %d）；没有 SNI %d（用 DNS 补上名字 %d，没名字 %d）；带 ECH %d（SNI 是外层公开名，不是真正的目的）", c["hello"], c["dot"], c["hello_no_sni"], c["hello_by_dns"], c["hello_unnamed"], c["hello_ech"])
            log.info("HTTP：读到 %d 个请求（Host 缺失用 DNS 补名 %d，没名字 %d）", c["http"], c["http_by_dns"], c["http_unnamed"])
            log.info("QUIC：%d 个连接，ClientHello 读全并有名字 %d，CRYPTO 流不完整 %d，读不出 %d；没有 SNI %d，没名字 %d，带 ECH %d",
                     c["quic_conn"], c["quic_conn"] - c["quic_incomplete"] - c["quic_unreadable"] - c["quic_unnamed"], c["quic_incomplete"], c["quic_unreadable"], c["quic_no_sni"], c["quic_unnamed"], c["quic_ech"])
        lost = c["tls_truncated"] + c["hello_after_gap"] + c["gap_first"]
        if lost:
            log.warning("%d 个 TCP 方向的 ClientHello / 请求没读到，因为数据被截断或中间缺包（tls_truncated %d，缺口之后才有 ClientHello %d，起点就缺 %d）：这些连接没有名字", lost, c["tls_truncated"], c["hello_after_gap"], c["gap_first"])
        if c["quic_incomplete"]:
            log.warning("%d 个 QUIC 连接的 CRYPTO 流不完整（缺包，常见于 ClientHello 跨两个包而只抓到一个）：这些连接没有名字", c["quic_incomplete"])
        if qstats and qstats["datagrams"]:
            log.debug("%s", quic.describe(qstats))
        log.debug("没读出 ClientHello / 请求的 TCP 方向：TLS 不是 ClientHello %d，服务器方向 %d，其它协议 %d", c["tls_not_hello"], c["server_side"], c["other_tcp"])
        per = collections.defaultdict(collections.Counter)
        for e in self.events:
            per[e["station"]][e["kind"]] += 1
        log.info("事件 %d 个，来自 %d 台设备", len(self.events), len(per))
        for dev, k in sorted(per.items(), key=lambda x: -sum(x[1].values())):
            log.debug("设备 %s：%s", dev, "、".join("%s %d" % kv for kv in k.most_common()))
        by_dns = sum(1 for e in self.events if e.get("via") == "dns")
        if by_dns:
            log.info("%d 个事件的名字来自这台设备自己先前的 DNS 应答（连接里没有 SNI / Host）", by_dns)
        if not self.events and (st["msdu"] or st["no_device"]):
            log.warning("包读了，但一个访问事件也没有：没有 DNS 查询、也没读到 TLS / HTTP / QUIC 的名字（只抓到后半段连接？设备认不出？加密 DNS？）")

    def finish(self):
        """读完所有包之后，从重组好的 TCP 流和收集的 UDP 数据报里认出 TLS / HTTP / DoT / QUIC 事件。返回自己（.events 已按时间排好）。"""
        events, answers, owner, first_ts, udp, flows = self.events, self.answers, self.owner, self.first_ts, self.udp, self.flows
        pairs = self.flows.pairs()
        c = collections.Counter()                                        # 诊断计数：读 ClientHello / 请求的结果
        for p in pairs:                                                  # 先处理 TCP 上的 DNS：它的应答要给后面的连接补名字
            k = p["key"]
            for key, d in ((k, p["fwd"]), ((k[2], k[3], k[0], k[1]), p["rev"])):
                if d is None or 53 not in (key[1], key[3]):
                    continue
                st = owner[key]
                for q in dns_over_tcp(d.data()):
                    if not q["response"] and q["questions"] and key[3] == 53:
                        qq = q["questions"][0]
                        events.append({"ts": first_ts[key], "station": st, "kind": "dns", "name": qq["name"], "qtype": qq["type"], "server": key[2], "port": 53, "transport": "tcp",
                                       "frame": d.first_frame})
                    elif q["response"] and key[1] == 53 and q["questions"]:
                        for a in q["answers"]:
                            if a["type"] in (1, 28) and isinstance(a["data"], str):
                                answers[(st, a["data"])] = q["questions"][0]["name"]
        for p in pairs:
            k = p["key"]
            for key, d in ((k, p["fwd"]), ((k[2], k[3], k[0], k[1]), p["rev"])):         # 哪一方是客户端不靠 SYN 认：谁发出了 ClientHello / 请求行谁就是（抓包可能从连接中途开始）
                if d is None:
                    continue
                data = d.data()
                hello = tls80211.parse_client_hello(data)
                st = owner[key]
                if hello is not None:
                    sni = hello["sni"][0] if hello["sni"] else None
                    c["hello"] += 1
                    c["hello_ech"] += bool(hello["ech"])
                    c["hello_no_sni"] += sni is None
                    if key[3] == DOT_PORT:                               # DNS over TLS：只记连了哪台服务器，不看里面的查询（加密的）
                        c["dot"] += 1
                        self.names.setdefault((st, "tcp") + key, (sni or key[2], "sni" if sni else "ip", "dot"))
                        events.append({"ts": first_ts[key], "station": st, "kind": "dot", "name": sni or key[2], "server": key[2], "port": key[3], "via": "sni" if sni else "ip",
                                       "frame": d.first_frame})
                        break
                    name = sni or answers.get((st, key[2]))
                    c["hello_by_dns"] += sni is None and name is not None
                    c["hello_unnamed"] += name is None
                    if name is not None:
                        self.names.setdefault((st, "tcp") + key, (name, "sni" if sni else "dns", "tls"))
                        events.append({"ts": first_ts[key], "station": st, "kind": "tls", "name": name, "server": key[2], "port": key[3], "via": "sni" if sni else "dns", "frame": d.first_frame})
                    break
                reqs = [r for kind, piece in d.pieces() if kind == "data" for r in http_requests(piece)]      # 缺口之后的一段若恰好从请求行开始，照样读（tshark 也这样）
                if reqs:
                    for r in reqs:
                        name = r["host"] or answers.get((st, key[2]))
                        c["http"] += 1
                        c["http_by_dns"] += r["host"] is None and name is not None
                        c["http_unnamed"] += name is None
                        if name is not None:
                            self.names.setdefault((st, "tcp") + key, (name, "host" if r["host"] else "dns", "http"))
                            events.append({"ts": first_ts[key], "station": st, "kind": "http", "name": name, "server": key[2], "port": key[3], "via": "host" if r["host"] else "dns",
                                           "method": r["method"], "path": r["path"], "frame": d.first_frame})
                    break
                if d.segs:                                                # 有数据但既不是 ClientHello 也不是请求：记下为什么
                    c[self._why_unread(d, data)] += 1
        qstats = collections.Counter()
        for (st, _src, _sport, dst, dport), g in udp.items():
            for conn in quic.collect(g["datagrams"], qstats).values():
                c["quic_conn"] += 1
                if conn["client_hello"] is None:
                    c["quic_incomplete"] += 1
                    continue
                ch = conn["client_hello"]
                hello = tls80211.parse_client_hello(b"\x16\x03\x01" + len(ch).to_bytes(2, "big") + ch) if len(ch) < 1 << 16 else None
                if hello is None:
                    c["quic_unreadable"] += 1
                    continue
                sni = hello["sni"][0] if hello["sni"] else None
                name = sni or answers.get((st, dst))
                c["quic_ech"] += bool(hello["ech"])
                c["quic_no_sni"] += sni is None
                c["quic_unnamed"] += name is None
                if name is not None:
                    self.names.setdefault((st, "udp", _src, _sport, dst, dport), (name, "sni" if sni else "dns", "quic"))
                    events.append({"ts": g["ts"], "station": st, "kind": "quic", "name": name, "server": dst, "port": dport, "via": "sni" if sni else "dns", "frame": g["frame"]})
        events.sort(key=lambda e: (e["ts"], e["frame"]))
        self._log_summary(c, qstats)
        return self


def analyze(frames, decrypted):
    """802.11：frames 是 iter_frames 的结果，decrypted 是 decrypt_capture 的结果 -> 已 finish 的 Collector（.events、.flow_stats、.names、.answers）。
    设备是帧里不是接入点的那一方；ToDS 的帧是设备发出的（上行），FromDS 的是发给设备的（下行）。"""
    by_n = {f.n: f for f in frames}
    c = Collector()
    for n, v in decrypted.items():
        f = by_n[n]
        st = station_of(f.h)
        if st is None:
            h = f.h
            c.excluded["AP 发出的组播 / 广播帧（转发的副本）" if h["from_ds"] and not h["to_ds"] else "WDS / IBSS（分不出哪个是设备）"] += 1
        c.feed(n, f.ts, st, v["msdus"], bool(f.h["to_ds"]))                # 有设备就一定是 ToDS 或 FromDS 之一（station_of 排除了 WDS / IBSS）
    return c.finish()


def build(frames, decrypted):
    """frames：iter_frames 的结果；decrypted：decrypt_capture 的结果。-> 按时间排好的事件列表。"""
    return analyze(frames, decrypted).events


def sessions(events, gap=60.0):
    """同一台设备连续访问同一个名字、相邻两次不超过 gap 秒，合成一段：[{"station", "name", "start", "end", "count", "kinds"}]，按开始时间排序。"""
    open_, out = {}, []
    for e in events:
        k = (e["station"], e["name"])
        s = open_.get(k)
        if s is None or e["ts"] - s["end"] > gap:
            s = {"station": e["station"], "name": e["name"], "start": e["ts"], "end": e["ts"], "count": 0, "kinds": set()}
            open_[k] = s
            out.append(s)
        s["end"] = e["ts"]
        s["count"] += 1
        s["kinds"].add(e["kind"])
    return out


def summary(events):
    """{设备: {名字: 次数}}。"""
    out = {}
    for e in events:
        c = out.setdefault(e["station"], {})
        c[e["name"]] = c.get(e["name"], 0) + 1
    return out
