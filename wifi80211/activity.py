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
import re

from . import dns as dns80211
from . import net
from . import quic
from . import tcpstream
from . import tls as tls80211

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
            return
        for m in msdus:
            ds = net.describe(m)
            if not ds or "ip" not in ds:
                continue
            ip = ds["ip"]
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

    def finish(self):
        """读完所有包之后，从重组好的 TCP 流和收集的 UDP 数据报里认出 TLS / HTTP / DoT / QUIC 事件。返回自己（.events 已按时间排好）。"""
        events, answers, owner, first_ts, udp, flows = self.events, self.answers, self.owner, self.first_ts, self.udp, self.flows
        pairs = self.flows.pairs()
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
                    if key[3] == DOT_PORT:                               # DNS over TLS：只记连了哪台服务器，不看里面的查询（加密的）
                        self.names.setdefault((st, "tcp") + key, (sni or key[2], "sni" if sni else "ip", "dot"))
                        events.append({"ts": first_ts[key], "station": st, "kind": "dot", "name": sni or key[2], "server": key[2], "port": key[3], "via": "sni" if sni else "ip",
                                       "frame": d.first_frame})
                        break
                    name = sni or answers.get((st, key[2]))
                    if name is not None:
                        self.names.setdefault((st, "tcp") + key, (name, "sni" if sni else "dns", "tls"))
                        events.append({"ts": first_ts[key], "station": st, "kind": "tls", "name": name, "server": key[2], "port": key[3], "via": "sni" if sni else "dns", "frame": d.first_frame})
                    break
                reqs = [r for kind, piece in d.pieces() if kind == "data" for r in http_requests(piece)]      # 缺口之后的一段若恰好从请求行开始，照样读（tshark 也这样）
                if reqs:
                    for r in reqs:
                        name = r["host"] or answers.get((st, key[2]))
                        if name is not None:
                            self.names.setdefault((st, "tcp") + key, (name, "host" if r["host"] else "dns", "http"))
                            events.append({"ts": first_ts[key], "station": st, "kind": "http", "name": name, "server": key[2], "port": key[3], "via": "host" if r["host"] else "dns",
                                           "method": r["method"], "path": r["path"], "frame": d.first_frame})
                    break
        for (st, _src, _sport, dst, dport), c in udp.items():
            for conn in quic.collect(c["datagrams"]).values():
                if conn["client_hello"] is None:
                    continue
                ch = conn["client_hello"]
                hello = tls80211.parse_client_hello(b"\x16\x03\x01" + len(ch).to_bytes(2, "big") + ch) if len(ch) < 1 << 16 else None
                if hello is None:
                    continue
                sni = hello["sni"][0] if hello["sni"] else None
                name = sni or answers.get((st, dst))
                if name is not None:
                    self.names.setdefault((st, "udp", _src, _sport, dst, dport), (name, "sni" if sni else "dns", "quic"))
                    events.append({"ts": c["ts"], "station": st, "kind": "quic", "name": name, "server": dst, "port": dport, "via": "sni" if sni else "dns", "frame": c["frame"]})
        events.sort(key=lambda e: (e["ts"], e["frame"]))
        return self


def analyze(frames, decrypted):
    """802.11：frames 是 iter_frames 的结果，decrypted 是 decrypt_capture 的结果 -> 已 finish 的 Collector（.events、.flow_stats、.names、.answers）。
    设备是帧里不是接入点的那一方；ToDS 的帧是设备发出的（上行），FromDS 的是发给设备的（下行）。"""
    by_n = {f.n: f for f in frames}
    c = Collector()
    for n, v in decrypted.items():
        f = by_n[n]
        c.feed(n, f.ts, station_of(f.h), v["msdus"], bool(f.h["to_ds"]))                # 有设备就一定是 ToDS 或 FromDS 之一（station_of 排除了 WDS / IBSS）
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
