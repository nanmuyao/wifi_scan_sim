# -*- coding: utf-8 -*-
"""
设备在访问什么：把解密后的明文（pipeline.decrypt_capture 的结果）逐帧读成事件——设备查了哪个域名（DNS）、连了哪个服务器的哪个域名（TLS 的 SNI）——
再按设备（MAC）汇总成访问时间线。纯标准库，只做被动识别，不碰 TLS 内容。

事件：{"ts", "station", "kind": "dns" | "mdns" | "tls" | "quic", "name", "server"（kind 为 tls 时是服务器 IP）, "port", "qtype"（dns）,"via"（tls / quic）, "frame"}。
一条 TLS 连接只在两个方向之一拿到完整 ClientHello（谁发出它谁就是客户端）时产生事件；ClientHello 缺了开头或被缺口截断（还没读到 SNI）的连接没有事件，
名字没有 SNI 时用这台设备先前 DNS 应答里的 IP -> 域名 补一个（kind 仍是 tls，字段 via 为 "dns"，SNI 的是 "sni"）。
"""
from . import dns as dns80211
from . import net
from . import quic
from . import tcpstream
from . import tls as tls80211

MDNS_PORT = 5353
QUIC_MIN = 1200


def station_of(h):
    """数据帧里「不是接入点」的那个设备：发往 AP 的取源地址，AP 发来的取目的地址；WDS / IBSS 不确定，返回 None。
    AP 发出的组播 / 广播帧（目的地址是组地址）不归任何设备：多半是 AP 把某台设备发来的组播转发出去的副本，那台设备自己的那一帧已经算过了。"""
    if h["to_ds"] and not h["from_ds"]:
        return h["sa"]
    if h["from_ds"] and not h["to_ds"]:
        return None if int(h["da"][:2], 16) & 1 else h["da"]
    return None


def build(frames, decrypted):
    """frames：iter_frames 的结果；decrypted：decrypt_capture 的结果。-> 按时间排好的事件列表。"""
    by_n = {f.n: f for f in frames}
    flows = tcpstream.Flows()
    owner, first_ts = {}, {}                                         # 连接方向 -> 设备 MAC / 第一个段的时间
    events = []
    udp = {}                                                         # (设备, 源 IP, 源端口, 目的 IP, 目的端口) -> {"ts", "frame", "datagrams": [...]}：可能是 QUIC Initial 的数据报
    answers = {}                                                     # (设备, 服务器 IP) -> 设备查过的域名（最近一次）
    for n, v in decrypted.items():
        f = by_n[n]
        st = station_of(f.h)
        if st is None:
            continue
        for m in v["msdus"]:
            ds = net.describe(m)
            if not ds or "ip" not in ds:
                continue
            ip = ds["ip"]
            if "dns" in ds["layers"]:
                q, u = ds["dns"], ds["udp"]
                if not q["response"] and q["questions"] and u["dport"] in (53, MDNS_PORT):
                    qq = q["questions"][0]
                    events.append({"ts": f.ts, "station": st, "kind": "mdns" if u["dport"] == MDNS_PORT else "dns", "name": qq["name"], "qtype": qq["type"],
                                   "server": ip["dst"], "port": u["dport"], "frame": n})
                elif q["response"] and u["sport"] == 53 and q["questions"]:
                    for a in q["answers"]:
                        if a["type"] in (1, 28) and isinstance(a["data"], str):
                            answers[(st, a["data"])] = q["questions"][0]["name"]
            elif "udp" in ds and len(ds["udp"]["payload"]) >= QUIC_MIN and ds["udp"]["payload"][0] & 0xC0 == 0xC0:       # 客户端 Initial 数据报至少 1200 字节，长包头
                u = ds["udp"]
                c = udp.setdefault((st, ip["src"], u["sport"], ip["dst"], u["dport"]), {"ts": f.ts, "frame": n, "datagrams": []})
                c["datagrams"].append(u["payload"])
            elif "tcp" in ds:
                t = ds["tcp"]
                key = (ip["src"], t["sport"], ip["dst"], t["dport"])
                flows.add(ip["src"], ip["dst"], t, n)
                owner.setdefault(key, st)
                first_ts.setdefault(key, f.ts)
    for p in flows.pairs():
        k = p["key"]
        for key, d in ((k, p["fwd"]), ((k[2], k[3], k[0], k[1]), p["rev"])):         # 哪一方是客户端不靠 SYN 认：谁发出了 ClientHello 谁就是（抓包可能从连接中途开始）
            hello = tls80211.parse_client_hello(d.data()) if d is not None else None
            if hello is None:
                continue
            st = owner[key]
            sni = hello["sni"][0] if hello["sni"] else None
            name = sni or answers.get((st, key[2]))
            if name is not None:
                events.append({"ts": first_ts[key], "station": st, "kind": "tls", "name": name, "server": key[2], "port": key[3], "via": "sni" if sni else "dns", "frame": d.first_frame})
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
                events.append({"ts": c["ts"], "station": st, "kind": "quic", "name": name, "server": dst, "port": dport, "via": "sni" if sni else "dns", "frame": c["frame"]})
    events.sort(key=lambda e: (e["ts"], e["frame"]))
    return events


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
