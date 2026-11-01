# -*- coding: utf-8 -*-
"""
流量统计：每台设备的每条 TCP / UDP 流（设备 IP:端口 <-> 对端 IP:端口）的包数、L3 字节（上行 / 下行）、首末时间，加上这条流认出的名字（SNI / HTTP Host / DNS 应答里的 IP -> 域名），
再按应用汇总成每台设备每个应用的上行 / 下行字节。纯标准库。

口径：字节 = IP 头里的总长度（IPv4 total length；IPv6 是 40 + 负载长度），和 tshark 的 ip.len / ipv6.plen 一致；含 TCP 重传的字节和 IP 头、TCP / UDP 头，不含链路层头。
包数 / 字节按「抓到的包」算，没有去掉重传（要去掉得跟踪 TCP 序号，重传在家用网络里通常很少，这里不做），所以是线上流量的近似，不是应用层数据量。
"""

import logging

log = logging.getLogger(__name__)
UNNAMED = "未命名"


def flows(result):
    """result：activity.analyze / plain.analyze 的结果 -> 流的列表，按首次出现时间排序：
    {"station", "proto", "local", "remote"（"IP:端口" 字符串之外另给 local_ip / local_port / remote_ip / remote_port）, "packets_up", "packets_down", "bytes_up", "bytes_down", "first", "last",
     "name"（认出的名字，没有是 None）, "via"（sni / host / dns / ip / None）, "kind"（tls / http / quic / dot / dns / None）}。
    名字先看这条连接自己的 SNI / Host（客户端口要对得上），没有再看设备自己 DNS 应答里这个 IP 的域名；都没有就是 None，不猜。"""
    out = []
    for (st, proto, lip, lport, rip, rport), a in result.flow_stats.items():
        hit = result.names.get((st, proto, lip, lport, rip, rport))
        if hit:
            name, via, kind = hit
        else:
            name = result.answers.get((st, rip))
            via, kind = ("dns", "dns") if name else (None, None)
        out.append(dict(a, station=st, proto=proto, local_ip=lip, local_port=lport, remote_ip=rip, remote_port=rport, name=name, via=via, kind=kind))
    out.sort(key=lambda f: (f["first"], f["station"], f["local_port"], f["remote_ip"]))
    return out


def aggregate(rules, flow_list):
    """-> {设备: {"apps": {应用: {"category", "flows", "packets_up", "packets_down", "bytes_up", "bytes_down", "first", "last"}},
              "other": {名字或服务器 IP: {同样的字段（没有 category）, "named": 有名字没规则 True / 没名字 False}}}}。
    有名字且规则认识的归应用；有名字但没规则的、没有名字的都放 other，键是名字，没有名字就是「未命名 对端 IP」。"""
    out = {}
    for f in flow_list:
        dev = out.setdefault(f["station"], {"apps": {}, "other": {}})
        hit = rules.label(f["name"]) if f["name"] else None
        if hit:
            bucket, key, extra = dev["apps"], hit["app"], {"category": hit["category"]}
        else:
            bucket, key, extra = dev["other"], f["name"] or "%s %s" % (UNNAMED, f["remote_ip"]), {"named": f["name"] is not None}
        b = bucket.get(key)
        if b is None:
            b = bucket[key] = dict(extra, flows=0, packets_up=0, packets_down=0, bytes_up=0, bytes_down=0, first=f["first"], last=f["last"])
        b["flows"] += 1
        for k in ("packets_up", "packets_down", "bytes_up", "bytes_down"):
            b[k] += f[k]
        b["first"], b["last"] = min(b["first"], f["first"]), max(b["last"], f["last"])
    return out


def human(n):
    """字节数 -> 人读的写法（1024 进制，B / KiB / MiB / GiB）。"""
    n = float(n)
    for unit in ("B", "KiB", "MiB"):
        if n < 1024:
            return ("%d %s" % (n, unit)) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024
    return "%.1f GiB" % n


def nameable(f):
    """这条流有可能认出名字：TCP（TLS / HTTP / DoT）和 443 端口的 UDP（QUIC）。DNS、mDNS、DHCP、NTP 之类本来就不带名字。"""
    return f["proto"] == "tcp" or f["remote_port"] == 443


def log_summary(flow_list):
    """写进日志：流数、上下行总字节、可命名的流里没有名字的占比。返回 (总字节, 没名字的字节)。"""
    up = sum(f["bytes_up"] for f in flow_list)
    down = sum(f["bytes_down"] for f in flow_list)
    unnamed = [f for f in flow_list if not f["name"]]
    ub = sum(f["bytes_up"] + f["bytes_down"] for f in unnamed)
    total = up + down
    protos = {}
    for f in flow_list:
        protos[f["proto"]] = protos.get(f["proto"], 0) + 1
    able = [f for f in flow_list if nameable(f)]
    able_unnamed = [f for f in able if not f["name"]]
    log.info("流量：%d 条流（%s），上行 %s、下行 %s；没有名字的 %d 条（%.0f%% 的字节）；其中可能带名字的（TCP、UDP 443）%d 条，没名字 %d 条",
             len(flow_list), "、".join("%s %d" % kv for kv in sorted(protos.items())) or "无", human(up), human(down), len(unnamed), 100 * ub / total if total else 0, len(able), len(able_unnamed))
    if len(able) >= 3 and len(able_unnamed) / len(able) > 0.5:
        log.warning("一半以上本该有名字的流没有名字（%d/%d）：没读到 SNI / Host，也没有这台设备的 DNS 应答可以对上。多半是只抓到连接的后半段、设备用了加密 DNS，或者是 QUIC / TLS 缺包", len(able_unnamed), len(able))
    return total, ub
