#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""应用级识别的第二份标准答案：nDPI（ntopng 用的深度包检测库）。tshark 只认协议，不认「这是抖音还是 YouTube」；nDPI 认。
同一批合成流量（TLS 的 SNI、QUIC Initial 的 SNI、明文 HTTP 的 Host，每个名字三种）：
  1. 先确认 nDPI 把它们识别成 TLS / QUIC / HTTP，且它读到的主机名和我们放进去的相同（独立验证我们的 TLS / QUIC / HTTP 构造器）；
  2. 再把 nDPI 给的应用名，和我们 apps80211 + rules/apps.json 给的应用名比：一致 / 只有我们认得 / 只有 nDPI 认得 / 都认得但说法不一样，
     各类的个数和分歧的清单固定成表——这是对比，不是「必须一致」：规则变了、nDPI 升级了，数字变化会让测试失败，提醒重新看一遍。
nDPI 的应用名和我们的不一定相同，中间靠 NDPI_TO_OURS 这张显式的对照表（每一项写明为什么算同一个）。"""
import logging
import os
import re
import subprocess
import sys
import tempfile

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, TCP, UDP, Raw, conf, wrpcap  # noqa: E402

conf.verb = 0
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import quic_build as qb  # noqa: E402
import tls_build as tb  # noqa: E402
from wifi80211 import apps  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


NAMES = ("www.douyin.com v26-web.douyinvod.com www.kuaishou.com www.bilibili.com i0.hdslb.com www.youtube.com rr3---sn-x.googlevideo.com www.netflix.com occ-0-1.nflxvideo.net "
         "www.tiktok.com www.facebook.com static.xx.fbcdn.net www.instagram.com t.me web.whatsapp.com open.spotify.com store.steampowered.com www.baidu.com www.taobao.com "
         "www.apple.com www.microsoft.com github.com chat.openai.com zoom.us discord.com www.twitch.tv line.me www.xiaohongshu.com www.iqiyi.com www.youku.com www.jd.com "
         "www.pinduoduo.com www.meituan.com twitter.com www.google.com www.amazon.com www.primevideo.com www.disneyplus.com weixin.qq.com www.huya.com www.douyu.com "
         "www.xiaomi.com music.163.com acfun.cn example.com en.wikipedia.org").split()
TRANSPORTS = ("tls", "quic", "http")
CLIENT = "10.0.0.2"

# nDPI 的应用名 -> 我们的应用名。只写「确实是同一个东西」的：每一项后面写原因。没有写的 nDPI 应用名原样比较（名字相同才算一致）。
NDPI_TO_OURS = {
    "Twitter": "X / Twitter",                          # 同一个服务，nDPI 还叫 Twitter
    "Line": "LINE",                                    # 只是大小写
    "Github": "GitHub",                                # 只是大小写
    "NetFlix": "Netflix",                              # 只是大小写
    "DisneyPlus": "Disney+",                           # 只是写法
    "iQIYI": "爱奇艺",                                  # 同一个服务的英文名 / 中文名
    "Taobao": "淘宝 / 阿里",                             # 我们把淘宝和阿里系放在一起，nDPI 单列淘宝
    "Xiaomi": "小米",                                   # 同一家的英文名 / 中文名
    "AmazonVideo": "Prime Video",                      # nDPI 的 AmazonVideo 就是 Prime Video 的流量
    "FbookReelStory": "Facebook",                      # Facebook Reels / Stories 的 CDN 域名，属于 Facebook
    "QQ": "腾讯（微信 / QQ / 腾讯视频等）",                  # weixin.qq.com：nDPI 归到 QQ，我们归到腾讯整家；同一家公司，nDPI 更细
}


def build(path):
    """每个（名字，传输方式）一条流，服务器 IP 各不相同：返回 {服务器 IP: (名字, 传输方式)}。"""
    pk, by_ip = [], {}
    n = 0
    for name in NAMES:
        for tr in TRANSPORTS:
            n += 1
            srv = "198.18.%d.%d" % (n // 250, n % 250 + 1)
            by_ip[srv] = (name, tr)
            sport = 20000 + n
            if tr == "quic":
                dcid = n.to_bytes(8, "big")
                pk.append(Ether() / IP(src=CLIENT, dst=srv) / UDP(sport=sport, dport=443) / Raw(qb.build(dcid, b"\x01", qb.crypto_frame(0, qb.client_hello(name)))))
                continue
            port = 443 if tr == "tls" else 80
            payload = tb.records(tb.hello([tb.sni_ext(name), tb.alpn_ext("h2")])) if tr == "tls" else \
                b"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n" % name.encode()
            pk += [Ether() / IP(src=CLIENT, dst=srv) / TCP(sport=sport, dport=port, seq=100, flags="S"),
                   Ether() / IP(src=srv, dst=CLIENT) / TCP(sport=port, dport=sport, seq=900, ack=101, flags="SA"),
                   Ether() / IP(src=CLIENT, dst=srv) / TCP(sport=sport, dport=port, seq=101, ack=901, flags="A"),
                   Ether() / IP(src=CLIENT, dst=srv) / TCP(sport=sport, dport=port, seq=101, ack=901, flags="PA") / Raw(payload)]
    wrpcap(path, pk)
    return by_ip


FLOW = re.compile(r"^\s*\d+\s+(?:TCP|UDP) \S+ <?-> (\S+):\d+ \[proto: ([^\]]+)\]")


def run_ndpi(path):
    """-> {服务器 IP: {"proto": "91.124/TLS.YouTube", "master": "TLS", "app": "YouTube" 或 None, "category": ..., "host": ...}}。"""
    try:
        out = subprocess.run([os.environ.get("NDPI_BIN", "ndpiReader"), "-i", path, "-v", "2"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return {}
    flows = {}
    for line in out.split("\n"):
        m = FLOW.match(line)
        if not m:
            continue
        ip, proto = m.group(1), m.group(2)
        names = proto.split("/", 1)[1].split(".") if "/" in proto else [proto]
        cat = re.search(r"\[cat: ([^\]/]+)/", line)
        host = re.search(r"\[Hostname/SNI: ([^\]]*)\]", line)
        flows[ip] = {"proto": proto, "master": names[0], "app": names[-1] if len(names) > 1 else None, "category": cat.group(1) if cat else None, "host": host.group(1) if host else None}
    return flows


tmp = tempfile.mkdtemp()
path = os.path.join(tmp, "ndpi.pcap")
by_ip = build(path)
flows = run_ndpi(path)
rules = apps.load()

print("== nDPI 把合成流量识别成什么协议 ==")
check(len(flows) == len(by_ip) == len(NAMES) * 3, "nDPI 报告了 %d 条流（造了 %d 条）" % (len(flows), len(by_ip)))
EXPECT_MASTER = {"tls": "TLS", "quic": "QUIC", "http": "HTTP"}
wrong = sorted((by_ip[ip], f["proto"]) for ip, f in flows.items() if ip in by_ip and f["master"] != EXPECT_MASTER[by_ip[ip][1]])
check(not wrong, "每条流的主协议都是对的（TLS 流是 TLS、QUIC 流是 QUIC、HTTP 流是 HTTP）；不对的：%s" % wrong[:5])
badhost = sorted((by_ip[ip], f["host"]) for ip, f in flows.items() if ip in by_ip and f["host"] != by_ip[ip][0])
check(not badhost, "nDPI 读到的主机名（SNI / Host）和我们放进去的逐条相同——独立验证了 TLS / QUIC / HTTP 的构造；不同的：%s" % badhost[:5])

print("== 应用名对比（nDPI vs 我们的规则）==")
cls = {"agree": [], "both_none": [], "we_only": [], "ndpi_only": [], "disagree": []}
for ip, (name, tr) in sorted(by_ip.items(), key=lambda kv: kv[1]):
    f = flows.get(ip)
    if f is None:
        continue
    ours = (rules.label(name) or {}).get("app")
    raw = f["app"]
    theirs = NDPI_TO_OURS.get(raw, raw)
    key = "both_none" if ours is None and theirs is None else "we_only" if theirs is None else "ndpi_only" if ours is None else "agree" if ours == theirs else "disagree"
    cls[key].append((name, tr, ours, raw))
for k, v in cls.items():
    print("    %-9s %3d" % (k, len(v)))
if os.environ.get("NDPI_DUMP"):
    for k, v in cls.items():
        print("  --", k)
        for row in v:
            print("     ", row)

names = {k: sorted({r[0] for r in v}) for k, v in cls.items()}
consistent = all(len({(r[2], r[3]) for r in rows if r[0] == n}) == 1 for rows in cls.values() for n in {r[0] for r in rows})
check(consistent, "同一个名字走 TLS / QUIC / HTTP，nDPI 和我们的结论都一样（两边都是按域名认的，和传输方式无关）")
check({k: len(v) for k, v in cls.items()} == {"agree": 84, "both_none": 3, "we_only": 48, "ndpi_only": 3, "disagree": 0}, "各类的流数：%s（共 %d 条 = %d 个名字 × 3 种传输）" % ({k: len(v) for k, v in cls.items()}, len(by_ip), len(NAMES)))
check(names["agree"] == sorted("""discord.com github.com line.me occ-0-1.nflxvideo.net open.spotify.com rr3---sn-x.googlevideo.com static.xx.fbcdn.net store.steampowered.com t.me twitter.com
    web.whatsapp.com weixin.qq.com www.amazon.com www.apple.com www.disneyplus.com www.facebook.com www.google.com www.instagram.com www.iqiyi.com www.microsoft.com www.netflix.com
    www.primevideo.com www.taobao.com www.tiktok.com www.twitch.tv www.xiaomi.com www.youtube.com zoom.us""".split()), "两边都认得、结论一致的 28 个名字（其中 12 个名字靠上面对照表里的 11 种 nDPI 应用名才算同一个，其余名字原样相同）")
check(names["we_only"] == sorted("""acfun.cn chat.openai.com i0.hdslb.com music.163.com v26-web.douyinvod.com www.baidu.com www.bilibili.com www.douyin.com www.douyu.com www.huya.com
    www.jd.com www.kuaishou.com www.meituan.com www.pinduoduo.com www.xiaohongshu.com www.youku.com""".split()), "只有我们认得、nDPI 只说 TLS / QUIC / HTTP 的 16 个名字：抖音、快手、哔哩哔哩、百度、小红书等国内应用，加 OpenAI")
check(names["ndpi_only"] == ["en.wikipedia.org"] and names["both_none"] == ["example.com"] and names["disagree"] == [], "只有 nDPI 认得：Wikipedia；两边都不认得：example.com；真正说法不一样的：没有")
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
