#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""流量统计对照 tshark：24 个样例解密后，每个设备的每条 TCP / UDP 流在每个方向上的包数和 L3 字节（IPv4 的 total length、IPv6 的 40 + 负载长度），
和 tshark 逐帧读到的 ip.len / ipv6.plen 按同样的五元组加起来的结果完全相同。
比较的口径：
  - tshark 解不开的帧（64 字节 PMK、FT 漫游等）只有我们有答案：把我们的统计限制在 tshark 解开了的那些帧上再比，限制之外多出来的包数固定在表里；
  - AP 发出的组播 / 广播帧（目的地址是组地址）我们不归任何设备（见 activity.station_of），tshark 的数据里去掉这类帧；
  - ICMP 差错报文里嵌着出错的那个包：tshark 的 tcp / udp 字段会读到里面一层，去掉 ICMP 帧；Teredo 隧道里 tshark 的第一个 udp / ip.len 就是外层的，和我们一致。"""
import collections
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decrypt_oracle as d  # noqa: E402
import fetch_samples  # noqa: E402
from wifi80211 import activity  # noqa: E402
from wifi80211 import frames as fr  # noqa: E402
from wifi80211 import pipeline as pl  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


FIELDS = ["ip.src", "ip.dst", "ip.len", "ipv6.src", "ipv6.dst", "ipv6.plen", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "wlan.fc.tods", "wlan.ra", "frame.number"]


def tshark_flows(path, keys):
    """-> {(协议, 设备 IP, 设备端口, 对端 IP, 对端端口): [上行包, 下行包, 上行字节, 下行字节]}，设备一侧按 ToDS（设备发出）判断。"""
    usable, _ = d.tshark_usable(keys)
    with d.key_env(usable) as env:
        cmd = ["tshark", "-r", path] + d.TSHARK_DECRYPT + ["-Y", "wlan.fc.protected==1 && wlan.fc.type==2 && (tcp || udp) && !icmp", "-T", "fields", "-E", "occurrence=f"]
        for f in FIELDS:
            cmd += ["-e", f]
        out = subprocess.run(cmd, capture_output=True, text=True, env=env).stdout
    flows, seen = collections.defaultdict(lambda: [0, 0, 0, 0]), set()
    for line in out.split("\n"):
        if not line:
            continue
        c = (line.split("\t") + [""] * len(FIELDS))[:len(FIELDS)]
        r = dict(zip(FIELDS, c))
        proto, sp, dp = ("tcp", r["tcp.srcport"], r["tcp.dstport"]) if r["tcp.srcport"] else ("udp", r["udp.srcport"], r["udp.dstport"])
        if r["ip.src"]:
            src, dst, length = r["ip.src"], r["ip.dst"], int(r["ip.len"])
        else:
            src, dst, length = r["ipv6.src"], r["ipv6.dst"], 40 + int(r["ipv6.plen"])
        up = r["wlan.fc.tods"] in ("1", "True")
        if not up and int(r["wlan.ra"].split(":")[0], 16) & 1:
            continue                                                       # AP 发出的组播 / 广播帧
        seen.add(int(r["frame.number"]))
        key = (proto, src, int(sp), dst, int(dp)) if up else (proto, dst, int(dp), src, int(sp))
        f = flows[key]
        f[0 if up else 1] += 1
        f[2 if up else 3] += length
    return flows, seen


def canon_v6(ip):
    import ipaddress
    return str(ipaddress.ip_address(ip)) if ":" in ip else ip


EXPECTED = {                                 # 流、包、L3 字节、只有我们解开的帧里的包（tshark 没有答案，不在比较里）
    "owe.pcapng.gz": (2, 5, 1640, 0),
    "wep.pcapng.gz": (2, 3, 996, 0),
    "wpa-Induction.pcap.gz": (37, 126, 43212, 0),
    "wpa-ccmp-256.pcapng.gz": (2, 5, 1664, 0),
    "wpa-gcmp-256.pcapng.gz": (2, 5, 1664, 0),
    "wpa-gcmp.pcapng.gz": (2, 6, 2004, 0),
    "wpa-test-decode.pcap.gz": (43, 148, 14444, 0),
    "wpa1-gtk-rekey.pcapng.gz": (2, 6, 1952, 0),
    "wpa2-ft-psk.pcapng.gz": (2, 4, 1320, 0),
    "wpa2-psk-ccmp-tkip.pcapng.gz": (2, 5, 1647, 0),
    "wpa2-psk-mfp.pcapng.gz": (2, 4, 1342, 0),
    "wpa3-ft-sae-h2e.pcapng.gz": (2, 2, 657, 2),                        # 漫游后的 DHCP：tshark 解不开的 2 个包只有我们数了
    "wpa3-sae-ext-key-group21.pcapng.gz": (0, 0, 0, 1),                 # 64 字节 PMK：tshark 一帧也解不开，这 1 个 mDNS 包只有我们有
    "wpa3-sae.pcapng.gz": (2, 6, 2010, 0),
}
fetch_samples.fetch()
keys = d.parse_keys()
total = collections.Counter()
for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    frames = list(fr.iter_frames(path))
    dec = pl.decrypt_capture(frames, keys)
    flows_t, seen = tshark_flows(path, keys)
    theirs = {(k[0], canon_v6(k[1]), k[2], canon_v6(k[3]), k[4]): v for k, v in flows_t.items()}

    def stats(decrypted):
        res = activity.analyze(frames, decrypted)
        return {(proto, canon_v6(lip), lport, canon_v6(rip), rport): [a["packets_up"], a["packets_down"], a["bytes_up"], a["bytes_down"]]
                for (st, proto, lip, lport, rip, rport), a in res.flow_stats.items()}
    mine_all, mine = stats(dec), stats({n: v for n, v in dec.items() if n in seen})
    pk = lambda m: sum(v[0] + v[1] for v in m.values())      # noqa: E731
    by = lambda m: sum(v[2] + v[3] for v in m.values())      # noqa: E731
    row = (len(theirs), pk(theirs), by(theirs), pk(mine_all) - pk(mine))
    if theirs or mine_all:
        check(mine == theirs, "%s：%d 条流的上下行包数和 L3 字节与 tshark 完全相同（我们 %d 条）" % (name, len(theirs), len(mine)))
        check(row == EXPECTED.get(name), "%s：流 / 包 / 字节 / 只有我们解开的帧里的包 = %s（表里 %s）" % (name, row, EXPECTED.get(name)))
        total.update(flows=row[0], packets=row[1], bytes=row[2], ours_only=row[3])
check(dict(total) == {"flows": 102, "packets": 325, "bytes": 74552, "ours_only": 3}, "合计 %s" % dict(total))
print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
