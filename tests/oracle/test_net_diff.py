#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解密之后的内容：用我们自己解出来的明文（pipeline80211），逐层解析（net80211），和 tshark 对同一帧的协议字段比。
  - 每个样例里各种协议栈（如 snap/ipv4/udp/dhcp）的帧数固定成表；
  - 逐帧对 tshark：ARP 操作码与地址、IPv4 / IPv6 的源目的地址与上层协议、UDP / TCP 端口、TCP 标志、ICMP / ICMPv6 类型、DHCP 报文类型与 xid
    （A-MSDU 的帧一帧里有多个 MSDU，tshark 的字段是列表，不逐帧比，只计数）；
  - 校验和：所有解出来的 IPv4 头、UDP、TCP、ICMP、ICMPv6 校验和都吻合——解密错一个比特就对不上，不依赖 tshark，是「解对了」的独立证明。
    例外固定在表里：13 个 ICMP 回显应答的负载是 00 01 02 03… 的测试图案，ICMP 头本身不合规，tshark 也报「Checksum Status: Bad」。
"""
import collections
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import decrypt_oracle as d  # noqa: E402
import fetch_samples  # noqa: E402
import frames80211 as fr  # noqa: E402
import net80211 as net  # noqa: E402
import pipeline80211 as pl  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


FIELDS = ["arp.opcode", "arp.src.proto_ipv4", "arp.dst.proto_ipv4", "ip.src", "ip.dst", "ip.proto", "ipv6.src", "ipv6.dst", "ipv6.nxt", "udp.srcport", "udp.dstport",
          "tcp.srcport", "tcp.dstport", "tcp.flags", "icmp.type", "icmpv6.type", "dhcp.option.dhcp", "dhcp.id"]


def tshark_fields(path, keys):
    usable, _ = d.tshark_usable(keys)
    with d.key_env(usable) as env:
        cmd = ["tshark", "-r", path] + d.TSHARK_DECRYPT + ["-E", "occurrence=f", "-Y", "wlan.fc.protected==1 && wlan.fc.type==2", "-T", "fields", "-e", "frame.number"]
        for f in FIELDS:
            cmd += ["-e", f]
        out = subprocess.run(cmd, capture_output=True, text=True, env=env).stdout
    rows = {}
    for line in out.split("\n"):
        if line:
            c = (line.split("\t") + [""] * (len(FIELDS) + 1))[:len(FIELDS) + 1]
            rows[int(c[0])] = dict(zip(FIELDS, c[1:]))
    return rows


def expect(ds):
    """我们解析出来的 -> 同样字段在 tshark 里应有的值（没有这一层的字段为空串）。"""
    e = {f: "" for f in FIELDS}
    if "arp" in ds:
        a = ds["arp"]
        e.update({"arp.opcode": str(a["op"]), "arp.src.proto_ipv4": a["spa"], "arp.dst.proto_ipv4": a["tpa"]})
    ip = ds.get("ip")
    if ip and "ipv4" in ds["layers"]:
        e.update({"ip.src": ip["src"], "ip.dst": ip["dst"], "ip.proto": str(ip["proto"])})
    if ip and "ipv6" in ds["layers"]:
        e.update({"ipv6.nxt": str(ip["next_header"])})
    if "udp" in ds:
        e.update({"udp.srcport": str(ds["udp"]["sport"]), "udp.dstport": str(ds["udp"]["dport"])})
    if "tcp" in ds:
        t = ds["tcp"]
        e.update({"tcp.srcport": str(t["sport"]), "tcp.dstport": str(t["dport"]), "tcp.flags": "0x%04x" % t["flags"]})
    if "icmp" in ds:
        e["icmp.type" if "icmp" in ds["layers"] else "icmpv6.type"] = str(ds["icmp"]["type"])
    if "dhcp" in ds:
        e.update({"dhcp.option.dhcp": str(ds["dhcp"]["message_type"]), "dhcp.id": "0x%08x" % ds["dhcp"]["xid"]})
    return e


EMBEDDED_BY_ICMP = ("udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport", "tcp.flags")      # ICMP 差错报文里嵌着出错的那个包，tshark 把它也解开
TEREDO_PORT = 3544                                                                                    # IPv4/UDP 里隧道的 IPv6（Teredo），tshark 也解开了里面的协议
EMBEDDED_BY_TEREDO = ("icmpv6.type", "ipv6.nxt")


def same(ds, t):
    """我们有的字段必须与 tshark 相同（IPv6 地址格式不同，不比）；我们没有的字段 tshark 也应当没有，
    例外：ICMP 差错报文里嵌套的原包、Teredo 隧道里的 IPv6——tshark 多解了一层，我们不解。"""
    e = expect(ds)
    icmp_error = "icmp" in ds["layers"] and ds["icmp"]["type"] in (3, 4, 5, 11, 12)
    teredo = "udp" in ds and TEREDO_PORT in (ds["udp"]["sport"], ds["udp"]["dport"])
    for k in FIELDS:
        if k in ("ipv6.src", "ipv6.dst"):
            continue
        if e[k] != "":
            if t[k] != e[k]:
                return False
        elif t[k] != "" and not ((icmp_error and k in EMBEDDED_BY_ICMP) or (teredo and k in EMBEDDED_BY_TEREDO)):
            return False
    return True


EXPECTED = {
    "owe-3-dh-groups.pcapng.gz": (3, {'snap/ipv4/icmp': 3}, 3, 2, 0),
    "owe.pcapng.gz": (10, {'snap/arp': 3, 'snap/ipv4/udp/dhcp': 7}, 0, 0, 0),
    "wep.pcapng.gz": (10, {'snap/arp': 2, 'snap/ipv4/icmp': 4, 'snap/ipv4/udp/dhcp': 4}, 0, 0, 0),
    "wpa-Induction.pcap.gz": (276, {'llc/stp': 18, 'snap': 49, 'snap/arp': 26, 'snap/ipv4': 6, 'snap/ipv4/icmp': 22, 'snap/ipv4/tcp': 67, 'snap/ipv4/udp': 66, 'snap/ipv4/udp/dhcp': 3, 'snap/ipv6/icmpv6': 19}, 0, 0, 0),
    "wpa-ccmp-256.pcapng.gz": (14, {'snap/arp': 4, 'snap/ipv4/icmp': 2, 'snap/ipv4/udp': 1, 'snap/ipv4/udp/dhcp': 7}, 0, 0, 0),
    "wpa-eap-tls.pcap.gz": (61, {'snap': 59, 'snap/ipv4': 2}, 0, 0, 0),
    "wpa-gcmp-256.pcapng.gz": (13, {'snap/arp': 4, 'snap/ipv4/icmp': 2, 'snap/ipv4/udp/dhcp': 7}, 0, 0, 0),
    "wpa-gcmp.pcapng.gz": (15, {'snap/arp': 4, 'snap/ipv4/icmp': 2, 'snap/ipv4/udp/dhcp': 9}, 0, 0, 0),
    "wpa-mlo-ccmp.pcapng.gz": (0, {}, 0, 0, 0),
    "wpa-test-decode-mgmt.pcap.gz": (0, {}, 0, 0, 0),
    "wpa-test-decode-tdls.pcap.gz": (6, {'snap': 6}, 0, 0, 0),
    "wpa-test-decode.pcap.gz": (756, {'snap': 5, 'snap/arp': 48, 'snap/ipv4': 40, 'snap/ipv4/icmp': 439, 'snap/ipv4/udp': 89, 'snap/ipv4/udp/dhcp': 7, 'snap/ipv6/icmpv6': 60, 'snap/ipv6/udp': 68}, 0, 0, 0),
    "wpa1-gtk-rekey.pcapng.gz": (22, {'snap': 6, 'snap/ipv4/icmp': 8, 'snap/ipv4/udp/dhcp': 8}, 0, 0, 0),
    "wpa2-ft-eap.pcapng.gz": (4, {'snap/arp': 2, 'snap/ipv4/icmp': 2}, 0, 0, 0),
    "wpa2-ft-psk.pcapng.gz": (17, {'snap/arp': 7, 'snap/ipv4/icmp': 4, 'snap/ipv4/udp/dhcp': 6}, 0, 0, 0),
    "wpa2-psk-ccmp-tkip.pcapng.gz": (12, {'snap/ipv4/icmp': 5, 'snap/ipv4/udp/dhcp': 7}, 0, 0, 0),
    "wpa2-psk-mfp.pcapng.gz": (9, {'snap/arp': 2, 'snap/ipv4/icmp': 3, 'snap/ipv4/udp/dhcp': 4}, 0, 0, 0),
    "wpa3-ft-sae-ext-key-group20.pcapng.gz": (4, {'snap/ipv6/icmpv6': 4}, 0, 4, 0),
    "wpa3-ft-sae-h2e.pcapng.gz": (16, {'snap/arp': 6, 'snap/ipv4/icmp': 4, 'snap/ipv4/udp/dhcp': 6}, 0, 6, 0),
    "wpa3-mlo.pcapng.gz": (8, {'snap': 2, 'snap/ipv6/icmpv6': 6}, 0, 6, 0),
    "wpa3-sae-ext-key-group21.pcapng.gz": (2, {'snap/ipv4/udp': 2}, 0, 2, 0),
    "wpa3-sae.pcapng.gz": (10, {'snap/arp': 2, 'snap/ipv4/udp/dhcp': 8}, 0, 0, 0),
    "wpa3-suiteb-192.pcapng.gz": (0, {}, 0, 0, 0),
    "wpa_ptk_extended_key_id.pcap.gz": (31, {'snap': 10, 'snap/ipv4/icmp': 10, 'snap/ipv6/icmpv6': 11}, 10, 0, 0),
}
BAD_CSUM = {"owe-3-dh-groups.pcapng.gz": 3, "wpa_ptk_extended_key_id.pcap.gz": 10}
fetch_samples.fetch()
keys = d.parse_keys()
total = amsdu_frames = ours_only_frames = 0
for name in sorted(os.listdir(fetch_samples.SAMPLE_DIR)):
    path = os.path.join(fetch_samples.SAMPLE_DIR, name)
    frames = list(fr.iter_frames(path))
    res = pl.decrypt_capture(frames, keys)
    ts = tshark_fields(path, keys)
    stacks, bad, diff, multi, no_tshark = collections.Counter(), 0, 0, 0, 0
    for n, v in res.items():
        descs = [net.describe(m) for m in v["msdus"]]
        if None in descs:
            stacks["unparsed"] += 1
            continue
        for ds in descs:
            stacks["/".join(ds["layers"])] += 1
            bad += any(c is False for c in ds["checks"])
        if len(descs) > 1:
            multi += 1
            continue
        t = ts.get(n)
        if t is None or (all(v == "" for v in t.values()) and not same(descs[0], t)):
            no_tshark += 1                      # tshark 解不开这一帧（64 字节 PMK 等）：字段全空，而我们解出了内容
        elif not same(descs[0], t):
            diff += 1
    total += len(res)
    amsdu_frames += multi
    ours_only_frames += no_tshark
    row = (len(res), dict(sorted(stacks.items())), bad, no_tshark, multi)
    if not EXPECTED:
        print('    "%s": %r,' % (name, row))
        continue
    check(diff == 0, "%s：和 tshark 的协议字段逐帧一致" % name)
    check(row == EXPECTED[name], "%s：%s（表里 %s）" % (name, row, EXPECTED[name]))
if EXPECTED:
    check(total == 1299 and ours_only_frames == 20 and amsdu_frames == 0, "共 %d 个解出的数据帧，其中 %d 个是 tshark 没有答案、靠校验和（和 CCMP 的 MIC）判断的；A-MSDU 帧 %d" % (total, ours_only_frames, amsdu_frames))
    check(sorted(EXPECTED) == sorted(os.listdir(fetch_samples.SAMPLE_DIR)), "表里的样例就是目录里的全部样例")
    print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
    sys.exit(0 if not failures else 1)
