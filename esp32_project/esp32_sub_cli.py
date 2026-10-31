#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esp32_sub_cli.py —— 命令行数据订阅端（阶段9 / M4）

两种消费模式：

  --ws URL      订阅 esp32_bridge 的 WebSocket snapshot，实时打印 AP 表格
                与信道分布（每收到一条快照刷新一次）。
  --serial      从 stdin / 文件读取 +SNIFF 串口文本，解析并打印展示结果
                （等价消费 esp32_bridge --serial 的输出）。

WebSocket 客户端为最小 RFC6455 实现：发起 GET 升级握手（Sec-WebSocket-Key /
Accept 校验），读取无掩码文本帧（单字节 / 两字节扩展长度），
全部基于标准库 socket/hashlib/base64/struct，无第三方依赖。

用法：
  python3 esp32_sub_cli.py --ws ws://127.0.0.1:8765/ws --once
  python3 esp32_sub_cli.py --ws ws://127.0.0.1:8765/ws   # 持续订阅
  python3 esp32_bridge.py --serial | python3 esp32_sub_cli.py --serial
  python3 esp32_sub_cli.py --serial --file serial.log
"""

import argparse
import base64
import hashlib
import os
import socket
import struct
import sys

import esp32_consumer as consumer

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _parse_url(url):
    if not url.startswith("ws://"):
        raise ValueError("仅支持 ws:// 地址")
    rest = url[5:]
    hostport, _, path = rest.partition("/")
    path = "/" + path if path else "/"
    host, _, port = hostport.partition(":")
    if not port:
        port = "80"
    return host, int(port), path


def connect_ws(url, timeout=5.0):
    """建立最小 WebSocket 连接并校验握手。返回已就绪的 socket。"""
    host, port, path = _parse_url(url)
    key = base64.b64encode(os.urandom(16)).decode()
    sock = socket.create_connection((host, port), timeout=timeout)
    req = (
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n" % (path, host, port, key)
    ).encode("latin-1")
    sock.sendall(req)
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("WebSocket 握手失败：连接关闭")
        resp += chunk
    head = resp.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n")
    if "101" not in lines[0]:
        raise ConnectionError("WebSocket 握手失败：%s" % lines[0])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    expect = base64.b64encode(
        hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
    if headers.get("sec-websocket-accept") != expect:
        raise ConnectionError("WebSocket Accept 校验失败")
    return sock


def recv_text_frame(sock):
    """读取一条服务端文本帧（无掩码），返回 str；连接关闭返回 None。"""
    header = _recv_exact(sock, 2)
    if header is None:
        return None
    opcode = header[0] & 0x0F
    length = header[1] & 0x7F
    if length == 126:
        ext = _recv_exact(sock, 2)
        if ext is None:
            return None
        length = struct.unpack(">H", ext)[0]
    elif length == 127:
        ext = _recv_exact(sock, 8)
        if ext is None:
            return None
        length = struct.unpack(">Q", ext)[0]
    payload = _recv_exact(sock, length)
    if payload is None:
        return None
    if opcode == 0x9:  # ping
        sock.sendall(bytes([0x8A, 0x80]) + bytes(len(payload)))
        return None  # 让调用方继续读取
    if opcode == 0x8:  # close
        return None
    if opcode != 0x1:
        return None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def subscribe_ws(url, once):
    sock = connect_ws(url)
    print("已连接 %s（Ctrl-C 退出）" % url, file=sys.stderr, flush=True)
    count = 0
    try:
        while True:
            text = recv_text_frame(sock)
            if text is None:
                break
            msg = consumer.parse_message(text)
            if msg is None:
                continue
            view = consumer.build_view(msg)
            count += 1
            print("\n== snapshot #%d  ==" % count)
            print(consumer.format_cli_table(view))
            if once:
                return 0
    except KeyboardInterrupt:
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return 0


def consume_serial(stream):
    text = stream.read()
    parsed = consumer.parse_serial_lines(text)
    print("== 串口文本解析结果 ==")
    if parsed["aps"]:
        view = {"ts_ms": None, "channel": None,
                "ap_rows": consumer.rank_aps(parsed["aps"]),
                "channel_stats": consumer.channel_distribution(parsed["aps"]),
                "totals": {"ap_total": len(parsed["aps"]),
                           "ap_unique": len({a["bssid"] for a in parsed["aps"]}),
                           "probe_total": len(parsed["probes"]),
                           "displayed": len(parsed["aps"])}}
        print(consumer.format_cli_table(view))
    if parsed["probes"]:
        print("\n== 探测记录 ==")
        for p in parsed["probes"]:
            print('  PROBE "%s" %s rssi=%d' % (p["ssid"], p["sta"], p["rssi"]))
    if parsed["skipped"]:
        print("（跳过 %d 行无法识别）" % parsed["skipped"])
    return 0


def main():
    argp = argparse.ArgumentParser(description="ESP32 M4 命令行订阅端")
    argp.add_argument("--ws", default="", help="WebSocket 地址，如 ws://127.0.0.1:8765/ws")
    argp.add_argument("--once", action="store_true", help="收到第一条快照后退出")
    argp.add_argument("--serial", action="store_true", help="解析 stdin / --file 的 +SNIFF 串口文本")
    argp.add_argument("--file", default="", help="--serial 时的输入文件（默认 stdin）")
    args = argp.parse_args()

    if args.serial:
        if args.file:
            with open(args.file, "r", encoding="utf-8") as f:
                return consume_serial(f)
        return consume_serial(sys.stdin)
    if args.ws:
        return subscribe_ws(args.ws, args.once)
    argp.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
