#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esp32_bridge.py —— 端侧数据桥 / 极简 WebSocket 服务（阶段9 / M4）

把 esp32_sim.py 的扫描仿真转成浏览器/命令行可订阅的实时数据：

  - WebSocket 订阅端点  ws://127.0.0.1:8765/ws
    每 1 秒向所有已连接客户端推送一条 JSON snapshot
      {"type":"snapshot","ts_ms":...,"channel":...,"aps":[{"bssid","ssid",
       "rssi","channel","beacons","authmode_name"}],"probes":[...]}
    aps 在 M3 字段基础上附加 authmode_name（加密类型），供仪表盘展示。
  - HTTP 页面端点      http://127.0.0.1:8765/
    返回 dashboard.html 单页前端（无外部依赖，纯手写 JS）。
  - HTTP 轮询端点      http://127.0.0.1:8765/api/snapshot
    返回最近一条快照 JSON（WebSocket 不可用时的兜底）。
  - 串口文本输出（--serial）  在 stdout 打印 +SNIFF 文本，供命令行订阅端
    通过管道或 --serial 模式消费。

WebSocket 服务端为最小 RFC6455 实现（握手 SHA1+Base64、文本帧编码、
ping/pong 响应），全部基于标准库 socket/hashlib/base64/struct/threading，
无第三方依赖，可作为 ESP32 真机（M5）上报通道的 PC 侧参考实现。

用法：
  python3 esp32_bridge.py                 # 启动 WS+HTTP 服务（默认 127.0.0.1:8765）
  python3 esp32_bridge.py --port 9000     # 指定端口
  python3 esp32_bridge.py --serial        # 只在 stdout 输出 +SNIFF 串口文本
  python3 esp32_bridge.py --once --json   # 输出一条 JSON 快照后退出（供单测/脚本）
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time

import esp32_ap_parser as parser
from esp32_collector import ApCollector, ProbeCollector
from esp32_sim import scan_round, demo_probes

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def encode_text_frame(text):
    """RFC6455 文本帧编码（服务端发送，无掩码）。"""
    payload = text.encode("utf-8")
    n = len(payload)
    if n < 126:
        header = bytes([0x81, n])
    elif n <= 0xFFFF:
        header = bytes([0x81, 126]) + struct.pack(">H", n)
    else:
        header = bytes([0x81, 127]) + struct.pack(">Q", n)
    return header + payload


def build_snapshot(round_no):
    """生成一条 snapshot：用 collector 聚合一轮仿真扫描（带 authmode 扩展）。"""
    channel = (1, 6, 11)[round_no % 3]
    col = ApCollector(rssi_policy="best")
    col.add_records(scan_round(round_no, channel))
    probe_col = ProbeCollector()
    for sta, ssid, rssi in demo_probes():
        probe_col.add_probe(sta, ssid, rssi)

    aps = []
    for ap, cnt in col.items():
        aps.append({
            "bssid": ap.bssid,
            "ssid": "<hidden>" if ap.hidden else ap.ssid,
            "rssi": ap.rssi,
            "channel": ap.channel,
            "beacons": cnt,
            "authmode_name": ap.authmode_name,
        })
    return {
        "type": "snapshot",
        "ts_ms": int(time.time() * 1000),
        "channel": channel,
        "aps": aps,
        "probes": [dict(p) for p in probe_col.probes()],
    }


class BridgeServer(object):
    """极简 TCP 服务：同一端口区分 WebSocket 升级与普通 HTTP 请求。"""

    def __init__(self, host, port, snapshot_getter):
        self.host = host
        self.port = port
        self.snapshot_getter = snapshot_getter
        self._clients = set()
        self._lock = threading.Lock()
        self._sock = None
        self._dashboard_html = self._load_dashboard()

    @staticmethod
    def _load_dashboard():
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "dashboard.html")
        with open(path, "r", encoding="utf-8") as f:
            return f.read()

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(16)
        print("bridge 已启动: http://%s:%d/  ws://%s:%d/ws" % (
            self.host, self.port, self.host, self.port), flush=True)
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    def _read_headers(self, conn):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return None, None
            buf += chunk
        head, rest = buf.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        if not lines:
            return None, None
        method_path = lines[0].split(" ")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return method_path, (headers, rest)

    def _handle(self, conn):
        try:
            method_path, parsed = self._read_headers(conn)
            if parsed is None:
                return
            method = method_path[0]
            path = method_path[1] if len(method_path) > 1 else "/"
            headers, _rest = parsed
            if headers.get("upgrade", "").lower() == "websocket":
                self._handle_ws(conn, headers, path)
            else:
                self._handle_http(conn, method, path)
        except (OSError, ValueError, TypeError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _handle_http(self, conn, method, path):
        if method == "GET" and path in ("/", "/index.html"):
            body = self._dashboard_html.encode("utf-8")
            ctype = "text/html; charset=utf-8"
        elif method == "GET" and path == "/api/snapshot":
            body = json.dumps(self.snapshot_getter(),
                              ensure_ascii=False).encode("utf-8")
            ctype = "application/json; charset=utf-8"
        else:
            body = b"not found"
            ctype = "text/plain; charset=utf-8"
        resp = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n\r\n" % (ctype, len(body))
        ).encode("latin-1") + body
        conn.sendall(resp)

    def _handle_ws(self, conn, headers, path):
        if path != "/ws":
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            return
        key = headers.get("sec-websocket-key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
        conn.sendall((
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n\r\n" % accept
        ).encode("latin-1"))
        with self._lock:
            self._clients.add(conn)
        try:
            # 收到 close/ping 前持续推送最新快照
            conn.settimeout(1.0)
            while True:
                try:
                    data = conn.recv(2)
                except socket.timeout:
                    data = b""
                if data:
                    opcode = data[0] & 0x0F
                    if opcode == 0x8:  # close
                        break
                    if opcode == 0x9:  # ping -> pong
                        conn.sendall(bytes([0x8A, 0x00]))
                try:
                    conn.sendall(encode_text_frame(
                        json.dumps(self.snapshot_getter(),
                                   ensure_ascii=False)))
                except OSError:
                    break
                time.sleep(1.0)
        except OSError:
            pass
        finally:
            with self._lock:
                self._clients.discard(conn)


def run_serial():
    """串口文本输出模式：+SNIFF:AP / +SNIFF:PROBE 逐条打印。"""
    import esp32_reporter as reporter
    col = ApCollector(rssi_policy="best")
    probe_col = ProbeCollector()
    for round_no in range(3):
        channel = (1, 6, 11)[round_no % 3]
        aps, _ = parser.parse_ap_records(scan_round(round_no, channel))
        col.add_records([{"ssid": a.ssid, "bssid": a.bssid, "rssi": a.rssi,
                          "channel": a.channel, "authmode": a.authmode}
                         for a in aps])
        for ap in aps:
            print(reporter.format_serial_ap(ap), flush=True)
        for sta, ssid, rssi in demo_probes():
            probe_col.add_probe(sta, ssid, rssi)
            print(reporter.format_serial_probe(sta, ssid, rssi), flush=True)
        time.sleep(0.5)
    print("== 聚合: 信道统计 ==", flush=True)
    print(col.channel_stats(), flush=True)


def run_server(host, port):
    server = BridgeServer(host, port, snapshot_getter=lambda: build_snapshot(0))
    server.start()
    round_no = 0
    try:
        while True:
            # 数据生成线程：每秒轮转信道并生成最新快照
            snap = build_snapshot(round_no)
            round_no += 1
            server.snapshot_getter = (lambda s=snap: s)
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nbridge 已退出", flush=True)


def main():
    argp = argparse.ArgumentParser(description="ESP32 M4 数据桥（WS + HTTP + 串口）")
    argp.add_argument("--host", default="127.0.0.1")
    argp.add_argument("--port", type=int, default=8765)
    argp.add_argument("--serial", action="store_true", help="串口文本输出模式")
    argp.add_argument("--once", action="store_true", help="输出一条 JSON 快照后退出")
    argp.add_argument("--json", action="store_true", help="--once 时输出 JSON 格式")
    args = argp.parse_args()

    if args.serial:
        run_serial()
        return 0
    if args.once:
        snap = build_snapshot(0)
        if args.json:
            print(json.dumps(snap, ensure_ascii=False))
        else:
            print(json.dumps(snap, ensure_ascii=False, indent=2))
        return 0
    run_server(args.host, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
