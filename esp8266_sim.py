#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ESP8266 AT 固件模拟器（虚拟串口）
==================================
在无硬件环境下仿真 ESP8266 模块，用于开发/测试 STM32 WiFi 扫描代码。

原理：
  - 用 pty 创建一对虚拟串口（master / slave）
  - 本程序绑定 master 端，扮演 ESP8266（AT 固件）
  - slave 端路径打印出来，供 STM32 程序或串口工具连接

用法：
  python3 esp8266_sim.py             # 自动演示：模拟器 + 客户端全流程
  python3 esp8266_sim.py --manual    # 手动模式：只起模拟器，等外部串口工具连接

支持的 AT 命令（与真实模块对齐）：
  AT                 -> OK
  AT+CWMODE=1        -> OK                  (Station 模式)
  AT+CWLAP           -> +CWLAP:(...) x N  + OK
  其它               -> ERROR
"""

import os
import pty
import sys
import time
import argparse
import select
import termios

# ---------------------------------------------------------------------------
# 预置的虚拟 AP 数据: (加密方式, SSID, RSSI, MAC, 信道)
# enc: 0=开放 1=WEP 2=WPA 3=WPA2 4=WPA/WPA2
# ---------------------------------------------------------------------------
FAKE_APS = [
    (3, "Paul-Home-2.4G",  -38, "a4:83:e7:11:22:02", 6),
    (3, "Paul-Home-5G",    -42, "a4:83:e7:11:22:01", 149),
    (4, "iPhone-13",       -55, "3c:06:30:ab:cd:ef", 1),
    (2, "Office_WPA",      -61, "00:1f:33:44:55:66", 11),
    (0, "",                -70, "e8:28:ca:77:88:99", 3),   # 隐藏 SSID
    (3, "Xiaomi_Router",   -47, "44:9b:b8:aa:bb:cc", 13),
    (4, "TP-LINK_5G",      -66, "6c:e8:73:12:34:56", 157),
    (3, "CMCC-EDU",        -58, "f0:03:f3:99:aa:bb", 1),
]

# ---------------------------------------------------------------------------
# 预置的虚拟 Probe Request（阶段 2 嗅探扩展）
# 真实场景：手机/笔记本主动扫描网络时发出 Probe Request，
#   定向探测带目标 SSID，广播探测 SSID 为空（找所有网络）。
# 字段: (SSID, STA MAC, RSSI)
# ---------------------------------------------------------------------------
FAKE_PROBES = [
    ("iPhone-13",        "3c:06:30:ab:cd:ef", -55),   # 定向：找自己的热点
    ("",                 "3c:06:30:ab:cd:ef", -52),   # 同一台手机广播探测
    ("Paul-Home-2.4G",   "9a:8b:7c:6d:5e:4f", -63),
    ("CoffeeShop",       "22:33:44:55:66:77", -71),
    ("",                 "aa:bb:cc:dd:ee:ff", -48),   # 广播探测
    ("Xiaomi_Router",    "9a:8b:7c:6d:5e:4f", -60),
]


class ESP8266Sim:
    """模拟 ESP8266 AT 固件行为。"""

    def __init__(self, fd):
        self.fd = fd
        self.buf = b""
        self.scan_count = 0
        # 阶段 2 嗅探仿真状态
        self.sniff_enabled = False
        self._sniff_idx = 0
        self._last_emit = 0.0
        self._sniff_interval = 0.35   # 真实 promiscuous 回调异步高频，压频便于演示

    def _send(self, data):
        """统一写响应：兼容 str / bytes，避免 os.write 类型错误。"""
        if isinstance(data, str):
            data = data.encode("utf-8")
        os.write(self.fd, data)

    def _handle_line(self, line: bytes):
        cmd = line.strip().decode("utf-8", "ignore")
        if cmd == "AT":
            self._send(b"OK\r\n")
        elif cmd.startswith("AT+CWMODE"):
            self._send(b"OK\r\n")
        elif cmd == "AT+CWLAP":
            self.scan_count += 1
            for ap in FAKE_APS:
                enc, ssid, rssi, mac, ch = ap
                # 与真实模块输出格式完全一致
                self._send('+CWLAP:(%d,"%s",%d,"%s",%d)\r\n'
                           % (enc, ssid, rssi, mac, ch))
            self._send(b"OK\r\n")
        elif cmd.startswith("AT+CWSNIFF"):
            # 阶段 2：promiscuous 嗅探开关（仿真扩展命令）
            arg = cmd.split("=", 1)[1].strip() if "=" in cmd else ""
            if arg == "1":
                self.sniff_enabled = True
                self._sniff_idx = 0
                self._last_emit = 0.0
                self._send(b"OK\r\n")
            elif arg == "0":
                self.sniff_enabled = False
                self._send(b"OK\r\n")
            else:
                self._send(b"ERROR\r\n")
        else:
            self._send(b"ERROR\r\n")

    def _emit_probe_if_due(self):
        """嗅探模式下按时间间隔推送一条 Probe Request 报告（主动上报）。

        真实 ESP8266 promiscuous 回调不依赖主机命令，抓到帧即触发；
        仿真中以时间驱动轮换 FAKE_PROBES，格式：
            +SNIFF:PROBE,"<SSID>",<STA MAC>,<RSSI>
        """
        if not self.sniff_enabled:
            return
        now = time.time()
        if now - self._last_emit < self._sniff_interval:
            return
        self._last_emit = now
        ssid, mac, rssi = FAKE_PROBES[self._sniff_idx % len(FAKE_PROBES)]
        self._sniff_idx += 1
        # 空 SSID 表示广播探测（未指定目标网络），与真实抓包语义一致
        name = ssid if ssid else "<broadcast>"
        self._send('+SNIFF:PROBE,"%s",%s,%d\r\n' % (name, mac, rssi))

    def poll(self):
        """非阻塞读取 master 端，按行处理命令。

        嗅探事件异步推送不依赖主机输入，因此每次 poll 先执行推送，
        再处理输入；避免无输入时过早 return 导致 probe 永远不发出。
        """
        self._emit_probe_if_due()
        try:
            r, _, _ = select.select([self.fd], [], [], 0)
            if not r:
                return
            data = os.read(self.fd, 256)
            if not data:
                return
            self.buf += data
        except (OSError, select.error):
            return
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            try:
                self._handle_line(line)
            except Exception as exc:   # 线程内异常若吞掉将导致模拟器静默死亡
                print("[sim] ERROR: line=%r exc=%r" % (line, exc),
                      file=sys.stderr)


def setup_pty():
    """创建虚拟串口对，并设为 raw 模式。

    raw 模式（cfmakeraw）至关重要：真实 UART 是纯字节流，没有终端行规程。
    若保留默认 canonical 模式，行规程会把 \\r\\n 转成 \\n（ICRNL/ONLCR），
    且按行缓冲（MAX_CANON）导致长响应丢数据——仿真结果将与真实串口不符。
    """
    master, slave = os.openpty()
    attrs = termios.tcgetattr(slave)
    try:
        termios.cfmakeraw(attrs)          # Python 3.5+ 提供
    except AttributeError:
        # 手动等效设置：关闭 ICANON / ECHO / ICRNL / OPOST 等
        iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attrs
        iflag &= ~(termios.ICRNL | termios.IGNCR | termios.INLCR)
        oflag &= ~termios.OPOST
        lflag &= ~(termios.ICANON | termios.ECHO | termios.ECHONL
                   | termios.ISIG | termios.IEXTEN)
        cflag &= ~(termios.CSIZE | termios.PARENB)
        cflag |= termios.CS8
        attrs = [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]
    termios.tcsetattr(slave, termios.TCSANOW, attrs)
    return master, slave, os.ttyname(slave)


# ---------------------------------------------------------------------------
# 自动演示模式：客户端线程扮演 STM32，发 AT 命令并解析 CWLAP
# ---------------------------------------------------------------------------
def demo_client(master_fd, slave_fd):
    """模拟 STM32 侧行为：握手 -> 设 Station 模式 -> 循环扫描解析。

    注意：单线程内交替执行「模拟器 poll」与「slave 读」，不使用独立模拟器线程。
    macOS 上双线程分别 select pty 的 master/slave 端时，master 写入的数据
    无法唤醒 slave 端的 select（已验证），单线程复用则完全正常。
    """
    sim = ESP8266Sim(master_fd)
    f = os.fdopen(os.dup(slave_fd), "rb+", buffering=0)
    buf = b""

    def send(cmd):
        f.write(cmd)
        time.sleep(0.2)  # 模拟模块处理时间

    def read_until(expect, timeout=3.0):
        nonlocal buf
        start = time.time()
        while time.time() - start < timeout:
            sim.poll()          # 模拟器读命令、写响应
            if expect.encode() in buf:
                return True
            r, _, _ = select.select([f], [], [], 0)
            if r:
                data = f.read(512)
                if data:
                    buf += data
                    print("[dbg] read %d bytes: %r" % (len(data), data[:120]),
                          file=sys.stderr)
        return False

    def parse_cwlap(data: bytes):
        """与 STM32 端 C 代码等价的解析逻辑（Python 参考实现）。

        手写状态机逐字段解析，与 C 版 ap_parser.c 行为对齐：
          - 支持空 SSID
          - 支持转义字符（\\, \\"）
        """
        aps = []
        for line in data.decode("utf-8", "ignore").splitlines():
            line = line.strip()
            if not line.startswith("+CWLAP:"):
                continue
            body = line[len("+CWLAP:"):].strip()
            if not (body.startswith("(") and body.endswith(")")):
                continue
            inner = body[1:-1]
            n = len(inner)
            p = 0

            def read_int():
                nonlocal p
                start = p
                while p < n and inner[p] != ",":
                    p += 1
                val = int(inner[start:p].strip())
                if p < n and inner[p] == ",":
                    p += 1
                return val

            def read_str():
                nonlocal p
                while p < n and inner[p].isspace():
                    p += 1
                if p >= n or inner[p] != '"':
                    raise ValueError
                p += 1
                out = []
                while p < n:
                    c = inner[p]
                    if c == "\\" and p + 1 < n and inner[p + 1] in ('"', ","):
                        out.append(inner[p + 1])
                        p += 2
                        continue
                    if c == '"':
                        p += 1
                        break
                    out.append(c)
                    p += 1
                if p < n and inner[p] == ",":
                    p += 1
                return "".join(out)

            try:
                enc = read_int()
                ssid = read_str()
                rssi = read_int()
                mac = read_str()
                ch = read_int()
                aps.append((enc, ssid, rssi, mac, ch))
            except (ValueError, IndexError):
                continue
        return aps

    # 1. 握手
    send(b"AT\r\n")
    ok = read_until("OK")
    print("[STM32] AT            -> %s" % ("OK" if ok else "TIMEOUT"))

    # 2. 设置 Station 模式
    send(b"AT+CWMODE=1\r\n")
    ok = read_until("OK")
    print("[STM32] AT+CWMODE=1   -> %s" % ("OK" if ok else "TIMEOUT"))

    # 3. 连续扫描 3 次
    for i in range(3):
        buf = b""          # 清空缓冲，只收集本次 CWLAP 响应
        send(b"AT+CWLAP\r\n")
        ok = read_until("OK", timeout=5.0)
        if not ok:
            print("[STM32] scan #%d -> TIMEOUT" % (i + 1))
            continue
        resp = buf.replace(b"\r\nOK", b"", 1)   # 去掉末尾的 OK 行
        aps = parse_cwlap(resp)
        print("\n[STM32] scan #%d: 发现 %d 个 AP" % (i + 1, len(aps)))
        for idx, (enc, ssid, rssi, mac, ch) in enumerate(aps):
            name = ssid if ssid else "<hidden>"
            print("  [%02d] ch=%-3d rssi=%-4d enc=%d  %-16s %s"
                  % (idx, ch, rssi, enc, name, mac))
        time.sleep(0.5)

    print("\n[demo] 完成：STM32 侧完整扫描链路已在无硬件环境下跑通")


def sniffer_demo():
    """阶段 2 演示：promiscuous 嗅探 Probe Request 并打印 SSID/MAC/RSSI 报告。

    模拟真实 ESP8266 promiscuous 回调：模块抓包后**主动**上报（无需主机
    逐条查询）。演示流程：
      1. 开启嗅探 AT+CWSNIFF=1
      2. 模拟器按间隔自动推送 +SNIFF:PROBE,... 报告
      3. 收到 6 条后关闭嗅探 AT+CWSNIFF=0
    同步打印到 stdout，便于直接验收输出格式。
    """
    print("[sniffer-demo] 阶段2：仿真 ESP8266 promiscuous 嗅探 Probe Request")
    master_fd, slave_fd, slave_name = setup_pty()
    sim = ESP8266Sim(master_fd)
    f = os.fdopen(os.dup(slave_fd), "rb+", buffering=0)

    def send(cmd):
        f.write(cmd)
        time.sleep(0.2)   # 模拟模块处理时间

    reports = []
    try:
        send(b"AT+CWSNIFF=1\r\n")
        deadline = time.time() + 8.0   # 6 条 * 0.35s，留足余量
        while len(reports) < len(FAKE_PROBES) and time.time() < deadline:
            sim.poll()
            # 模拟器响应写 master 端，从 slave 端（f）读取（与 demo_client 一致）
            r, _, _ = select.select([f], [], [], 0)
            if r:
                chunk = f.read(4096)
                if chunk:
                    for raw in chunk.split(b"\r\n"):
                        line = raw.strip()
                        if line.startswith(b"+SNIFF:PROBE,"):
                            text = line.decode("ascii", "replace")
                            if text not in reports:
                                reports.append(text)
                                print("  " + text)
            time.sleep(0.02)
        send(b"AT+CWSNIFF=0\r\n")
        print("\n[sniffer-demo] Probe 报告汇总：%d 条（含定向探测与广播探测）"
              % len(reports))
        for text in reports:
            print("  " + text)
        print("[sniffer-demo] 完成：无硬件环境下已可观察 Probe 嗅探链路")
    finally:
        f.close()
        os.close(master_fd)
        os.close(slave_fd)
        _ = slave_name   # 演示不需要手动连接 slave 端


def main():
    parser = argparse.ArgumentParser(description="ESP8266 AT 固件模拟器")
    parser.add_argument("--manual", action="store_true",
                        help="手动模式：只起模拟器，不运行演示客户端")
    parser.add_argument("--sniffer-demo", action="store_true",
                        help="嗅探演示：仿真 promiscuous 抓 Probe Request 并输出报告")
    args = parser.parse_args()

    if args.sniffer_demo:
        sniffer_demo()
        return

    master, slave, slave_name = setup_pty()
    print("=" * 60)
    print("[sim] ESP8266 AT 固件模拟器已启动")
    print("[sim] 虚拟串口 (slave) : %s" % slave_name)
    print("[sim] 预置虚拟 AP 数量 : %d" % len(FAKE_APS))
    print("=" * 60)

    sim = ESP8266Sim(master)

    if args.manual:
        print("[sim] 手动模式：请用串口工具连接 %s 交互测试" % slave_name)
        try:
            while True:
                sim.poll()
                time.sleep(0.01)
        except KeyboardInterrupt:
            print("\n[sim] 已退出")
    else:
        # 自动演示：单线程内交替驱动模拟器与客户端（见 demo_client 注释）
        try:
            demo_client(master, slave)
        finally:
            os.close(master)
            os.close(slave)
        print("\n[demo] 演示结束，可加 --manual 手动交互测试")


if __name__ == "__main__":
    main()
