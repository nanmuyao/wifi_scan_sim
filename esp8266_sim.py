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


class ESP8266Sim:
    """模拟 ESP8266 AT 固件行为。"""

    def __init__(self, fd):
        self.fd = fd
        self.buf = b""
        self.scan_count = 0

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
        else:
            self._send(b"ERROR\r\n")

    def poll(self):
        """非阻塞读取 master 端，按行处理命令。"""
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


def main():
    parser = argparse.ArgumentParser(description="ESP8266 AT 固件模拟器")
    parser.add_argument("--manual", action="store_true",
                        help="手动模式：只起模拟器，不运行演示客户端")
    args = parser.parse_args()

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
