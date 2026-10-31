#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
仿真接收链路测试：真实固件接收代码 <-> pty 虚拟串口 <-> esp8266_sim.py

被测对象是 stm32_project/Core/Src/main.c 里的真实代码（接收回调、esp_wait、
parse_cwlap、print_aps），由 tests/sim_chain/harness.c 以一层 HAL 桩编译到 PC 上。
本脚本负责：
  1. 编译 harness
  2. 创建 pty，让 esp8266_sim.ESP8266Sim 扮演 ESP8266
  3. 启动 harness，等它扫满 3 轮后退出
  4. 解析固件的调试串口输出，与 FAKE_APS 逐项比对

退出码 0 = 全部通过。在 Docker 里跑：bash tests/sim_chain/run.sh
"""
import os
import re
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import esp8266_sim as simmod  # noqa: E402

SCAN_TARGET = 3
RUN_TIMEOUT_S = 40

LINE_RE = re.compile(
    r"^\[(\d+)\] ch=(\d+)\s+rssi=(-?\d+)\s+enc=(\d+)\s+ssid=(.*)$")


def build(outdir):
    exe = os.path.join(outdir, "harness")
    cmd = ["gcc", "-Wall", "-Wextra", "-O1",
           "-I", os.path.join(ROOT, "tests/sim_chain/stub"),
           "-I", os.path.join(ROOT, "stm32_project/Core/Inc"),
           "-o", exe,
           os.path.join(ROOT, "tests/sim_chain/harness.c"),
           os.path.join(ROOT, "stm32_project/Core/Src/ap_parser.c"),
           "-lpthread"]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout + r.stderr)
        sys.exit("编译 harness 失败")
    if r.stderr.strip():
        print("[build] 编译告警:\n" + r.stderr)
    return exe


def run_firmware(exe, outdir):
    """起 pty + 模拟器，跑 harness，返回 (退出码, 标准输出文本)。"""
    master, slave, slave_name = simmod.setup_pty()
    sim = simmod.ESP8266Sim(master)
    out_path = os.path.join(outdir, "fw_stdout.txt")
    with open(out_path, "wb") as out:
        proc = subprocess.Popen([exe, slave_name], stdout=out,
                                stderr=subprocess.STDOUT)
        deadline = time.time() + RUN_TIMEOUT_S
        try:
            while proc.poll() is None:
                sim.poll()
                if time.time() > deadline:
                    proc.kill()
                    break
                time.sleep(0.0005)
        finally:
            os.close(master)
            os.close(slave)
    with open(out_path, encoding="utf-8", errors="replace") as f:
        return proc.returncode, f.read()


def main():
    failures = []

    def check(ok, msg):
        print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
        if not ok:
            failures.append(msg)

    with tempfile.TemporaryDirectory() as tmp:
        print("== 编译 harness（真实 main.c + HAL 桩）==")
        exe = build(tmp)
        print("== 运行固件，连接 esp8266_sim 虚拟串口 ==")
        code, text = run_firmware(exe, tmp)

    print(text)
    print("== 校验 ==")
    check(code == 0, "固件正常退出（退出码 %s）" % code)
    check("HARNESS TIMEOUT" not in text, "没有触发看门狗超时")
    check("scan timeout" not in text, "没有出现 esp_wait 扫描超时")

    m = re.search(r"HARNESS scans=(\d+) overruns=(\d+)", text)
    check(m is not None, "harness 输出了汇总行")
    if m:
        check(int(m.group(1)) == SCAN_TARGET, "完成 %d 轮扫描" % SCAN_TARGET)
        check(int(m.group(2)) == 0,
              "接收中断无溢出（overruns=%s，非 0 表示回调重挂前来了字节）"
              % m.group(2))

    # 按 "--- scan ---" 分段，逐轮比对
    rounds = text.split("--- scan ---")[1:]
    check(len(rounds) == SCAN_TARGET, "固件调试串口有 %d 段扫描输出" % SCAN_TARGET)
    expect = [(ch, rssi, enc, ssid)
              for (enc, ssid, rssi, _mac, ch) in simmod.FAKE_APS]
    for i, seg in enumerate(rounds, 1):
        got = []
        for line in seg.splitlines():
            mm = LINE_RE.match(line.strip())
            if mm:
                got.append((int(mm.group(2)), int(mm.group(3)),
                            int(mm.group(4)), mm.group(5)))
        check(len(got) == len(expect),
              "第 %d 轮解析出 %d 个 AP（期望 %d）" % (i, len(got), len(expect)))
        check(got == expect, "第 %d 轮 8 个 AP 的信道/RSSI/加密/SSID 全部一致" % i)
        if got != expect:
            for g, e in zip(got, expect):
                if g != e:
                    print("      差异: got=%r expect=%r" % (g, e))

    print("\n结果: %s（%d 项失败）"
          % ("全部通过" if not failures else "存在失败", len(failures)))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
