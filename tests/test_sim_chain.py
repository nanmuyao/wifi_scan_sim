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
  4. 解析固件的调试串口输出，与期望的 AP 列表逐项比对
同一份固件按 SCENARIOS 表跑多遍：除了「模拟器永远完美应答」的基线，还有回显、
噪声行、逐字节分片、ERROR、无应答、超长响应、AP 数超过上限、FAIL 收尾等故障注入
（故障由 esp8266_sim.ESP8266Sim 的 faults 参数产生，harness 与固件代码不变）。

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


def run_firmware(exe, outdir, faults=None):
    """起 pty + 模拟器，跑 harness，返回 (退出码, 标准输出文本)。"""
    master, slave, slave_name = simmod.setup_pty()
    sim = simmod.ESP8266Sim(master, faults)
    out_path = os.path.join(outdir, "fw_stdout_%d.txt" % time.monotonic_ns())
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


MANY_APS = [(3, "Many-%02d" % i, -40 - i, "aa:bb:cc:00:00:%02x" % i, 1 + i % 11)
            for i in range(20)]
MAX_AP_T = 16   # main.c 里单次扫描最多保存的 AP 数


def ap_tuples(aps):
    return [(ch, rssi, enc, ssid) for (enc, ssid, rssi, _mac, ch) in aps]


FULL = ap_tuples(simmod.FAKE_APS)
NONE = []   # 这一轮没有 AP，固件应打印 "scan timeout"

# (名称, 故障注入, 三轮期望, 已知问题说明)。期望为 None 的轮不检查 AP。
# 已知问题：场景按「应有的行为」写期望，固件目前不满足时填说明 -> 报 XFAIL 不算失败；
# 一旦固件修好变成 XPASS，会提示去掉标记。目前没有已知问题。
SCENARIOS = [
    ("baseline 完美应答", {}, [FULL] * 3, None),
    ("回显 + 无关噪声行（ATE1 / ready / busy p...）",
     {"echo": True, "noise": True}, [FULL] * 3, None),
    ("逐字节分片到达（chunk=1，OK 行被拆在多次回调里）",
     {"chunk": 1}, [FULL] * 3, None),
    ("第 1 次 CWLAP 回 ERROR，之后恢复",
     {"cwlap": ["error"]}, [NONE, FULL, FULL], None),
    ("第 1 次 CWLAP 无应答（5s 超时），之后恢复",
     {"cwlap": ["silent"]}, [NONE, FULL, FULL], None),
    ("第 1 次响应超过 4096 字节接收缓冲，之后恢复",
     {"cwlap": ["oversize"]}, [NONE, FULL, FULL], None),
    ("20 个 AP，固件只保存前 %d 个、不越界" % MAX_AP_T,
     {"aps": MANY_APS}, [ap_tuples(MANY_APS)[:MAX_AP_T]] * 3, None),
    ("第 1 次以 FAIL 收尾且前面行里有 SSID \"OK-Cafe\"，应判失败",
     {"cwlap": ["fail"]}, [NONE, FULL, FULL], None),
]


def split_rounds(text):
    """按 '--- scan ---' 分段，返回每轮 (AP 元组列表, 是否打印了 scan timeout)。"""
    rounds = []
    for seg in text.split("--- scan ---")[1:]:
        got = []
        for line in seg.splitlines():
            mm = LINE_RE.match(line.strip())
            if mm:
                got.append((int(mm.group(2)), int(mm.group(3)),
                            int(mm.group(4)), mm.group(5)))
        rounds.append((got, "scan timeout" in seg))
    return rounds


def run_scenario(exe, tmp, name, faults, expect_rounds):
    """跑一个场景，返回 [(是否通过, 说明)]。"""
    results = []

    def check(ok, msg):
        results.append((ok, msg))

    code, text = run_firmware(exe, tmp, faults)
    check(code == 0, "固件正常退出（退出码 %s）" % code)
    check("HARNESS TIMEOUT" not in text, "没有触发看门狗超时")
    m = re.search(r"HARNESS scans=(\d+) overruns=(\d+)", text)
    check(m is not None, "harness 输出了汇总行")
    if m:
        check(int(m.group(1)) == SCAN_TARGET, "完成 %d 轮扫描" % SCAN_TARGET)
        check(int(m.group(2)) == 0,
              "接收中断无溢出（overruns=%s，非 0 表示字节到达时回调还没重挂接收）"
              % m.group(2))
    rounds = split_rounds(text)
    check(len(rounds) == SCAN_TARGET, "固件调试串口有 %d 段扫描输出" % SCAN_TARGET)
    for i, ((got, timed_out), expect) in enumerate(zip(rounds, expect_rounds), 1):
        if expect == NONE:
            check(got == [] and timed_out,
                  "第 %d 轮失败被正确处理：没有 AP、打印 scan timeout（实际 %d 个 AP，timeout=%s）"
                  % (i, len(got), timed_out))
        else:
            check(got == expect and not timed_out,
                  "第 %d 轮 %d 个 AP 的信道/RSSI/加密/SSID 全部一致（实际 %d 个，timeout=%s）"
                  % (i, len(expect), len(got), timed_out))
    return results, text


def main():
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        print("== 编译 harness（真实 main.c + HAL 桩）==")
        exe = build(tmp)
        for name, faults, expect_rounds, known in SCENARIOS:
            print("\n== 场景：%s ==" % name)
            results, text = run_scenario(exe, tmp, name, faults, expect_rounds)
            bad = [msg for ok, msg in results if not ok]
            for ok, msg in results:
                tag = "PASS" if ok else ("XFAIL" if known else "FAIL")
                print("  [%s] %s" % (tag, msg))
            if known and not bad:
                print("  [XPASS] 已知问题已修复，请去掉该场景的已知问题标记")
                failures.append("%s: XPASS" % name)
            elif known:
                print("  已知问题：%s" % known)
            elif bad:
                print("  ---- 固件输出 ----\n" + text)
                failures += ["%s: %s" % (name, m) for m in bad]

    print("\n结果: %s（%d 项失败）"
          % ("全部通过" if not failures else "存在失败", len(failures)))
    for f in failures:
        print("  - " + f)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
