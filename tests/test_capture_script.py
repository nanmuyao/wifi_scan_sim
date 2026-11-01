#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/capture_monitor.sh：参数检查、--dry-run 打印的命令顺序，以及用假的 iw / ip / tcpdump / nmcli 跑真流程——
正常结束、切监听模式失败、中途被 Ctrl-C 打断，三种情况退出时都要把网卡恢复回去。
没有在真实网卡上跑过；命令格式对照 iw 6.7 的帮助和 NetworkManager 手册核对过（见脚本开头的说明）。"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "tools", "capture_monitor.sh")
failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


def sh(*args, env=None, timeout=20):
    p = subprocess.run(["bash", SCRIPT] + list(args), capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, p.stdout, p.stderr


print("== 语法与参数 ==")
check(subprocess.run(["bash", "-n", SCRIPT]).returncode == 0, "bash -n：语法没问题")
rc, o, e = sh("-h")
check(rc == 0 and "--dry-run" in o and "-i IFACE" in o, "-h 打印用法")
for args, word, what in [
    ((), "缺少 -i", "不给网卡"),
    (("-i", "wlan1"), "缺少 -c", "不给信道"),
    (("-i", "wlan1", "-c", "abc"), "要是数字", "信道不是数字"),
    (("-i", "wlan1", "-c", "0"), "不在 1–233", "信道 0"),
    (("-i", "wlan1", "-c", "300"), "不在 1–233", "信道 300"),
    (("-i", "wlan1", "-c", "44", "--width", "160"), "只能是", "宽度 160 不支持"),
    (("-i", "wl;rm", "-c", "44"), "不该有的字符", "网卡名里有分号"),
    (("-i", "wlan1", "-c", "44", "-r", "0"), "大于 0", "滚动秒数 0"),
    (("-i", "wlan1", "-c", "44", "--duration", "x"), "大于 0", "时长不是数字"),
    (("-i", "wlan1", "-c", "44", "--bogus"), "不认识的参数", "不认识的参数"),
]:
    rc, o, e = sh(*args, "--dry-run")
    check(rc == 2 and word in e and not o.strip(), "%s：退出码 2，说明原因，不打印任何命令" % what)

print("== --dry-run：命令和顺序 ==")
rc, o, e = sh("-i", "wlan1", "-c", "44", "--width", "80", "-d", "/tmp/caps", "-r", "600", "--dry-run")
want = """+ nmcli device set wlan1 managed no
+ ip link set wlan1 down
+ iw dev wlan1 set type monitor
+ ip link set wlan1 up
+ iw dev wlan1 set channel 44 80MHz
+ mkdir -p /tmp/caps
+ tcpdump -i wlan1 -y IEEE802_11_RADIO -s 0 -B 16384 -n -G 600 -w /tmp/caps/cap-%Y%m%d-%H%M%S.pcap
+ ip link set wlan1 down
+ iw dev wlan1 set type managed
+ ip link set wlan1 up
+ nmcli device set wlan1 managed reset"""
check(rc == 0 and o.strip() == want, "信道 44、宽度 80：命令和顺序完全符合（最后四行是退出时的恢复）")
if o.strip() != want:
    print(o)
for width, iw_width in (("20", "HT20"), ("40+", "HT40+"), ("40-", "HT40-"), ("80", "80MHz")):
    rc, o, e = sh("-i", "w", "-c", "6", "--width", width, "--dry-run")
    check("+ iw dev w set channel 6 %s" % iw_width in o, "宽度 %s -> iw 的 %s" % (width, iw_width))
rc, o, e = sh("-i", "w", "-c", "6", "--dry-run")
check("set channel 6 80MHz" in o, "不给宽度：默认 80")
rc, o, e = sh("-i", "w", "-c", "6", "--duration", "90", "--dry-run")
check("+ timeout -s INT 90 tcpdump -i w " in o, "--duration：用 timeout -s INT 包住 tcpdump")
rc, o, e = sh("-i", "w", "-c", "6", "-r", "30", "--dry-run")
check("-G 30 " in o, "-r：滚动秒数传给 tcpdump 的 -G")
check(" -W " not in o, "不用 tcpdump 的 -W（和 -G 合用会在文件数到了就退出，不是循环覆盖）")

print("== 假命令跑真流程 ==")
tmp = tempfile.mkdtemp()
bindir = os.path.join(tmp, "bin")
os.mkdir(bindir)
log = os.path.join(tmp, "calls.log")


def stub(name, body):
    p = os.path.join(bindir, name)
    open(p, "w").write("#!/bin/bash\n" + body + "\n")
    os.chmod(p, 0o755)


stub("id", 'echo 0')
stub("iw", 'echo "iw $*" >> "$LOG"\n'
           'if [ "$3" = "info" ]; then\n'
           '  echo "Interface wlan1"; echo "\\ttype monitor"; echo "\\tchannel 44 (5220 MHz), width: 80 MHz, center1: 5210 MHz"; exit 0\nfi\n'
           '[ -n "${FAIL:-}" ] && { [ "$FAIL" = "$5" ] || [ "$FAIL" = "$4" ]; } && exit 1\nexit 0')
stub("ip", 'echo "ip $*" >> "$LOG"')
stub("nmcli", 'echo "nmcli $*" >> "$LOG"')
stub("tcpdump", 'echo "tcpdump $*" >> "$LOG"\n[ -n "${SLEEP:-}" ] && sleep "$SLEEP"\nexit 0')
base_env = dict(os.environ, PATH=bindir + ":/usr/bin:/bin", LOG=log)


def calls():
    """假命令的调用记录；`iw dev X info` 只是查询（开头检查网卡在不在、设置后核对信道），不算进顺序里。"""
    return [l.strip() for l in open(log) if not l.strip().endswith(" info")] if os.path.exists(log) else []


def fresh():
    if os.path.exists(log):
        os.remove(log)


caps = os.path.join(tmp, "caps")
fresh()
rc, o, e = sh("-i", "wlan1", "-c", "44", "-d", caps, env=base_env)
c = calls()
expect = ["nmcli device set wlan1 managed no", "ip link set wlan1 down", "iw dev wlan1 set type monitor", "ip link set wlan1 up",
          "iw dev wlan1 set channel 44 80MHz"]
check(rc == 0 and c[:5] == expect and c[-4:] == ["ip link set wlan1 down", "iw dev wlan1 set type managed", "ip link set wlan1 up",
                                                     "nmcli device set wlan1 managed reset"] and any(x.startswith("tcpdump ") for x in c),
      "正常结束：先设置、再抓包、最后恢复网卡，退出码 0")
check(os.path.isdir(caps), "抓包目录被建出来了")
check("警告" not in e, "信道和模式都对时没有警告")

fresh()
env = dict(base_env, FAIL="monitor")
rc, o, e = sh("-i", "wlan1", "-c", "44", "-d", caps, env=env)
c = calls()
check(rc == 3 and "切监听模式失败" in e, "切监听模式失败：退出码 3，说明原因")
check(not any(x.startswith("tcpdump ") for x in c), "失败时不会开始抓包")
check(c[-4:] == ["ip link set wlan1 down", "iw dev wlan1 set type managed", "ip link set wlan1 up", "nmcli device set wlan1 managed reset"],
      "失败时也把网卡恢复回去")

fresh()
env = dict(base_env, FAIL="channel")
rc, o, e = sh("-i", "wlan1", "-c", "44", "-d", caps, env=env)
check(rc == 3 and "锁定信道" in e and "iw dev wlan1 set type managed" in calls(), "锁信道失败：退出码 3，并恢复网卡")

fresh()
env = dict(base_env, SLEEP="30")
p = subprocess.Popen(["bash", SCRIPT, "-i", "wlan1", "-c", "44", "-d", caps], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                     preexec_fn=os.setsid)
for _ in range(100):
    if any(x.startswith("tcpdump ") for x in calls()):
        break
    time.sleep(0.1)
os.killpg(p.pid, signal.SIGINT)                 # 终端里按 Ctrl-C：信号发给整个前台进程组
try:
    p.communicate(timeout=15)
except subprocess.TimeoutExpired:
    p.kill()
    p.communicate()
c = calls()
check(p.returncode == 130, "Ctrl-C：退出码 130（实际 %s）" % p.returncode)
check(c[-4:] == ["ip link set wlan1 down", "iw dev wlan1 set type managed", "ip link set wlan1 up", "nmcli device set wlan1 managed reset"],
      "Ctrl-C 之后也把网卡恢复回去")

if shutil.which("timeout"):
    fresh()
    env = dict(base_env, SLEEP="30")
    t0 = time.time()
    rc, o, e = sh("-i", "wlan1", "-c", "44", "-d", caps, "--duration", "1", env=env, timeout=25)
    check(rc == 0 and time.time() - t0 < 10 and "iw dev wlan1 set type managed" in calls(), "--duration 1：到点自动停止，退出码 0（timeout 的 124 不算错误），并恢复网卡")
else:
    print("  [SKIP] 没有 timeout 命令（macOS）：--duration 的真实运行只在 Linux 上测")

fresh()
userbin = os.path.join(tmp, "userbin")
os.mkdir(userbin)
open(os.path.join(userbin, "id"), "w").write("#!/bin/bash\necho 1000\n")
os.chmod(os.path.join(userbin, "id"), 0o755)
rc, o, e = sh("-i", "nope", "-c", "44", env=dict(base_env, PATH=userbin + ":/usr/bin:/bin"))
check(rc == 2 and "要用 root" in e, "不是 root：退出码 2，说明要用 root，不动网卡")
shutil.rmtree(tmp)

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
