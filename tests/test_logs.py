#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""logs80211：级别、日志文件、运行头、十六进制遮蔽、--redact、重复 setup；report 命令行的日志行为（默认写文件、--no-log-file、内部错误的退出码 70 和日志里的堆栈）。"""
import io
import logging
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wifi80211 import logs  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


tmp = tempfile.mkdtemp()
log = logging.getLogger("wifi80211.testmod")

print("== 级别与输出位置 ==")
buf = io.StringIO()
path = os.path.join(tmp, "a.log")
check(logs.setup("warning", path, stream=buf) == path, "setup 返回日志文件路径")
log.debug("细节 d")
log.info("阶段 i")
log.warning("警告 w")
logs.trace(log, "逐帧 t")
for h in logging.getLogger("wifi80211").handlers:
    h.flush()
text = open(path, encoding="utf-8").read()
check("警告 w" in buf.getvalue() and "阶段 i" not in buf.getvalue() and "细节 d" not in buf.getvalue(), "屏幕：级别 warning 只出警告以上")
check("细节 d" in text and "阶段 i" in text and "警告 w" in text and "逐帧 t" not in text, "文件：固定记到 debug，TRACE 不记")
check(re.search(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} WARNING wifi80211\.testmod: 警告 w$", text, re.M) is not None, "文件的格式：时间、级别、模块名、消息")
logs.setup("trace", path, stream=buf)
logs.trace(log, "逐帧 %s", "t2")
for h in logging.getLogger("wifi80211").handlers:
    h.flush()
check("逐帧 t2" in open(path, encoding="utf-8").read(), "级别 trace：文件里有逐帧")
logs.setup("error", None, stream=buf)
check(len([h for h in logging.getLogger("wifi80211").handlers if getattr(h, "_wifi80211", False)]) == 1, "重复 setup：旧的处理器被去掉，不会重复输出（没有文件时只剩屏幕）")
check(logging.getLogger("wifi80211").propagate is False, "不向根日志传播（不会被别的库的配置重复输出）")

buf = io.StringIO()
path = os.path.join(tmp, "f.log")
logs.setup("warning", path, stream=buf)
log.warning("只进文件 %s", "x", extra={"file_only": True})
log.warning("屏幕和文件都有")
for h in logging.getLogger("wifi80211").handlers:
    h.flush()
text = open(path, encoding="utf-8").read()
check("只进文件" in text and "只进文件" not in buf.getvalue() and "屏幕和文件都有" in buf.getvalue() and "屏幕和文件都有" in text, "file_only 的记录只进日志文件，屏幕上不重复（给人看的提示已经另外打印过）")

print("== 兜底遮蔽与 --redact ==")
buf = io.StringIO()
path = os.path.join(tmp, "b.log")
logs.setup("info", path, stream=buf)
key = "0123456789abcdef0123456789abcdef"
log.info("PTK 是 %s，随机数 %s，指纹 %s，字节 %s", key, "ab" * 31, "deadbeefcafebabe", "ff" * 16)
for h in logging.getLogger("wifi80211").handlers:
    h.flush()
text = open(path, encoding="utf-8").read() + buf.getvalue()
check(key not in text and "ab" * 31 not in text and "ff" * 16 not in text, "16 字节以上的十六进制串在屏幕和文件里都被遮掉")
check("<hex 16B>" in text and "<hex 31B>" in text and "deadbeefcafebabe" in text, "遮成 <hex NB>；短的（8 字节指纹）保留")
buf = io.StringIO()
path = os.path.join(tmp, "c.log")
logs.setup("info", path, redact=True, stream=buf)
log.info("设备 AA:BB:CC:00:11:22 访问 www.example.com（203.0.113.5），又是 aa:bb:cc:00:11:22")
for h in logging.getLogger("wifi80211").handlers:
    h.flush()
text = open(path, encoding="utf-8").read()
check("AA:BB" not in text and "aa:bb" not in text and "example.com" not in text and "203.0.113.5" not in text, "--redact：MAC、域名、IP 都不出现")
tags = re.findall(r"mac-[0-9a-f]{6}", text)
check(len(tags) == 2 and tags[0] == tags[1], "同一个 MAC（大小写不同）得到同一个标记，看得出是同一台")
check(re.search(r"name-[0-9a-f]{6}", text) and re.search(r"ip-[0-9a-f]{6}", text), "域名和 IP 也有标记")
check("wifi80211.testmod" in text, "模块名不被当成域名遮掉")
logs.setup("info", None, redact=True)
rf = logs.RedactFilter(salt="s")
check(rf.tag("mac", "x") == logs.RedactFilter(salt="s").tag("mac", "x") != logs.RedactFilter(salt="t").tag("mac", "x"), "标记由盐决定：同盐同值同标记，换盐就变")

print("== 运行头 ==")
buf = io.StringIO()
path = os.path.join(tmp, "d.log")
logs.setup("info", path, stream=buf)
f = os.path.join(tmp, "in.bin")
open(f, "wb").write(b"x" * 5000)
logs.run_header(log, ["--keys", "k.txt", f], [f, os.path.join(tmp, "missing")])
for h in logging.getLogger("wifi80211").handlers:
    h.flush()
text = open(path, encoding="utf-8").read()
size, fp = logs.fingerprint(f)
check("wifi80211 0.1.0" in text and "Python " in text and "参数：--keys k.txt" in text and "5000 字节" in text and fp in text, "运行头：版本、Python、系统、参数、输入文件大小和指纹")
check("读不了" in text and logs.fingerprint(os.path.join(tmp, "missing")) == (None, None), "输入文件读不了：记「读不了」，不抛异常")
check(logs.fingerprint(f, limit=10)[1] != fp and logs.fingerprint(f)[1] == fp, "指纹只看前 limit 字节，同样的文件得到同样的值")
check(logs.default_log_path().startswith("wifi80211-") and logs.default_log_path().endswith(".log"), "默认日志文件名")

print("== report 命令行 ==")
env = dict(os.environ, PYTHONPATH=ROOT)


def cli(*args, cwd=None):
    p = subprocess.run([sys.executable, "-m", "wifi80211.report"] + list(args), capture_output=True, text=True, env=env, cwd=cwd or tmp)
    return p.returncode, p.stdout, p.stderr


work = tempfile.mkdtemp()
rc, o, e = cli("--help", cwd=work)
check(rc == 0 and "--log-level" in o and "--redact" in o, "--help 列出日志参数")
rc, o, e = cli("/nonexistent.pcap", "--keys", "/nonexistent.txt", cwd=work)
logs_found = [x for x in os.listdir(work) if x.startswith("wifi80211-") and x.endswith(".log")]
check(rc == 2 and len(logs_found) >= 1 and "日志文件：" in e, "出错时也写了日志文件，并告诉你路径（出错的时候最需要它）")
check(e.count("读不了密钥文件") == 1, "错误提示在屏幕上只出现一次")
text = open(os.path.join(work, logs_found[0]), encoding="utf-8").read()
check("wifi80211 0.1.0" in text and "参数：/nonexistent.pcap" in text, "日志里有运行头和参数")
work2 = tempfile.mkdtemp()
rc, o, e = cli("/nonexistent.pcap", "--keys", "/nonexistent.txt", "--no-log-file", cwd=work2)
check(os.listdir(work2) == [] and "日志文件：" not in e, "--no-log-file：不写文件")
rc, o, e = cli("/nonexistent.pcap", "--keys", "/nonexistent.txt", "--log-file", os.path.join(work2, "x", "no.log"), cwd=work2)
check(rc == 2 and "日志文件写不了" in e, "日志文件写不了（目录不存在）：只警告，不影响报告命令本身")
code = "import sys; sys.argv=['r']; from wifi80211 import report, capture; capture.read_capture=lambda p: 1/0; sys.exit(report.main(['%s','--keys','%s']))"
kf = os.path.join(tmp, "k.txt")
open(kf, "w").write('"wpa-pwd","SuperSecretPassphrase"\n')
work3 = tempfile.mkdtemp()
p = subprocess.run([sys.executable, "-c", code % (f, kf)], capture_output=True, text=True, env=env, cwd=work3)
lf = [x for x in os.listdir(work3) if x.endswith(".log")]
body = open(os.path.join(work3, lf[0]), encoding="utf-8").read() if lf else ""
check(p.returncode == 70 and "内部错误" in p.stderr and lf and "ZeroDivisionError" in body and "Traceback" in body, "没料到的异常：退出码 70，告诉你日志路径，堆栈写进日志")
check("SuperSecretPassphrase" not in body and "SuperSecretPassphrase" not in p.stderr and "SuperSecretPassphrase" not in p.stdout, "密钥文件里的口令不会出现在日志和屏幕上")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
