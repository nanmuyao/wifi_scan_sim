# -*- coding: utf-8 -*-
"""
日志：库里每个模块用标准的 logging.getLogger(__name__)（名字是 wifi80211.xxx），不自己配置；命令行（report）调用 setup() 装上处理器。纯标准库。
规范见 docs/日志规范.md。要点：
  - 级别：ERROR 做不下去；WARNING 结果可能不对（有帧没解开、文件被截断）；INFO 每个阶段的结论和数字；DEBUG 每个决定的理由（握手怎么配对、MIC 为什么不对、帧为什么没解开，按原因汇总的计数）；
    TRACE（5）逐帧，量很大，只在定位具体某一帧时开。
  - 密钥、口令、PMK / PTK / KCK / KEK / TK / GTK / WEP 密钥永远不进日志；setup() 装的过滤器还会把任何 16 字节以上的十六进制串遮成 <hex NB> 兜底。
  - 默认每次运行写一个 wifi80211-时间.log（DEBUG 级别，带运行头：版本、系统、参数、输入文件大小和指纹），出了问题把它发给我就够了。
"""
import datetime
import hashlib
import logging
import os
import platform
import re
import sys

TRACE = 5
logging.addLevelName(TRACE, "TRACE")
LEVELS = {"error": logging.ERROR, "warning": logging.WARNING, "info": logging.INFO, "debug": logging.DEBUG, "trace": TRACE}
ROOT = "wifi80211"
HEX_RUN = re.compile(r"(?<![0-9A-Za-z])([0-9a-fA-F]{32,})(?![0-9A-Za-z])")
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?![0-9A-Fa-f:])")
IP4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
NAME_RE = re.compile(r"(?<![\w.-])((?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\.)+[a-z]{2,})(?![\w-])", re.I)


def trace(logger, msg, *args):
    """逐帧级别的日志；先判断级别，避免关闭时白白拼字符串。"""
    if logger.isEnabledFor(TRACE):
        logger.log(TRACE, msg, *args)


class SecretFilter(logging.Filter):
    """兜底：把 16 字节（32 个十六进制字符）以上的十六进制串遮掉。写日志的代码本来就不该带密钥，这里防的是疏忽。"""

    def filter(self, record):
        msg = record.getMessage()
        masked = HEX_RUN.sub(lambda m: "<hex %dB>" % (len(m.group(1)) // 2), msg)
        if masked != msg:
            record.msg, record.args = masked, ()
        return True


class RedactFilter(logging.Filter):
    """--redact：日志里的 MAC、IPv4、域名换成稳定的短标记（同一个值每次得到同一个标记，仍然看得出「是同一台」）。"""

    def __init__(self, salt=None):
        super().__init__()
        self.salt = (salt or os.urandom(8).hex()).encode()

    def tag(self, kind, value):
        return "%s-%s" % (kind, hashlib.sha256(self.salt + value.lower().encode()).hexdigest()[:6])

    def filter(self, record):
        msg = MAC_RE.sub(lambda m: self.tag("mac", m.group(1)), record.getMessage())
        msg = IP4_RE.sub(lambda m: self.tag("ip", m.group(1)), msg)
        msg = NAME_RE.sub(lambda m: self.tag("name", m.group(1)), msg)
        record.msg, record.args = msg, ()
        return True


def default_log_path(now=None):
    return "wifi80211-%s.log" % (now or datetime.datetime.now()).strftime("%Y%m%d-%H%M%S")


def setup(level="info", logfile=None, redact=False, stream=None):
    """装处理器。level：控制台的级别（默认 info）；logfile 给了就同时写文件（文件固定 DEBUG，level 是 trace 时 TRACE）。返回日志文件路径或 None。
    重复调用会先去掉自己上次装的处理器。"""
    root = logging.getLogger(ROOT)
    for h in list(root.handlers):
        if getattr(h, "_wifi80211", False):
            root.removeHandler(h)
            h.close()
    lvl = LEVELS[level] if isinstance(level, str) else level
    root.setLevel(min(lvl, TRACE if lvl == TRACE else logging.DEBUG) if logfile else lvl)
    root.propagate = False
    filters = [SecretFilter()] + ([RedactFilter()] if redact else [])
    handlers = [(logging.StreamHandler(stream or sys.stderr), lvl, "%(levelname)s %(message)s")]
    if logfile:
        handlers.append((logging.FileHandler(logfile, encoding="utf-8"), TRACE if lvl == TRACE else logging.DEBUG, "%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    for h, hl, fmt in handlers:
        h.setLevel(hl)
        h.setFormatter(logging.Formatter(fmt))
        for f in filters:
            h.addFilter(f)
        h._wifi80211 = True
        root.addHandler(h)
    return logfile


def fingerprint(path, limit=1 << 20):
    """输入文件的大小和前 1 MiB 的 sha256 前 16 位：对得上「是不是同一个文件」，不读完整个大文件。"""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            return size, hashlib.sha256(f.read(limit)).hexdigest()[:16]
    except OSError:
        return None, None


def run_header(logger, argv, inputs=()):
    """每次运行开头写一次：版本、系统、参数、输入文件。参数里的密钥文件只记路径，不读内容。"""
    from . import __version__
    logger.info("wifi80211 %s，Python %s，%s %s", __version__, platform.python_version(), platform.system(), platform.machine())
    logger.info("参数：%s", " ".join(argv))
    logger.debug("工作目录：%s", os.getcwd())
    for p in inputs:
        size, fp = fingerprint(p)
        logger.info("输入文件 %s：%s 字节，前 1MiB 指纹 %s", p, size if size is not None else "读不了", fp or "-")
