#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""兼容入口：python3 wifi_report.py capture.pcap --keys keys.txt。实现在 wifi80211/report.py（等同 python3 -m wifi80211.report）。"""
import sys

from wifi80211.report import main

if __name__ == "__main__":
    sys.exit(main())
