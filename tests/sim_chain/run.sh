#!/usr/bin/env bash
# 在 Docker 里只跑仿真接收链路测试（真实 main.c <-> esp8266_sim 虚拟串口）
set -euo pipefail
exec bash "$(dirname "$0")/../docker.sh" python3 tests/test_sim_chain.py
