#!/usr/bin/env bash
# 在 Docker 里跑仿真接收链路测试（真实 main.c <-> esp8266_sim 虚拟串口）
set -euo pipefail
cd "$(dirname "$0")/../.."
docker build -q -t wifi-scan-sim-test -f tests/sim_chain/Dockerfile .
docker run --rm wifi-scan-sim-test
