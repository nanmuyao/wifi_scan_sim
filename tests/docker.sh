#!/usr/bin/env bash
# 在 Docker 里跑测试（仓库挂载到容器，改代码不用重建镜像）。
#   bash tests/docker.sh                          全部测试（tests/run_all.sh）
#   bash tests/docker.sh python3 tests/test_sim_chain.py   只跑某一项
#   bash tests/docker.sh bash                     进容器交互
set -euo pipefail
cd "$(dirname "$0")/.."
docker build -q -t wifi-scan-sim-dev . >/dev/null
if [ -t 0 ]; then t=-it; else t=-i; fi
exec docker run --rm "$t" -v "$PWD":/work wifi-scan-sim-dev "$@"
