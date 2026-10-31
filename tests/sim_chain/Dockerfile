# 仿真接收链路测试环境：gcc + Python3，固定版本，不依赖宿主机工具链
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY esp8266_sim.py ap_parser.c ap_parser.h ./
COPY stm32_project ./stm32_project
COPY tests ./tests

CMD ["python3", "tests/test_sim_chain.py"]
