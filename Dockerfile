# 开发/测试环境：gcc + Python3 + 第 4 阶段测试用到的两个 Python 库。
# 不依赖宿主机工具链（macOS 上没有 gcc、没有 pty 以外的 Linux 行为差异也一并抹平）。
# 依赖版本固定在发布满两周以上的版本。
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*

# pycryptodome：4.1.5 CCMP 解密的 AES 原语；scapy：生成测试 pcap / 测试帧
RUN pip install --no-cache-dir pycryptodome==4.0.0 scapy==2.7.0

ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
# 代码不 COPY 进镜像，由 tests/docker.sh 把仓库挂载到 /work：改完代码直接重跑，不用重建
CMD ["bash", "tests/run_all.sh"]
