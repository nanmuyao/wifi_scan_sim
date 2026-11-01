# 开发/测试环境：gcc + Python3 + tshark（对照用的标准答案）+ 第 4 阶段测试用到的两个 Python 库。
# 不依赖宿主机工具链（macOS 上没有 gcc、没有 pty 以外的 Linux 行为差异也一并抹平）。
# 依赖版本固定在发布满两周以上的版本。
# 第一阶段：编译 nDPI 的 ndpiReader（深度包检测库，ntopng 用的就是它；只在测试里当“应用识别”的第二份标准答案）。
# 6.0 发布于 2026-08-28（满两周），源码包的 sha256 固定；Debian 软件源里的 libndpi-bin 是 4.2（2022 年），应用特征太旧，不用。
FROM python:3.12-slim AS ndpi
ARG NDPI_VERSION=6.0
ARG NDPI_SHA256=21fc40cab5505942c0b21d9bbaf73e9adf8162ddfe782e4cd072cab855a2eda9
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential autoconf automake libtool pkg-config libpcap-dev curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/ndpi.tar.gz https://github.com/ntop/nDPI/archive/refs/tags/${NDPI_VERSION}.tar.gz \
 && echo "${NDPI_SHA256}  /tmp/ndpi.tar.gz" | sha256sum -c - \
 && mkdir /src && tar xzf /tmp/ndpi.tar.gz -C /src --strip-components=1 && cd /src \
 && ./autogen.sh >/dev/null && ./configure --disable-shared --enable-static >/dev/null \
 && make -j"$(nproc)" >/dev/null && install -m 0755 example/ndpiReader /usr/local/bin/ndpiReader \
 && /usr/local/bin/ndpiReader -h 2>&1 | head -2

FROM python:3.12-slim

# tshark：Wireshark 的命令行版，只用来当“标准答案”做对照（tests/oracle/），不参与本项目的解析。
# 装的是 Debian 13 软件源里的版本（写本文时 4.4.19）；tests/oracle 会检查主版本，变了会提示。
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gcc libc6-dev tshark libpcap0.8t64 \
 && rm -rf /var/lib/apt/lists/*

# ndpiReader（上一阶段编译；静态链接 libndpi，运行时只需要 libpcap）
COPY --from=ndpi /usr/local/bin/ndpiReader /usr/local/bin/ndpiReader

# pycryptodome：4.1.5 CCMP 解密的 AES 原语；scapy：生成测试 pcap / 测试帧
RUN pip install --no-cache-dir pycryptodome==4.0.0 scapy==2.7.0

ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
# 代码不 COPY 进镜像，由 tests/docker.sh 把仓库挂载到 /work：改完代码直接重跑，不用重建
CMD ["bash", "tests/run_all.sh"]
