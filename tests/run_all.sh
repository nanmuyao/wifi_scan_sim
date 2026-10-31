#!/usr/bin/env bash
# 跑全部测试。需要 gcc 和 pycryptodome / scapy，一般通过 tests/docker.sh 在容器里调用。
# 每项独立运行、最后汇总，某一项失败不会挡住后面的。
cd "$(dirname "$0")/.."
failed=()
run() {
    local name=$1; shift
    echo; echo "################ $name"
    if "$@"; then echo ">>> $name: OK"; else echo ">>> $name: FAILED"; failed+=("$name"); fi
}

tmp=$(mktemp -d)
run "C 解析器单元测试" bash -c "gcc -Wall -Wextra -o $tmp/test_ap_parser test_ap_parser.c ap_parser.c && $tmp/test_ap_parser"
run "STM32 工程与根目录的 ap_parser 一致" bash -c "cmp ap_parser.c stm32_project/Core/Src/ap_parser.c && cmp ap_parser.h stm32_project/Core/Inc/ap_parser.h"
run "抓包文件读取（pcap / pcapng / gzip）" python3 tests/test_capture.py
run "WPA2 握手 / CCMP" python3 tests/test_wpa2_handshake.py
for t in esp32_project/tests/test_esp32_*.py; do
    run "$t" bash -c "cd esp32_project/tests && python3 $(basename "$t")"
done
run "样例下载脚本（离线）" python3 tests/oracle/test_fetch_samples.py
run "差分工具（tshark 对照）" python3 tests/oracle/test_diff.py
run "信息元素遍历" python3 tests/test_ie.py
run "MAC 头逐位检查" python3 tests/test_mac_header.py
run "radiotap 解析" python3 tests/test_radiotap.py
run "radiotap 头剥离" python3 tests/test_radiotap_strip.py
run "解析结果对照 tshark（24 个公开样例）" python3 tests/oracle/test_samples_diff.py
run "抓包读取对照 tshark（24 个公开样例）" python3 tests/oracle/test_capture_oracle.py
run "帧类型表对照 tshark" python3 tests/oracle/test_subtype_names.py
run "固件接收链路仿真（真实 main.c <-> esp8266_sim，含故障注入）" python3 tests/test_sim_chain.py

echo; echo "################ 汇总"
if [ ${#failed[@]} -eq 0 ]; then echo "全部通过"; exit 0; fi
printf '失败: %s\n' "${failed[@]}"; exit 1
