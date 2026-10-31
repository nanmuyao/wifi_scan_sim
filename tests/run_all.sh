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
run "握手跟踪（MIC 算法、PTK、候选 PMK、合成握手）" python3 tests/test_handshake.py
run "握手对照 tshark（30 个握手：MIC 自证 + KCK / TK）" python3 tests/oracle/test_handshake_oracle.py
run "CCMP / GCMP 数据帧解密（独立加密方、AAD / nonce 的各位）" python3 tests/test_decrypt.py
run "CCMP / GCMP 解密对照 tshark 明文（1055 帧单播 + 82 帧组播逐字节）" python3 tests/oracle/test_decrypt_diff.py
run "组密钥（KDE、Key Data 解包、GTK / IGTK、组播帧解密）" python3 tests/test_groupkeys.py
run "组密钥对照 tshark 的 GTK（34 个，12 个相同）" python3 tests/oracle/test_groupkeys_oracle.py
run "EAPOL-Key 解析与帧迭代" python3 tests/test_eapol.py
run "EAPOL-Key 对照 tshark（109 帧）" python3 tests/oracle/test_eapol_diff.py
run "密钥推导原语（CMAC / 密钥包装 / PRF / KDF）" python3 tests/test_kdf80211.py
run "加密原语（CCM / GCM / RC4 / WEP / TKIP / Michael）" python3 tests/test_crypto80211.py
run "解密标准答案（tshark 用公开密钥解出的明文）" python3 tests/oracle/test_decrypt_oracle.py
run "A-MSDU 子帧" python3 tests/test_amsdu.py
run "Action 帧解码" python3 tests/test_action.py
run "Action 类别名称对照 tshark" python3 tests/oracle/test_action_names.py
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
