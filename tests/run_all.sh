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
run "握手对照 tshark（37 个握手：MIC 自证 + KCK / TK）" python3 tests/oracle/test_handshake_oracle.py
run "CCMP / GCMP / TKIP / WEP 解密（数据帧与 PMF 管理帧，独立加密方）" python3 tests/test_decrypt.py
run "TKIP 密钥混合对照 tshark（27 个合成帧）" python3 tests/oracle/test_tkip_oracle.py
run "解密对照 tshark 明文（单播 1094、组播 175、PMF 管理帧 6、WEP 11 帧逐字节）" python3 tests/oracle/test_decrypt_diff.py
run "组密钥（KDE、Key Data 解包、GTK / IGTK、组播帧解密）" python3 tests/test_groupkeys.py
run "组密钥对照 tshark 的 GTK（48 个，19 个相同）" python3 tests/oracle/test_groupkeys_oracle.py
run "BIP（四种套件的独立构造、IGTK 选择、组管理套件）" python3 tests/test_bip.py
run "BIP 在真实抓包上（MME 个数对照 tshark，1 个 GMAC-256 帧验证通过）" python3 tests/oracle/test_bip_oracle.py
run "FTE（快速切换元素）对照 tshark（16 帧）" python3 tests/oracle/test_ft_diff.py
run "FT 密钥层级（真实抓包的已知答案、公式结构）" python3 tests/test_ft.py
run "SAE 认证帧与曲线检查（独立生成的点）" python3 tests/test_sae.py
run "SAE / OWE 对照 tshark（commit / confirm / DH 参数，曲线上的点）" python3 tests/oracle/test_sae_diff.py
run "解密后的内容（LLC/SNAP、ARP、IP、UDP、TCP、ICMP、DHCP 与校验和，scapy 独立构造）" python3 tests/test_net.py
run "解密流水线接线（WEP 合成帧、A-MSDU）" python3 tests/test_pipeline.py
run "解密后的内容对照 tshark（1301 个数据帧逐层，校验和全部吻合）" python3 tests/oracle/test_net_diff.py
run "DNS / mDNS 报文（名字压缩、记录类型、坏报文，scapy 独立构造）" python3 tests/test_dns.py
run "DNS / mDNS 对照 tshark（3 个样例 40 帧逐字段）" python3 tests/oracle/test_dns_diff.py
run "TCP 流重组（乱序、重传、重叠、回绕、缺口，scapy 独立构造）" python3 tests/test_tcpstream.py
run "TCP 流重组对照 tshark 的 Follow TCP Stream（真实抓包 10 个方向含 4 处缺包 + 合成 12 个方向）" python3 tests/oracle/test_tcpstream_diff.py
run "Wireshark 公布的 TK / GTK 全部被我们推出（21 个 TK、20 个 GTK）" python3 tests/oracle/test_published_keys.py
run "用户直接给 TK 解密对照 tshark（5 个样例）" python3 tests/oracle/test_user_tk.py
run "TDLS（建立帧、TPK、MIC、直连帧解密，独立构造）" python3 tests/test_tdls.py
run "TDLS 对照 tshark（wpa-test-decode-tdls）" python3 tests/oracle/test_tdls_oracle.py
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
