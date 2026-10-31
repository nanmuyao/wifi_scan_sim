---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 0bd2c4904e701d4269608d4ce4d80073_7287abe8d46711f180d5525400248c00
    ReservedCode1: /h0dO6ILttPIzlzL1TYJURcXuW4qNQNn9ceGtovR+InNN+6sh7I1UEqs2cIE6xoZCiLYixqg8kAhWPNmxN2iDpOTClKonejxNCe4QWpnSBik1QKHkrrzoyernlF2tleXH9ArO0WSnQY1sO6iSuqj8oiCkf29N3kalviopwUwfuJlx59EHkWwlZoEGCE=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 0bd2c4904e701d4269608d4ce4d80073_7287abe8d46711f180d5525400248c00
    ReservedCode2: /h0dO6ILttPIzlzL1TYJURcXuW4qNQNn9ceGtovR+InNN+6sh7I1UEqs2cIE6xoZCiLYixqg8kAhWPNmxN2iDpOTClKonejxNCe4QWpnSBik1QKHkrrzoyernlF2tleXH9ArO0WSnQY1sO6iSuqj8oiCkf29N3kalviopwUwfuJlx59EHkWwlZoEGCE=
---

# wifi_scan_sim 项目规划（基于 GitHub 调研）

## 1. 项目定位
- 用途：研究学习（理解 802.11 协议与 WiFi 电磁波扫描），非产品化
- 背景：用户软件背景（Go/Linux），硬件入门，偏好"先仿真、无硬件先开发"
- 当前已交付：STM32+ESP8266 AT 扫描工程、纯C CWLAP 解析库、pty 虚拟串口仿真、手写 802.11 帧解析器（Beacon/Probe/Auth/Assoc/Deauth/Action/加密Data）、pcap 支持、三档采购清单；仓库 nanmuyao/wifi_scan_sim

## 2. 调研结论（参考项目）
GitHub 上无全栈完全一致的同类项目（STM32+AT 扫描+802.11 帧解析+仿真组合为空白），但各模块有可参考先例：
- 路线 B 先例：vpecanins/stm32f7-rtlsdr —— STM32F7 USB Host 直驱 RTL-SDR dongle，已实现 RTL2832 寄存器操作/E4000 调谐/采样搬运，FFT 未完成（半成品，可借鉴 USB Host+调谐器驱动）
- 路线 A 库参考：ximtech/ESP8266Wifi —— STM32 LL 库 DMA 非阻塞 AT 交互含 CWLAP 扫描（定位是连接库，非扫描分析）
- 帧解析参考：YassineKaibi/wifispy（Scapy 被动分析，帧类型覆盖与本项目近似）、flupzor/packetparser（纯 Python Beacon/Probe 解析）、wraith-wireless/itamae（C 语言原始 802.11 解析，纯解析无依赖思路与 ap_parser.c 一致）
- ESP8266 嗅探参考：xiixim101-pixel/sniffus（promiscuous 抓 802.11+AP 雷达+Web Serial 仪表盘）、kalanda/esp8266-sniffer（经典 Probe Request 嗅探，输出 RSSI/MAC/SSID 与本项目仿真目标最相似）、mzealey/ESP8266-WIFI-Scanner（周期 dump MAC+RSSI 室内定位）、AsHfIEXE/SigVoid（威胁监控+Python 后端+PWA 仪表盘）
- SDR/FFT 参考：omer-acarr/Audio-Spectrum-Analyzer-with-ARM-CMSIS-DSP、g0fcu/ARM-radio（STM32 直采 SDR，CMSIS-DSP FFT 集成方式可参考，但非 RTL-SDR 架构）

## 3. 借鉴点对照表

| 本项目现状 | 参考项目 | 可借鉴内容 |
|---|---|---|
| 纯C CWLAP 解析库（ap_parser.c） | ximtech/ESP8266Wifi、wraith-wireless/itamae | LL 库 DMA 非阻塞 AT 交互模式；C 语言纯解析无依赖的实现思路 |
| 手写 802.11 帧解析器（Beacon/Probe/Auth/Assoc/Deauth/Action/加密Data） | YassineKaibi/wifispy、flupzor/packetparser | 帧类型覆盖与解析逻辑对照；纯 Python 轻量解析的字段组织方式 |
| pty 虚拟串口仿真 + 解析验证 | kalanda/esp8266-sniffer、xiixim101-pixel/sniffus | Probe Request 报告格式（SSID/MAC/RSSI）；promiscuous 抓包思路在仿真层的等价实现 |
| STM32 + ESP8266 扫描工程 | vpecanins/stm32f7-rtlsdr、g0fcu/ARM-radio | USB Host 直驱 dongle 架构；CMSIS-DSP FFT 集成方式（路线 B 用） |
| 可视化/监控仪表盘（待扩展） | xiixim101-pixel/sniffus、AsHfIEXE/SigVoid | Web Serial 仪表盘；Python 后端 + PWA 前端展示形态 |
| 无（数据帧仅能解析 MAC 头） | florenzi002/WPA-Analyzer、junan-98/WPA2_Decrypt、william-r-dieter/pyDot11、mfontanini/dot11decrypt | PBKDF2 密钥推导 + EAPOL 解析 + PTK 推导 + CCMP 解密全链路，离线 pcap 演示 |

## 4. 分阶段路线图

| 阶段 | 内容 | 参考项目 | 状态 |
|---|---|---|---|
| 阶段 1 方案A基础 | STM32+ESP8266 AT 扫描、CWLAP 解析、pty 仿真、802.11 帧解析、采购清单 | ximtech/ESP8266Wifi、wraith-wireless/itamae、flupzor/packetparser | 已完成 |
| 阶段 2 嗅探扩展 | 移植 ESP8266 deauther/promiscuous 思路，输出 Probe Request 的 SSID/MAC/RSSI 报告 | kalanda/esp8266-sniffer、xiixim101-pixel/sniffus | 待做 |
| 阶段 3 真实抓包验证 | Linux 机器监听模式抓包回传，用现有解析器验证；macOS 无 RFMON 已实测确认 | —（本机验证流程） | 待做 |
| 阶段 4 WPA2 离线解密 | 已知口令前提下：PBKDF2 推 PMK → 解析 EAPOL 四次握手 → 推 PTK → MIC 校验 → CCMP 解密数据帧；纯离线 pcap，详见 4.1 | florenzi002/WPA-Analyzer、junan-98/WPA2_Decrypt、william-r-dieter/pyDot11、mfontanini/dot11decrypt | 已完成（4.1.1~4.1.5 全链路） |
| 阶段 5 ESP32 版 | ESP32 直扫 + Web 仪表盘 | xiixim101-pixel/sniffus（Web Serial UI） | 待做 |
| 阶段 6 路线B 频谱 | RTL-SDR 下变频 + STM32 FFT | vpecanins/stm32f7-rtlsdr；备选 PC 端 rtl_power 出图 | 待做 |

### 4.1 阶段 4：WPA2 离线解密（设计）

**目标**：给定一份含四次握手的 pcap 和已知口令，把现有解析器里标记为"密文状态"的数据帧解出明文。仅处理**自己的网络**或公开样例，口令必须已知；不做口令爆破，不抓他人流量（见第 5 节合法性边界）。

**依赖**：需要一份带握手的抓包。macOS 无法监听（已实测），来源只有两种：
- 公开样例：Wireshark 官方 SampleCaptures 里的 WPA 抓包（使用前先核对其口令与 SSID，不要凭记忆）；
- 阶段 3 在 Linux 上抓自家 AP 的握手。

**拆成 5 步，每步有独立验收，前一步不过不进下一步**

| 步骤 | 内容 | 验收 | 状态 |
|---|---|---|---|
| 4.1.1 PMK | `PBKDF2-HMAC-SHA1(口令, SSID, 4096 次, 32 字节)` | 对上 802.11i 附录标准向量：口令 `password`、SSID `IEEE` → `f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e`（已用标准库 `hashlib.pbkdf2_hmac` 核对一致） | ✅ 已完成 |
| 4.1.2 EAPOL 解析 | 从数据帧里取 LLC/SNAP（EtherType `0x888E`）后的 EAPOL-Key，区分握手 1–4 条，取出 ANonce、SNonce、MIC、Key Info。握手 1–4 条区分特征：M1 ANonce 非零、SNonce 零、MIC 零；M2 SNonce 非零、MIC 非零；M3 ANonce 非零、MIC 非零、含 GTK；M4 双 nonce 零、仅 MIC | 一份抓包里能识别出完整的 4 条，并给出 AP/STA 的 MAC | ✅ 已完成 |
| 4.1.3 PTK | 用 PRF 展开：`PRF-512(PMK, "Pairwise key expansion", min(MAC)‖max(MAC)‖min(Nonce)‖max(Nonce))`，拆出 KCK/KEK/TK。注意：PTK 没有独立判据，正确性完全依赖 4.1.4 的 MIC 校验间接验证 | 有标准向量时对向量；没有时靠 4.1.4 间接验证 | ✅ 已完成 |
| 4.1.4 MIC 校验 | 把握手 2（或 3）的 MIC 字段清零，用 KCK 做 HMAC-SHA1 取前 16 字节，与帧内 MIC 比较。前置条件：先解析 Key Info 确认 Key Descriptor Version = 2（AES/CCMP）才用 HMAC-SHA1；TKIP（版本 1）用 HMAC-MD5，本阶段只支持 AES，遇到版本 1 直接跳过 | 口令正确 → MIC 一致；故意改错一位口令 → 必须不一致。这是整条密钥链是否正确的**唯一可靠判据**，务必加反向用例 | ✅ 已完成 |
| 4.1.5 CCMP 解密 | AES-128-CCM：nonce = 优先级‖A2‖PN（共 13 字节），AAD 由 MAC 头按规则屏蔽可变位得到，TK 解 payload，校验 8 字节 MIC。注意 LLC/SNAP 偏移随 QoS 位变化：QoS 帧在地址 4 之后多 2 字节 QoS Control，定位 EAPOL/LLC 时要同步偏移 | 解出的 payload 前 8 字节是 LLC/SNAP（`AA AA 03 00 00 00`），再接 IP 头；解不出 → 先排查 AAD 屏蔽位与 PN 字节序 | ✅ 已完成 |

**取舍：AES 要不要引入依赖**
- 4.1.1–4.1.4 只用标准库（`hashlib`/`hmac`/`struct`），保持项目"纯手写、少依赖"的风格；
- 4.1.5 需要 AES-CCM，标准库没有。选项：①引入 `cryptography` 或 `pycryptodome`，只用它的 AES 原语，CCM 的 nonce/AAD 拼装仍手写；②手写 AES（教学价值高，但慢且易错，不建议作为首版）。建议先走 ①，把"依赖仅限 AES"写进 README。

**已知难点（提前记下，避免卡住）**
- 握手可能不完整（只抓到 2 条），仍可用握手 2 做 MIC 校验，但 4.1.5 需要 TK，必须 PTK 已定；
- 数据帧 QoS 位、A4 字段、HT 控制位会影响 AAD 构造和头长度，要在现有 `parse_mac_header` 里补齐；
- PN 在帧内的字节顺序容易写反；
- 重放/乱序帧只影响 PN 检查，离线解密可先不做重放校验。

**与现有代码的衔接**：在 `wifi_frame_parser.py` 的 `parse_data_frame` 处，当前遇到 WPA2 加密帧只标记"密文状态"；本阶段给它加一个可选的 `--passphrase/--ssid` 参数，提供密钥时才尝试解密，不提供时行为完全不变，原有 demo 与测试不受影响。

## 5. 技术决策与取舍
- 仿真优先：继续沿用 pty 虚拟串口 + 纯C 单测双轨验证，无硬件也能推进
- 合法性边界：仅自建实验网络；不攻击他人网络；WPA2 解密只在口令已知（自家网络或公开样例）的前提下做，不做口令爆破
- macOS 限制：监听模式不可用，真实 802.11 抓包需 Linux 机器
- RTL-SDR 数据率风险：USB Host 搬运 + FFT 计算量大，STM32F103 不足，路线 B 需 F4/F7 级芯片（采购清单已分档）

## 6. 下一步行动清单（TODO，带优先级）
- P0：阶段2 嗅探演示脚本（基于现有 pty 仿真扩展 probe 嗅探输出）
- P0：阶段3 准备 Linux 抓包操作指引（发给用户手动执行）
- ~~P1：阶段4 WPA2 离线解密：先做 4.1.1 PMK + 标准向量单测，再做 4.1.2 EAPOL 解析~~（已完成：4.1.1~4.1.5 全链路，含 fixture 闭环与单测）
- P1：阶段5 ESP32 版设计文档
- P2：阶段6 RTL-SDR 频谱方案可行性验证（stm32f7-rtlsdr 源码研读）
- P2：更新 README 与本规划文档同步
*（内容由AI生成，仅供参考）*
