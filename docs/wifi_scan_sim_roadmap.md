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
| 阶段 4 ESP32 版 | ESP32 直扫 + Web 仪表盘 | xiixim101-pixel/sniffus（Web Serial UI） | 待做 |
| 阶段 5 路线B 频谱 | RTL-SDR 下变频 + STM32 FFT | vpecanins/stm32f7-rtlsdr；备选 PC 端 rtl_power 出图 | 待做 |

## 5. 技术决策与取舍
- 仿真优先：继续沿用 pty 虚拟串口 + 纯C 单测双轨验证，无硬件也能推进
- 合法性边界：仅自建实验网络；不攻击他人网络
- macOS 限制：监听模式不可用，真实 802.11 抓包需 Linux 机器
- RTL-SDR 数据率风险：USB Host 搬运 + FFT 计算量大，STM32F103 不足，路线 B 需 F4/F7 级芯片（采购清单已分档）

## 6. 下一步行动清单（TODO，带优先级）
- P0：阶段2 嗅探演示脚本（基于现有 pty 仿真扩展 probe 嗅探输出）
- P0：阶段3 准备 Linux 抓包操作指引（发给用户手动执行）
- P1：阶段4 ESP32 版设计文档
- P2：阶段5 RTL-SDR 频谱方案可行性验证（stm32f7-rtlsdr 源码研读）
- P2：更新 README 与本规划文档同步
*（内容由AI生成，仅供参考）*
