---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 0bd2c4904e701d4269608d4ce4d80073_3c0101cad52311f180d5525400248c00
    ReservedCode1: Z8IEtf4vVVHaBgX7dAi5Ztwk3pX/6aPin09SfO9TautipUPXTsCTXonxNscLDO1FuROr4HoxTV0m6HT9e4PPkBV9RptXigfzkJ3azKEwCTmvAkt2NcP/Y+Tmk9DhSMqcVLBfp8BQek9Tu/8hVDZ8hINrjDuk/IQEBa3H7G7cVSMrlilhhs9Y/lMaOWY=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 0bd2c4904e701d4269608d4ce4d80073_3c0101cad52311f180d5525400248c00
    ReservedCode2: Z8IEtf4vVVHaBgX7dAi5Ztwk3pX/6aPin09SfO9TautipUPXTsCTXonxNscLDO1FuROr4HoxTV0m6HT9e4PPkBV9RptXigfzkJ3azKEwCTmvAkt2NcP/Y+Tmk9DhSMqcVLBfp8BQek9Tu/8hVDZ8hINrjDuk/IQEBa3H7G7cVSMrlilhhs9Y/lMaOWY=
---

# wifi_scan_sim 下一阶段规划（Roadmap v2）

> 承接 [wifi_scan_sim_roadmap.md](wifi_scan_sim_roadmap.md) 的阶段 1-6（全部已完成），
> 本文件规划 **阶段 7-11**：从"仿真跑通 + 设计文档齐备"迈向"实物联调 + 真实数据验证 +
> 端侧实现 + 可视化 + 频谱落地"。

## 0. 背景与定位

- **已完成基础（阶段 1-6）**：STM32+ESP8266 AT 扫描工程、纯 C CWLAP 解析、pty 仿真、
  手写 802.11 帧解析器、Linux 抓包指引、WPA2 离线解密全链路（4.1.1~4.1.5）、
  ESP32 版设计文档、RTL-SDR 频谱方案可行性结论。
- **v2 原则（延续项目底线）**：
  1. 研究学习用途，非产品化；
  2. **仿真优先**：无硬件也能先推进逻辑与脚本，硬件只是最后一层验证；
  3. **合法性边界**：仅自建网络与公开样例；不抓/不解他人网络；不做口令爆破；
  4. **纯手写、少依赖**：解析与算法核心保持标准库手写，第三方依赖（如 AES 原语、scapy 造样本）明确标注且收窄到最小范围。

## 1. 阶段总览

| 阶段 | 内容 | 优先级 | 依赖 | 状态 |
|---|---|---|---|---|
| 阶段 7 | 硬件实施：STM32+ESP8266 实物联调 | P0 | 阶段 1（已完成）、采购清单 | 待做 |
| 阶段 8 | 真实抓包 + WPA2 解密实操验证 | P1 | 阶段 3 指引、阶段 4（已完成） | 待做 |
| 阶段 9 | ESP32 版实现（设计文档 → 代码） | P1 | 阶段 5 设计文档（已完成） | 待做 |
| 阶段 10 | 可视化仪表盘（Web Serial / Python 后端+PWA） | P2 | 阶段 7 数据源可选；可先接模拟器 | 待做 |
| 阶段 11 | SDR 频谱仪落地（PC rtl_power 优先） | P2 | 阶段 6 可行性（已完成） | 待做 |

## 2. 各阶段详情

### 阶段 7：硬件实施（STM32 + ESP8266 实物联调）· P0

**目标**
按 [采购清单与接线方案.md](采购清单与接线方案.md) 经济档（约 ¥70）采购，
把阶段 1 的仿真工程烧到真实板子，跑通"AT 扫描 → CWLAP 解析 → 串口上报 → PC 绘图"闭环，
并与现场真实 AP 对照验证。

**关键交付物**
- 实物接线验证记录（照片/说明，按接线方案完成：ESP8266 VCC/GND/CH_PD、TXD→PA10、RXD←PA9、USART2→USB-TTL）
- STM32 真机固件烧录步骤 + 实测串口日志（`docs/硬件联调记录.md`）
- `tools/serial_wifi_plot.py` 真机适配（确认真实固件输出格式与模拟器一致，必要时兼容真实固件变体）
- 真机扫描 3 轮的 `[i] ch=.. rssi=.. enc=.. ssid=..` 记录 + 绘图 PNG

**无硬件仿真路径**
- 逻辑部分已在阶段 1/2 用 pty 虚拟串口 + 纯 C 单测覆盖；此阶段**仿真侧不新增代码**，
  仅需在 PC 上先跑 `python3 esp8266_sim.py --sniffer-demo` 与 `bash tests/sim_chain/run.sh` 复验基线，
  确保固件行为预期明确后采购。
- 采购前可用本文件 + 采购清单核对清单（器件、供电注意：ESP8266 峰值 300mA+ 建议独立 AMS1117）。

**验收标准**
1. 真机 3 轮扫描均能解析出周边真实 AP，SSID/信道/加密类型与手机或电脑扫描结果可对应（允许信号弱 AP 偶发缺失）；
2. `serial_wifi_plot.py` 在真机串口上出图成功；
3. 烧录步骤与接线记录完整，他人可复现。

**优先级与依赖**
- P0：硬件是后续真机数据（阶段 8 数据源之一、阶段 10 实时源）的地基；
- 依赖：阶段 1（已完成）；可选参考逻辑分析仪（标准档）抓 ESP8266 RX/TX 时序学习。

---

### 阶段 8：真实抓包 + WPA2 解密实操验证 · P1

**目标**
把阶段 3 的 Linux 抓包指引真正执行一遍，抓到**真实环境**的 802.11 帧与 WPA2 握手；
再用阶段 4 的 `wpa2_handshake.py` 解真实抓包（自家网络），并与 Wireshark 官方公开样例交叉验证。

**关键交付物**
- 真实抓包产物与解析日志：`capture.pcap`（Radiotap）、`wifi_frame_parser.py --pcap` 输出
- 自家网络握手解密结果：`wpa2_handshake.py --pcap capture.pcap --password ...` 输出（4 条 EAPOL + MIC 一致 + CCMP 解出明文）
- Wireshark 官方 SampleCaptures 的 WPA 样例跑通记录（先用它验证解密器，再上自家网络）
- 验证结论文档：真实帧/仿真帧差异、解析器需要修补的点（如真实固件变体、QoS/HT 位、PN 字节序确认）

**无硬件仿真路径（重要）**
- 解密器验证**不需要真实抓包**：先用 `tests/fixtures/wpa2_handshake.pcap`（scapy 构造）与
  Wireshark SampleCaptures 公开样例在 PC 端跑通 4.1.1~4.1.5 全链路，作为"仿真验证层"；
- 真实抓包仅需一次性 Linux 操作（有监听模式网卡的机器），抓完回传后全部解析/解密仍在 PC 端完成。

**验收标准**
1. 解密器对**至少一份公开样例**（Wireshark SampleCaptures 的 WPA 抓包，口令/SSID 以样例文档为准）跑通 PMK→EAPOL→PTK→MIC→CCMP，还原明文；
2. 对**自家网络**真实抓包同样跑通，解出的 payload 前 8 字节为 LLC/SNAP（`AA AA 03 00 00 00`）；
3. 反向用例仍有效：故意改错口令 → MIC 不一致；
4. 输出与 Wireshark 手工解密结果一致（若 Wireshark 可用作对照）。

**优先级与依赖**
- P1：验证阶段 4 成果在真实数据上的正确性，为阶段 9/10 的端侧能力背书；
- 依赖：阶段 3 指引（已完成）、阶段 4（已完成）；建议排在阶段 7 之后（顺手在真机环境做），
  但**不阻塞**——只要有一台 Linux 机器即可独立完成。

---

### 阶段 9：ESP32 版实现（设计文档 → 代码）· P1

**目标**
按 [ESP32版设计文档.md](ESP32版设计文档.md) 推进代码：ESP32 直扫（替代 STM32+AT 链路）、
复用 ap_parser 解析、聚合上报（WebSocket/串口），逐步落地设计文档的里程碑 M1-M5。

**关键交付物**
- `esp32_project/` 源码：直扫（ESP-IDF WiFi scan）、AP 解析（复用 `ap_parser.c` 移植）、聚合与上报
- 仿真路径落地：设计文档 L1-L4（PC 侧解析复用、Wokwi/qemu 仿真）跑通
- 里程碑推进记录：M1（直扫+解析）→ M2（聚合）→ M3（上报）→ M4（端侧仪表盘对接）→ M5（真机联调，可选）
- 新增/更新单测：直扫结果解析、聚合逻辑（保持纯标准库）

**无硬件仿真路径**
- 完全可先行：解析与聚合逻辑在 PC 上单测；Wokwi 可模拟 ESP32 直扫流程；
  真机联调（M5）作为可选里程碑，无板子也能推进 M1-M4。

**验收标准**
1. M1：仿真/Wokwi 下直扫返回的 AP 列表能被解析器正确解析（含隐藏 SSID 等边界）；
2. M2-M3：聚合/上报在仿真链路有对应演示与单测；
3. 代码复用关系与设计文档一致，未破坏阶段 1-4 既有测试；
4. （可选）真机 ESP32 扫描输出与现场 AP 对应。

**优先级与依赖**
- P1：端侧实现的自然延伸；依赖阶段 5 设计文档（已完成）；
- 与阶段 7 可**并行**（一个在 STM32+ESP8266 实物、一个在 ESP32 代码/仿真）。

---

### 阶段 10：可视化仪表盘（Web Serial / Python 后端 + PWA）· P2

**目标**
参考 sniffus（Web Serial UI）与 SigVoid（Python 后端 + PWA），做 AP 列表 +
信道热力图 + RSSI 时间曲线的实时仪表盘，数据源优先接 pty 模拟器（无硬件），真机串口为可选。

**关键交付物**
- 仪表盘前端：AP 列表视图、信道热力图、RSSI 曲线（纯 HTML/JS 或轻量框架，少依赖）
- 数据通道：优先 Web Serial（浏览器直连串口/pty 虚拟串口）；备选 Python 后端（解析 `serial_wifi_plot.py` 同款格式 + WebSocket 推前端）
- `tools/` 下新增数据接入脚本 + 演示：`esp8266_sim.py --sniffer-demo` 输出直接灌入仪表盘
- 截图/演示录屏 + 使用说明

**无硬件仿真路径**
- 完全不需要真实硬件：pty 虚拟串口就是数据源，仪表盘在 PC 浏览器直接演示；
  真机接入仅需把数据源换成 `/dev/tty.usbserial-XXXX`（阶段 7 产物）。

**验收标准**
1. 模拟器数据实时刷新：AP 列表正确、信道热力图按 1/6/11 分布、RSSI 曲线连续；
2. 页面在浏览器打开即可用，无外部服务依赖（纯本地）；
3. 真机串口接入（若有）不改变前端逻辑。

**优先级与依赖**
- P2：展示层增强，不阻塞任何研究主线；
- 依赖：阶段 7 真机数据为可选项，**默认先接模拟器**，因此可在无硬件时启动；
- 参考：xiixim101-pixel/sniffus、AsHfIEXE/SigVoid（见 roadmap 阶段 5 参考项目）。

---

### 阶段 11：SDR 频谱仪落地（PC 端 rtl_power 优先）· P2

**目标**
落实阶段 6 可行性结论：**PC 端 rtl_power 优先**，用 RTL-SDR（进阶档 ¥200-260）扫 2.4GHz
WiFi 频段并出频谱热力图；F7 直解（STM32 端 FFT）为可选扩展，不作为默认路径。

**关键交付物**
- PC 端一键脚本：`tools/rtl_power_scan.sh`（rtl_power 抓 2400-2500MHz → CSV → 绘图脚本出热力图）
- 自绘频谱绘图脚本（纯 Python/标准库，出 PNG 热力图；不依赖 rtl_power 自带 heatmap 也可用）
- 使用说明 + 实测结果：2.4GHz 频段能看出 WiFi 信道占用（对比 `iw`/手机扫描）
- （可选）阶段 6 文档中 F7 直解路径的原型或明确标注为"跳过/搁置"

**无硬件仿真路径**
- 用公开/模拟频谱数据（CSV）跑通绘图脚本，验证出图管线；真机只需一次性接入 RTL-SDR 采样。
- 注意阶段 6 结论：RTL-SDR 覆盖上限约 1.7GHz，**看 2.4GHz 需 upconverter**；
  若未购 upconverter，可先扫 FM/GSM 等 1.7GHz 以下频段验证链路，WiFi 频段留待 upconverter 到位。

**验收标准**
1. 绘图脚本对公开/模拟 CSV 出图成功；
2. 真机 rtl_power 扫 2.4GHz（含 upconverter）或低频段出热力图，信道占用可辨识；
3. 文档明确记录"PC rtl_power 为默认、F7 直解为可选/搁置"的取舍。

**优先级与依赖**
- P2：频谱是独立探索线，不影响其余阶段；
- 依赖：阶段 6 可行性（已完成）；硬件投入较高（进阶档），**可整阶段跳过**，
  仅保留绘图脚本与模拟数据演示也能形成交付物。

## 3. 建议路线

**推荐执行顺序（按优先级与收益）**

1. **先做阶段 9 的 M1-M3（P1，无硬件可推进）**：这是"代码产出"最确定的路径，
   解析/聚合逻辑纯 PC 仿真即可完成，风险最低。
2. **并行推进阶段 7（P0，采购+实物联调）**：硬件是后续真实数据的地基；
   经济档 ¥70 投入小，联调一次即可为阶段 8/10 提供真实数据源。
3. **阶段 8（P1）穿插执行**：不依赖阶段 7 的板子，只依赖一台 Linux 机器；
   建议在阶段 9 仿真跑通后集中做一次真实抓包+解密验证，一次性闭环阶段 4 的真伪性疑问。
4. **阶段 10（P2）随时可启动**：先接模拟器数据做仪表盘，等阶段 7 真机串口数据到位后再切数据源。
5. **阶段 11（P2）独立探索**：若已购 RTL-SDR 可提前；否则只做绘图脚本 + 模拟数据演示。

**可并行项**
- 阶段 7 与阶段 9 并行（硬件联调 vs ESP32 仿真代码，互不阻塞）；
- 阶段 10 与阶段 8 并行（仪表盘接模拟器，抓包解密独立进行）；
- 阶段 11 全程可独立并行。

**可跳过项**
- 阶段 11 的 **F7 直解**（STM32 端 FFT）可跳过——PC rtl_power 已覆盖需求；
- 进阶档硬件（F4/F7 + HackRF One）非必需，按需购买；
- 阶段 8 若确实无 Linux 机器，可用 Wireshark 公开样例完成"解密器验证"这一核心目标，
  真实抓包部分降级为文档记录待办。

**关键决策点**
- 采购决策：先经济档（¥70）验证接线与固件，再按需升级标准档/进阶档；
- upconverter 决策：若目标明确是 2.4GHz WiFi 频谱，需先备 upconverter，否则阶段 11 先扫低频段验证链路。

## 4. 与阶段 1-6 的复用关系

| v2 阶段 | 复用的已有资产 |
|---|---|
| 阶段 7 | `stm32_project/`（阶段 1）、`tools/serial_wifi_plot.py`、`docs/采购清单与接线方案.md` |
| 阶段 8 | `docs/Linux抓包操作指引.md`（阶段 3）、`wpa2_handshake.py` + `tests/fixtures/wpa2_handshake.pcap`（阶段 4）、`wifi_frame_parser.py`（阶段 1/3） |
| 阶段 9 | `docs/ESP32版设计文档.md`（阶段 5）、`ap_parser.c`（阶段 1）、`wifi_frame_parser.py`（阶段 2） |
| 阶段 10 | `esp8266_sim.py`（阶段 1/2，pty 数据源）、`tools/serial_wifi_plot.py` 数据格式；参考 sniffus / SigVoid |
| 阶段 11 | `docs/RTL-SDR频谱方案.md`（阶段 6 可行性结论）、进阶档采购清单 |
*（内容由AI生成，仅供参考）*
*（内容由AI生成，仅供参考）*
