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

# ESP32 版设计文档（阶段 5）

## 1. 目标与范围

- **目标**：用 ESP32 内置 WiFi 的 promiscuous 模式**直扫** 802.11 管理帧（Beacon / Probe Request / Probe Response），解析出 SSID / BSSID / STA MAC / RSSI / 信道等字段，聚合后通过 WebSocket 或 Web Serial 推送到浏览器仪表盘实时展示（参考 xiixim101-pixel/sniffus 的 Web Serial UI 思路）。
- **范围**：研究学习用途，仅监听**自建实验网络**与公共环境广播帧，不爆破、不攻击、不抓取并解密他人受保护流量（见第 8 节合法性边界）。
- **与阶段 1-4 的关系**：复用阶段 1-3 的手写 802.11 解析逻辑与 pty 仿真测试思路，在 ESP32 上重新落地"采集 → 解析 → 展示"全链路；阶段 4 的 WPA2 解密不进入本阶段固件（仅作参考）。

## 2. 硬件选型与差异（ESP32 vs STM32+ESP8266）

### 2.1 对比

| 维度 | STM32F103C8T6 + ESP8266（阶段 1） | ESP32（本阶段） |
|------|-----------------------------------|-----------------|
| 无线接入方式 | MCU 无无线能力，经 USART AT 指令控制 ESP8266 | 芯片内置 2.4GHz 802.11 b/g/n 射频与协议栈 |
| 抓包能力 | 仅能拿 `AT+CWLAP` 扫描**摘要**（SSID/信号/加密），拿不到原始 802.11 帧；promiscuous 原始帧需经 UART 搬运，带宽受限 | `esp_wifi_set_promiscuous()` 直接接收原始 802.11 帧（管理/数据/控制帧均可达回调） |
| 处理核心 | 单核 Cortex-M3 72MHz，仅做 AT 解析与展示 | 双核 Xtensa LX6 240MHz（ESP32）/ 双核 LX7 240MHz（ESP32-S3），可独立任务处理采集与网络 |
| 内存 | 20KB SRAM，帧数据只能流式处理 | 520KB SRAM（S3 为 512KB），可容纳环形帧缓冲与聚合表 |
| Web 服务 | 无，需外接串口/上位机 | 内置 TCP/IP 栈，ESP-IDF 提供 HTTP 服务器 / WebSocket 组件，Arduino 提供 WiFiServer |
| 外设 | 需 USART 接线（+3.3V/GND/TX/RX 四线） | 单板集成，USB-UART 即可供电与烧录 |
| 典型成本 | 板 + 模块约 ¥20-30（已有） | ESP32-DevKitC / NodeMCU-32S / ESP32-WROOM-32 约 ¥20-40 |

### 2.2 差异要点

1. **直扫原始帧 vs AT 摘要**：ESP8266 AT 模式只能返回 CWLAP 摘要（阶段 1 已实现解析）；要拿 Probe Request 这类原始帧必须切 promiscuous 并经 UART 搬运（阶段 2 仿真了该场景）。ESP32 直接在芯片内收原始帧，解析在本地完成，**无需外挂 AT 模块**，链路更短、无波特率瓶颈。
2. **板级集成 vs 双芯片**：ESP32 单芯片方案免除接线与握手协议（AT/CWMODE/CWLAP），固件复杂度显著降低。
3. **Web 能力内置**：ESP32 可直接充当 Web 服务器（HTTP + WebSocket），浏览器直连设备即可看仪表盘，不必依赖 PC 端 Python 绘图（对比 `tools/serial_wifi_plot.py` 的上位机模式）。

### 2.3 选型建议

- 首选 **ESP32-DevKitC（ESP32-WROOM-32）**：文档多、双核 240MHz、SRAM 充足，满足本阶段全部需求；
- 可选 **ESP32-S3**：主频更高、支持 USB，Web 场景更顺，但功耗与生态差异不影响本设计；
- 仅作对比、不推荐：ESP8266 单做嗅探（阶段 1 方案已覆盖 AT 模式），ESP32-C3 资源偏小（单核 160MHz、400KB SRAM，可作为降级选项）。

## 3. 软件架构

### 3.1 分层视图

```
┌─────────────────────────────────────────────────────────┐
│  展示层：浏览器仪表盘（HTML/JS，WebSocket 或 Web Serial） │
├─────────────────────────────────────────────────────────┤
│  服务层：WebSocket 推送 / 串口 CLI（+SNIFF 风格输出）      │
├─────────────────────────────────────────────────────────┤
│  聚合层：collector —— 环形缓冲 + 按 AP/STA 聚合去重统计   │
├─────────────────────────────────────────────────────────┤
│  解析层：frame_parser —— 802.11 管理帧解析（自阶段1-3移植）│
├─────────────────────────────────────────────────────────┤
│  采集层：wifi_sniffer —— promiscuous 回调 + 信道轮转      │
└─────────────────────────────────────────────────────────┘
```

### 3.2 模块划分

| 模块 | 职责 | 对应阶段 1-4 资产 |
|------|------|--------------------|
| `wifi_sniffer` | 注册 `esp_wifi_set_promiscuous_rx_cb()` 回调；接收原始帧后**投递到采集任务队列**（不在回调内做耗时解析）；控制信道轮转 | esp8266_sim.py 的嗅探行为（`AT+CWSNIFF` 开关、主动上报思路） |
| `frame_parser` | 从原始帧偏移解析 802.11 头与帧体：Beacon（SSID、信道、加密能力）、Probe Request（SSID 为空则广播）、Probe Response、可选 Beacon 间 dtls | `wifi_frame_parser.py` 的纯手写解析逻辑（管理帧部分 1:1 移植） |
| `collector` | 内存结构聚合：按 BSSID 聚合 AP 表、按 STA MAC 聚合探测表、去重（timeout 内重复帧合并）、计数与 RSSI 滑动更新 | `wifi_frame_parser.py` 输出格式；阶段 2 `+SNIFF:PROBE` 报告字段 |
| `server` | 两个输出通道：① HTTP 静态页 + WebSocket 实时推送（JSON）；② 串口 `+SNIFF` 风格文本输出（兼容上位机/plot 脚本） | `tools/serial_wifi_plot.py` 的解析协议 |
| `dashboard` | 浏览器端页面：AP 表格 / Probe 列表 / 信道热力图 / RSSI 曲线，实时刷新 | 参考 sniffus Web Serial UI、AsHfIEXE/SigVoid PWA |

### 3.3 数据流

```
Beacon / Probe Request（射频）
   │ promiscuous 回调（中断上下文，仅拷贝）
   ▼
帧缓冲（预分配 DMA/环形，例如 64 × 512B）
   │ 采集任务（FreeRTOS task）出队
   ▼
frame_parser 解析 → 原始帧摘要（ssid/bssid/sta/rssi/channel/fc）
   │
   ▼
collector 聚合（AP 表 / STA 表 / 信道统计）
   │
   ├──→ WebSocket 推送（JSON 增量/全量快照）
   │
   └──→ 串口文本输出（+SNIFF:BEACON / +SNIFF:PROBE，兼容上位机）
            │
            ▼
浏览器仪表盘 或  PC 端 tools/serial_wifi_plot.py
```

- **回调职责最小化**：promiscuous 回调发生在 WiFi 中断上下文，只做帧拷贝并入队；解析、聚合、网络推送全部移到采集任务与服务器任务，避免丢帧与看门狗风险。
- **周期快照**：服务层每 1-2s 推送一次聚合快照（含信道轮转进度），WebSocket 全量下发 + 增量 patch 两档可选，控制带宽。

### 3.4 内存结构（示例）

```c
/* AP 表：按 BSSID 聚合 */
typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];          /* 隐藏 SSID 置空 */
    int8_t   rssi;              /* 最近观测值（可滑动平均） */
    uint8_t  channel;
    uint32_t last_seen_ms;
    uint32_t beacon_count;
} ap_entry_t;

/* STA 表：按 STA MAC 聚合（Probe 探测） */
typedef struct {
    uint8_t  sta_mac[6];
    char     probed_ssid[33];   /* 广播探测记 "<broadcast>" */
    int8_t   rssi;
    uint32_t last_seen_ms;
    uint32_t probe_count;
} sta_entry_t;
```

WebSocket 输出 JSON（与阶段 2 报告字段对齐）：

```json
{
  "type": "snapshot",
  "ts_ms": 1710000000000,
  "channel": 6,
  "aps": [
    {"bssid": "aa:bb:cc:dd:ee:01", "ssid": "MyAP", "rssi": -52, "channel": 6, "beacons": 120}
  ],
  "probes": [
    {"sta": "11:22:33:44:55:66", "ssid": "MyAP", "rssi": -61, "count": 3}
  ]
}
```

### 3.5 信道扫描策略

- 2.4GHz 共 13 信道；每信道停留 100-200ms 后切下一信道（`esp_wifi_set_channel()`），一轮约 1.3-2.6s；
- 回调中记录的帧带当前信道号；聚合时按 BSSID 记忆最近信道，避免重复 AP 错位；
- 与 sniffus 一致：扫完一轮后推送一轮快照，页面可看到"轮转进度"。

## 4. 开发环境与无硬件仿真路径

### 4.1 环境选项

| 选项 | 说明 | 适用 |
|------|------|------|
| **ESP-IDF（推荐）** | v5.x 官方框架，`idf.py build/flash/monitor`；组件 `esp_wifi`、`esp_http_server`、WebSocket server、FreeRTOS；文档齐全，promiscuous 示例（`wifi/scan`、`esp-idf` 官方 `esp_wifi_set_promiscuous` demo） | 正式开发、任务化架构 |
| Arduino（上手快） | `WiFi` 库 + `WiFiServer` / `WebSockets` 库；`WiFi.` 底层同样暴露 promiscuous（`esp_wifi_set_promiscuous_rx_cb` 可混用），示例多 | 原型、快速验证 Web UI |
| PlatformIO | 双框架统一管理，便于本地编译与单测 | 长期维护 |

推荐以 **ESP-IDF** 为主线：任务化（采集任务 / 服务器任务）与 FreeRTOS 队列天然匹配本架构；Arduino 作为 Web UI 原型备选。

### 4.2 无硬件仿真路径（沿用"先仿真、后硬件"策略）

仿真拆成三层，与阶段 1-4 的 pty + 单测双轨思路一致：

| 层 | 环境 | 做法 | 验证点 |
|----|------|------|--------|
| L1 解析单测 | PC（gcc / Python） | 移植后的 `frame_parser` 用 `wifi_demo_parse.pcap` / `demo.pcap` 中的 Beacon/Probe 帧做输入，与 `wifi_frame_parser.py` 输出逐字段比对 | 移植正确性 |
| L2 固件逻辑仿真 | **Wokwi**（浏览器）或 **qemu（espressif/qemu）** | 编译 ESP-IDF 固件到仿真环境运行；**Wokwi/qemu 无法模拟真实射频嗅探**，因此用"桩帧源"替代 `wifi_sniffer`：从预置 pcap 提取若干 Beacon/Probe 帧，周期注入解析队列 | 采集→解析→聚合→WebSocket/串口输出全链路在固件内跑通 |
| L3 硬件真扫 | 实体 ESP32（采购后） | 桩帧源替换为 `esp_wifi_set_promiscuous_rx_cb` 真实回调 | 真实环境 Beacon/Probe 捕获与展示 |

- **桩帧源设计**：`tools/make_esp32_stub_frames.py`（规划）从 `wifi_demo_parse.pcap` 提取管理帧，输出为 C 头文件数组或 JSON，固件编译时按 `CONFIG_SNIFFER_SOURCE=stub|radio` 切换；
- Wokwi 上可验证：烧录流程（固件编译）、串口 `+SNIFF` 输出、Web 服务启动；WebSocket 页面在 qemu 网络桥接下也可观察；
- **验收口径**：L1-L2 全部通过才采购硬件，避免"先买板再踩坑"。

## 5. 与阶段 1-4 代码的复用关系

| 阶段资产 | 复用方式 | 说明 |
|----------|----------|------|
| `wifi_frame_parser.py` | **直接移植**（管理帧解析部分） | 纯手写、无 scapy 依赖；Beacon/Probe Request/Response 的字段偏移、SSID/信道/加密能力提取逻辑可 1:1 翻译为 C 或对照实现；pcap 容器解析不需要（ESP32 直接收帧） |
| `ap_parser.c` / `ap_parser.h` | 风格参考 | CWLAP 解析在直扫方案中不再需要（无 AT 模式），但其"纯 C、无 HAL 依赖、PC 可编译单测"的组织方式用于 ESP32 的 `frame_parser` 落地 |
| `esp8266_sim.py` | 行为与格式参考 | `+SNIFF:PROBE,"<SSID>",<STA MAC>,<RSSI>` 报告格式继续沿用；仿真层"预置虚拟帧"思路扩展为桩帧源（L2） |
| `tests/test_sim_chain.py` | 测试模式迁移 | 桩帧注入 + 输出断言的方式迁移到 ESP32 固件单测（PC 侧 gcc 测移植解析，固件侧测聚合逻辑） |
| `tools/serial_wifi_plot.py` | 兼容演进 | 保留串口文本协议，PC 端绘图脚本可直接消费 ESP32 串口输出；Web 仪表盘是它的升级形态 |
| `demo.pcap` / `wifi_demo_parse.pcap` | 桩帧数据源 | 提取 Beacon/Probe 帧用于 L1/L2 验证，无需新造抓包 |
| `wpa2_handshake.py` | 不进入固件 | 阶段 4 解密链路线下 pcap 完成，ESP32 固件不做解密（内存与复杂度不划算），仅文档关联 |

**结论**：阶段 1-3 的解析与测试资产约可覆盖 ESP32 版 60% 以上的逻辑工作量（解析层 + 桩帧 + 输出协议），新增工作集中在 WiFi 采集、聚合与 Web 服务三块。

## 6. 里程碑拆分与验收标准

| 里程碑 | 内容 | 验收标准 | 状态 |
|--------|------|----------|------|
| M1 解析移植 + 单测 | 将 `wifi_frame_parser.py` 管理帧解析移植为 ESP32 C 模块（或 Arduino 版本），PC 侧 gcc 单测 | 预置 pcap 的 Beacon/Probe 解析结果与 `wifi_frame_parser.py` **逐字段一致**；含隐藏 SSID、广播 Probe 用例 | 待做 |
| M2 固件仿真链路 | Wokwi/qemu 跑通"桩帧 → 解析 → 聚合 → 串口/WebSocket 输出" | 仿真中注入桩帧后串口出现 `+SNIFF` 报告且 JSON 快照字段正确；L1-L2 全部通过 | 待做 |
| M3 硬件直扫 | 实体 ESP32 promiscuous 直扫，串口输出 | 真实环境能捕获 Beacon 与 Probe Request，输出含 SSID/BSSID/STA MAC/RSSI/信道；信道轮转可见 | 待做 |
| M4 Web 仪表盘 | WebSocket 实时仪表盘（或 Web Serial UI） | 浏览器打开页面实时刷新 AP 表 / Probe 列表 / 信道热力图，数据与串口输出一致 | 待做 |
| M5 联调与文档 | 全链路联调、README/roadmap 同步 | 一键演示脚本（`tools/esp32_demo` 或固件 README）跑通；文档与验收记录入库 | 待做 |

每步独立验收，前一步不过不进下一步（与阶段 4 的 4.1.x 门禁一致）。

## 7. 风险与已知难点

1. **回调上下文限制**：promiscuous 回调内禁止阻塞/打印/堆分配，必须"拷贝入队"，否则丢帧或触发看门狗；
2. **内存预算**：帧缓冲与聚合表需静态分配；Beacon 最长可达 ~500B，环形缓冲按 64×512B 起步，必要时压缩（只留摘要字段）；
3. **信道轮转丢帧**：切换信道瞬间的帧会丢，统计中标记"轮转中"避免误判 AP 消失；
4. **Web Serial 权限**：Web Serial 需要用户在浏览器中手动选择串口（HTTPS 或 localhost 限制），交互上需给足引导；
5. **5GHz 不支持**：ESP32 仅 2.4GHz，5GHz AP 扫不到，属预期范围；
6. **真实抓包仍受环境约束**：ESP32 只能被动收本机范围内的帧，验证"解析正确性"仍需以阶段 3 的 Linux 抓包回灌（pcap 离线对比）为基准。

## 8. 合法性边界（与项目整体一致）

- 仅监听/分析**自建实验网络**与环境中公开广播的管理帧（Beacon/Probe 属于主动公开信息）；
- 不攻击他人网络、不爆破口令、不解密他人受保护流量；
- 研究学习用途，不以任何形式用于未经授权的监控。
