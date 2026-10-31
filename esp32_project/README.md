---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 0bd2c4904e701d4269608d4ce4d80073_f420d195d53d11f1a0da525400393706
    ReservedCode1: 6RGWUviaSPrZ4vcTedTm3DwztEipNt7l5pxnxdPhNgQcYfYyO2zMwr/nGMo8tyFX3KnoROKNELIbpqZxjWDHBcnv4Fjq0PiLxCyCCvEC8db67LEBYwPi2M1g+kEC1iMl0QFVQ+/f12V+BB/BpXRsQMsOxBs1vJO2usYBlTGIJ2juYi6KwQJWDurQk+Q=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 0bd2c4904e701d4269608d4ce4d80073_f420d195d53d11f1a0da525400393706
    ReservedCode2: 6RGWUviaSPrZ4vcTedTm3DwztEipNt7l5pxnxdPhNgQcYfYyO2zMwr/nGMo8tyFX3KnoROKNELIbpqZxjWDHBcnv4Fjq0PiLxCyCCvEC8db67LEBYwPi2M1g+kEC1iMl0QFVQ+/f12V+BB/BpXRsQMsOxBs1vJO2usYBlTGIJ2juYi6KwQJWDurQk+Q=
---



# esp32_project —— ESP32 版实现（v2 路线图 阶段9 / M1-M4）

> 对应 [docs/ESP32版设计文档.md](../docs/ESP32版设计文档.md) 与
> [docs/wifi_scan_sim_roadmap_v2.md](../docs/wifi_scan_sim_roadmap_v2.md) 阶段9。
> 本阶段交付 **M1-M4**：纯 PC 仿真、无需硬件；ESP-IDF 固件（M3 真机）、
> 真机联调（M5）为后续里程碑，不在本次范围。

## 里程碑推进记录

### M1 直扫结果解析 —— 完成 ✅

- 新增 `esp32_ap_parser.py`：把 ESP-IDF `esp_wifi_scan_get_ap_records()` 返回的
  `wifi_ap_record_t`（字典对齐字段）标准化为统一 `ApInfo` 结构。
- 覆盖边界：
  - 隐藏 SSID：ssid 为空串或全 NUL 字节 → `hidden=True`，展示名 `<hidden>`
  - SSID 超 32 字节截断（ESP32 协议栈上限）
  - BSSID 归一：冒号 / 短横 / 无分隔 hex / `bytes[6]` → 统一小写冒号形式
  - authmode 枚举映射（OPEN/WEP/WPA_PSK/WPA2_PSK/WPA_WPA2_PSK/…），越界记 `UNKNOWN`
  - 非法记录（bssid 非法、rssi/channel 类型错误）拒绝并计数
- 单测：`tests/test_esp32_parser.py`（10 项，含隐藏 SSID、广播/全 NUL、多形态 BSSID）。

### M2 AP 聚合逻辑 —— 完成 ✅

- 新增 `esp32_collector.py`：
  - `ApCollector`：按 BSSID 去重合并多轮扫描（seen_count 累计；SSID 合并
    优先保留可见；RSSI 策略 latest/best；信道更新）
  - RSSI 降序排序、`channel_stats()` 信道统计、`top_aps(n)`
  - `ProbeCollector`：按 STA MAC 聚合探测记录，广播探测记 `<broadcast>`
- 单测：`tests/test_esp32_collector.py`（10 项，覆盖去重 / 排序 / 信道统计 /
  隐藏→可见合并 / probe 聚合）。

### M3 上报通道消息格式与仿真演示 —— 完成 ✅

- 新增 `esp32_reporter.py`：
  - 串口文本：`+SNIFF:AP,<bssid>,<ssid|hidden>,<rssi>,<ch>,<authmode>`、
    `+SNIFF:PROBE,"<ssid>",<sta>,<rssi>`（对齐阶段2 报告格式）
  - WebSocket JSON 快照：`{"type":"snapshot","ts_ms":...,"channel":...,"aps":[...],"probes":[...]}`
    （对齐设计文档 3.4 结构）
- 仿真演示：`esp32_sim.py` 构造 3 轮 ESP-IDF 扫描记录（含隐藏 SSID、同 BSSID
  重复观测、新 AP 出现），跑通「直扫 → 解析 → 聚合 → 上报」全链路；
  支持 `--json-only`（WebSocket 仿真）与 `--pty`（pty 虚拟串口写入 +SNIFF 文本）。
- 单测：`tests/test_esp32_reporter.py`（5 项，串口格式 + JSON 快照结构 + 回读）。

### M4 端侧仪表盘对接 —— 完成 ✅

- 新增 `esp32_consumer.py`：数据消费/展示模型。消费 WebSocket JSON snapshot
  （解析、容错非法 JSON / 未知消息 / 字段缺失，隐藏 SSID 判定对齐 M1）与
  `+SNIFF` 串口文本（按行解析 AP / PROBE，坏行只跳过不中断），输出
  仪表盘可直接渲染的展示模型：按 RSSI 降序的 AP 行（SSID/BSSID/RSSI/信道/
  加密/beacons）、信道分布、去重/总数/探测统计。
- 新增 `esp32_bridge.py`：极简数据桥（纯标准库 socket/threading/hashlib/base64/
  struct）。同一端口区分 WebSocket 升级与普通 HTTP：
  - `ws://127.0.0.1:8765/ws`：每 1 秒向客户端推送 snapshot（aps 在 M3 字段
    基础上附加 `authmode_name` 加密类型）
  - `http://127.0.0.1:8765/`：返回 `dashboard.html` 单页
  - `http://127.0.0.1:8765/api/snapshot`：最近一条快照 JSON（轮询兜底）
  - `--serial`：在 stdout 输出 `+SNIFF` 串口文本（等价消费串口通道）
- 新增 `dashboard.html`：纯手写 HTML/CSS/JS 单页（无外部框架，无 CDN），
  WebSocket 订阅 + 断线自动切轮询；展示 AP 列表表格（RSSI 分级配色、
  隐藏 SSID 样式）、信道分布条形图、AP 总数/去重/探测统计与更新时间。
- 新增 `esp32_sub_cli.py`：命令行订阅端。`--ws` 以最小 RFC6455 客户端
  （握手 + Accept 校验 + 文本帧解码）订阅快照并打印表格；`--serial` 从
  stdin/文件解析 `+SNIFF` 文本。
- 单测：`tests/test_esp32_consumer.py`（17 项，覆盖 snapshot 解析与容错、
  RSSI 排序、信道分布、展示统计、串口文本解析、WebSocket 帧编码、订阅端
  URL 解析）。

## 仿真路径与设计文档对应

| 设计文档 L 路径 | 本仓库落地 |
|---|---|
| L1 PC 侧解析复用（复用阶段1/2 解析逻辑） | `esp32_ap_parser.py`（M1） |
| L2 固件仿真链路（桩帧 → 解析 → 聚合 → 输出） | `esp32_sim.py` + `esp32_collector.py` + `esp32_reporter.py`（M2/M3） |
| L3 实体 ESP32 直扫 | 待 M5 真机（需硬件，未执行） |
| L4 Web 仪表盘对接 | `esp32_bridge.py` + `dashboard.html` + `esp32_sub_cli.py`（M4） |

## 运行方法

```bash
# 单测（4 个文件独立可跑，pytest 亦兼容）
python3 esp32_project/tests/test_esp32_parser.py
python3 esp32_project/tests/test_esp32_collector.py
python3 esp32_project/tests/test_esp32_reporter.py
python3 esp32_project/tests/test_esp32_consumer.py

# 仿真演示
python3 esp32_project/esp32_sim.py            # stdout 串口 + JSON
python3 esp32_project/esp32_sim.py --json-only
python3 esp32_project/esp32_sim.py --pty      # pty 虚拟串口

# M4 端侧仪表盘
python3 esp32_project/esp32_bridge.py         # 启动 http://127.0.0.1:8765/ + ws://…/ws
# 浏览器打开 http://127.0.0.1:8765/ 即可查看仪表盘
python3 esp32_project/esp32_sub_cli.py --ws ws://127.0.0.1:8765/ws --once
python3 esp32_project/esp32_bridge.py --serial | python3 esp32_project/esp32_sub_cli.py --serial
```

## 设计说明与后续

- 解析与聚合核心**纯手写、标准库少依赖**（re/json/os/pty/time/socket/hashlib/
  base64/struct/threading），无第三方包。
- 直扫部分以设计文档接口为准，用构造模拟数据代替真实 ESP-IDF 调用；
  ESP-IDF 侧仅需在 `esp_wifi_scan_start()` 回调后把 `wifi_ap_record_t`
  序列化为本模块输入即可接入；M4 数据桥可作为真机串口/网络上报的 PC 侧
  参考实现（见 M5 待做）。
- 待做：M3 真机固件（ESP-IDF 工程）、M5 真机联调（可选）。
*（内容由AI生成，仅供参考）*
*（内容由AI生成，仅供参考）*
