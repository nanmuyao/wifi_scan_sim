---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 0bd2c4904e701d4269608d4ce4d80073_867a159fd44411f180d5525400248c00
    ReservedCode1: BAFAp1hAkISE4mZDRg5vZAb70Q7PSI8ndn5yEa/Fc6/f4TMcReHqZxgQHYMMursfsW+KROBMzcUP6sv1ZUI+KU8DtE9DljcjvOSM2UvQivKm3phk1dnkluDyN/zw4RtlyXI1XEMa1TO2pPUNYYVlNKrQ/+DKh0snSoAB3bS6FLO2AXPwWrL8c573OBM=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 0bd2c4904e701d4269608d4ce4d80073_867a159fd44411f180d5525400248c00
    ReservedCode2: BAFAp1hAkISE4mZDRg5vZAb70Q7PSI8ndn5yEa/Fc6/f4TMcReHqZxgQHYMMursfsW+KROBMzcUP6sv1ZUI+KU8DtE9DljcjvOSM2UvQivKm3phk1dnkluDyN/zw4RtlyXI1XEMa1TO2pPUNYYVlNKrQ/+DKh0snSoAB3bS6FLO2AXPwWrL8c573OBM=
---

# STM32 WiFi 扫描 · 无硬件仿真开发套件

用 PC 仿真替代实物开发调试 STM32 + ESP8266 的 WiFi 扫描方案。**目标：先跑通逻辑，再买硬件。**

## 文件结构

| 文件 | 角色 | 说明 |
|------|------|------|
| `esp8266_sim.py` | ESP8266 AT 固件模拟器 | 用 pty 创建虚拟串口，预置 8 个虚拟 AP，响应 AT / AT+CWMODE / AT+CWLAP |
| `ap_parser.c` / `ap_parser.h` | CWLAP 解析库（纯 C） | STM32 核心解析逻辑，无 HAL 依赖，PC 可直接编译测试 |
| `test_ap_parser.c` | 解析器单元测试 | 6 组用例：正常多 AP / 隐藏 SSID / 转义字符 / 空响应 / 干扰行 / 非法参数 |
| `wifi_frame_parser.py` | 802.11 帧解析器（纯手写） | 解析 Beacon / Probe Request / 加密数据帧；scapy 仅用于生成标准测试帧 |

## 仿真层次

```
第 1 层（逻辑）：C 解析库 ap_parser.c 在 PC 上用 gcc 编译跑单测
      ↓ 同一份代码可直接放进 STM32 工程（仅替换 printf 为 UART 输出）
第 2 层（链路）：esp8266_sim.py 提供虚拟串口，模拟 STM32 侧发 AT 命令并解析
      ↓ 真实硬件上把虚拟串口路径换成 UART1 即可
第 3 层（硬件）：STM32 + ESP8266 实物联调（此阶段再买板子）
```

## 使用方法

### 1. 跑 C 解析器单元测试（无需任何工具链）

```bash
gcc -o test_ap_parser test_ap_parser.c ap_parser.c
./test_ap_parser
```

### 2. 自动演示：模拟器 + 客户端全流程

```bash
python3 esp8266_sim.py
```

输出：握手 OK → 设 Station 模式 OK → 连续 3 次扫描，每次解析 8 个 AP（含隐藏 SSID）。

### 3. 手动交互：只起模拟器，外部串口工具连接

```bash
python3 esp8266_sim.py --manual
```

按提示用串口工具（如 minicom / CoolTerm / 串口调试助手）连接打印出的虚拟串口路径
（如 `/dev/ttys007`，波特率无关，pty 无真实波特率），发送 `AT`、`AT+CWMODE=1`、
`AT+CWLAP` 观察响应。

## 仿真 vs 真实硬件的差异（务必知晓）

| 维度 | 仿真 | 真实硬件 |
|------|------|----------|
| 扫描结果 | 固定预置 8 个虚拟 AP | 真实环境 AP，数量/信号随机 |
| 串口 | pty 虚拟串口，无波特率概念 | USART1 115200，需接线 |
| 时序 | 固定 0.2s 处理延迟 | 取决于模块固件与信道扫描时间 |
| 输入边界 | 已覆盖空 SSID / 转义 / 干扰行 | 真实固件还有其它变体需实测 |

## 踩坑记录（本次仿真发现的问题，移植时直接避开）

1. **pty 必须设 raw 模式（cfmakeraw）**：默认 canonical 行规程会把 `\r\n` 转成 `\n` 且按行缓冲，长响应丢数据；真实 UART 是纯字节流，没有行规程。
2. **macOS 双线程交叉读写 pty 有坑**：模拟器线程写 master、主线程 select slave 时，写入无法唤醒读端 select。改为单线程 select 多路复用（模拟器 poll 与客户端读交替）后正常。
3. **os.write 只接受 bytes**：格式化 `+CWLAP` 响应时先 `encode()`，否则抛 TypeError 导致模拟器静默死亡。
4. **CWLAP 解析三个真实格式坑**：
   - 空 SSID：`+CWLAP:(0,"",-70,...)`，`sscanf %[^"]` 无法匹配空串，必须手写状态机；
   - 转义字符：SSID 内逗号/引号输出为 `\,` 和 `\"`，需去转义还原；
   - `strncpy` 不保证 NUL 结尾，拷贝后必须显式补 `'\0'`。

## 移植到 STM32 的步骤

1. 把 `ap_parser.c` / `ap_parser.h` 加入 STM32 工程；
2. `ap_print()` 内的 `printf` 换成 `HAL_UART_Transmit`（或重定向 printf 到 UART1）；
3. USART1 中断接收字节存入环形缓冲，攒到 `\n` 后调用 `parse_cwlap()`；
4. 主循环每 10s 发一次 `AT+CWLAP`，解析结果打印/上报。
*（内容由AI生成，仅供参考）*
