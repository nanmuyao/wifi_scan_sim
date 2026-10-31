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
| `esp8266_sim.py` | ESP8266 AT 固件模拟器 | 用 pty 创建虚拟串口，预置 8 个虚拟 AP，响应 AT / AT+CWMODE / AT+CWLAP；阶段 2 扩展：AT+CWSNIFF 开关 promiscuous 嗅探，按间隔主动推送预置的 Probe Request 报告（SSID/MAC/RSSI），支持 `--sniffer-demo` 一键演示 |
| `ap_parser.c` / `ap_parser.h` | CWLAP 解析库（纯 C） | STM32 核心解析逻辑，无 HAL 依赖，PC 可直接编译测试 |
| `test_ap_parser.c` | 解析器单元测试 | 7 组用例：正常多 AP / 隐藏 SSID / 转义字符 / 空响应 / 干扰行 / 非法参数 / AT 响应收尾判定 |
| `wifi_frame_parser.py` | 802.11 帧解析器（纯手写） | 解析 Beacon / Probe Request / 加密数据帧；scapy 仅用于生成标准测试帧；可读 pcap 文件逐帧解析 |
| `wpa2_handshake.py` | WPA2 密钥推导 + EAPOL 四次握手解析 + CCMP 解密（纯手写，阶段 4） | `--pmk`：PBKDF2-HMAC-SHA1 推导 PMK（含 802.11i 标准向量校验）；`--pcap`：从 pcap 提取 EAPOL-Key，区分握手 1/4~4/4，输出 ANonce/SNonce/MIC/Key Info 并对 M2~M4 做 MIC 校验；`--ptk`：PRF-512 展开 PTK 并切分 KCK/KEK/TK（4.1.3）；4.1.5：AES-128-CCM 手写拼装，TK 解 CCMP 加密 QoS Data 帧并校验 8 字节 MIC |
| `tests/test_wpa2_handshake.py` | 阶段 4 单元测试 | PMK 标准向量（password/IEEE）+ M1~M4 手工构造帧 + pcap 全链路 + 4.1.3 PTK 推导 / 4.1.4 MIC 校验（含错口令反向用例与 TKIP 跳过）/ 4.1.5 CCMP 解密（还原 LLC/SNAP+IP、AAD 屏蔽位、错 TK 反向），全部通过时退出码 0 |
| `tools/make_wpa2_handshake_pcap.py` | 生成四次握手 + CCMP 加密数据帧 pcap 样本 | 用 scapy 构造 802.11 QoS Data + LLC/SNAP + EAPOL M1/M2/M3/M4（KCK 计算真实 MIC）+ 1 帧 CCMP 加密 QoS Data（TK 加密 LLC/SNAP+IP），输出到 `tests/fixtures/wpa2_handshake.pcap` |
| `stm32_project/` | STM32 完整工程（CubeMX .ioc + 源码） | F103C8T6 + USART1(ESP8266) + USART2(调试)，复用 ap_parser 解析库，修正逐字节接收缓冲、NUL 结尾、帧结束判定（看 OK/ERROR/FAIL 终止行）三处隐患 |
| `tools/serial_wifi_plot.py` | 串口实时绘图脚本 | 解析 `[i] ch=.. rssi=.. enc=.. ssid=..` 输出，画信道热力图 + RSSI 时间曲线，Ctrl+C 保存 PNG |
| `docs/Linux抓包操作指引.md` | Linux 监听模式抓包指引（阶段 3） | macOS 无 RFMON 已实测（tcpdump -I 收不到帧），指引用户在有监听模式的 Linux 机器上抓包回传，再用 `wifi_frame_parser.py` 验证；含步骤与常见问题 |
| `docs/采购清单与接线方案.md` | 三档采购清单 + 接线图 | 经济档 ¥70 / 标准档 ¥200 / 进阶档 ¥1300（频谱版） |
| `docs/ESP32版设计文档.md` | ESP32 版设计文档（阶段 5） | 硬件选型差异（ESP32 vs STM32+ESP8266）、软件架构（直扫→解析→聚合→WebSocket/Web Serial 仪表盘）、ESP-IDF/Wokwi/qemu 仿真路径、与阶段1-4 代码复用关系、里程碑拆分与验收标准 |
| `docs/RTL-SDR频谱方案.md` | RTL-SDR 频谱方案可行性文档（阶段 6 · 路线B） | STM32F7 直解 vs PC 端 rtl_power vs 混合三方案对比、硬件需求与成本、数据率/FFT 瓶颈（4.8-6.4 MB/s I/Q 流 + DMA 乒乓）、软件架构建议、无硬件仿真路径（L1-L4）、可行性结论（F7 算力够、RTL-SDR 覆盖上限 ~1.7GHz 需 upconverter 才能看 2.4GHz WiFi） |

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

### 1b. 固件接收链路仿真测试（Docker）

把 `stm32_project/Core/Src/main.c` 的**真实代码**（接收回调、`esp_wait`、`parse_cwlap`）
加一层 HAL 桩编译到 PC，经虚拟串口连到 `esp8266_sim.py`，扫满 3 轮后逐项比对 8 个 AP，
同时检查接收中断有无溢出。需要 Docker：

```bash
bash tests/sim_chain/run.sh
```

用旧版 `main.c`（帧结束判断错误）跑同一个测试会因握手永远完不成而触发看门狗超时，
说明测试能抓到这类问题。

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

### 3b. 嗅探演示：promiscuous 模式抓 Probe Request（阶段 2）

```bash
python3 esp8266_sim.py --sniffer-demo
```

仿真真实 ESP8266 promiscuous 嗅探：`AT+CWSNIFF=1` 开启后模拟器**主动上报**（非查询式）
Probe Request 报告，格式对齐 kalanda/esp8266-sniffer：

```
+SNIFF:PROBE,"<SSID>",<STA MAC>,<RSSI>
```

- 6 条预置虚拟 Probe：含定向探测（目标 SSID）与广播探测（空 SSID，显示 `<broadcast>`）
- 演示流程：开嗅探 → 自动收集 6 条报告 → 关嗅探 → 打印汇总
- 手动模式下也可用串口工具发 `AT+CWSNIFF=1` / `AT+CWSNIFF=0` 交互观察

### 4. 802.11 数据包解析（pcap）

```bash
# 演示：生成混合流量 pcap（beacon/probe/控制帧/加密数据帧）并逐帧解析
python3 wifi_frame_parser.py

# 解析真实抓包（macOS 需管理员权限开监听模式）
sudo tcpdump -I -i en0 -w capture.pcap
python3 wifi_frame_parser.py --pcap capture.pcap
```

> **macOS 监听模式限制（实测）**：Apple Silicon / 802.11ac+ 网卡不支持真 RFMON，
> `tcpdump -I -i en0` 虽显示 `link-type IEEE802_11_RADIO` 但收不到任何帧（0 packets），
> `awdl0` 直接报 `doesn't support monitor mode`。解析器已用 demo.pcap（scapy 构造的
> Radiotap 混合流量，17 帧全类型）与 en0 真实大流量 pcap（17312 帧容器解析）双重验证。
> 若要真实 802.11 管理帧，需在支持监听模式的 Linux 机器抓包后拿回解析。

解析器为纯手写字节级实现（pcap 容器解析 + 802.11 帧解析均不依赖 scapy），支持：
- 管理帧完整解析：
  - Beacon / Probe Request / Probe Response：SSID、信道、速率、加密能力
  - Authentication：认证算法（Open/Shared Key/SAE）、事务序号、状态码及含义
  - Association Request / Response：能力、监听间隔、状态码、AID
  - Deauthentication / Disassociation：原因码及含义（含 MIC 失败、四次握手超时、不活动踢出等）
  - Action：类别（Spectrum/QoS/Block Ack/Public...）与动作码
- 控制帧短帧解析：RTS / CTS / ACK / PS-Poll（RA/TA）
- 数据帧：解析 MAC 头，WPA2 加密帧标记密文状态（无密钥不解 payload），开放网络明文可读
- 链路层：Radiotap (127) / 802.11 (105) / Ethernet (1)；pcap 微秒/纳秒与大小端 magic

### 5. WPA2 密钥推导与 EAPOL 四次握手解析（阶段 4）

```bash
# 4.1.1 PMK 推导（PBKDF2-HMAC-SHA1，含 802.11i 标准向量校验）
python3 wpa2_handshake.py --pmk --password password --ssid IEEE
# 输出：PMK = f42c6fc5...12e，一致 = True（标准向量）

# 4.1.2 EAPOL 握手解析 + 4.1.4 MIC 校验（测试样本为自建实验网络的模拟握手，仅用于研究学习）
python3 wpa2_handshake.py --pcap tests/fixtures/wpa2_handshake.pcap --password password --ap-mac aa:bb:cc:dd:ee:01 --sta-mac 11:22:33:44:55:66
# 输出 4 帧：握手 1/4 (M1 AP→STA) / 2/4 (M2 STA→AP) / 3/4 (M3 AP→STA) / 4/4 (M4 STA→AP)
# 每帧含 Key Info 位分解、replay counter、ANonce/SNonce、MIC、Key Data 状态；
# M2~M4 额外输出 MIC 校验结果（口令正确 → 一致）

# 4.1.3 PTK 推导演示（PRF-512 展开并切分 KCK/KEK/TK）
python3 wpa2_handshake.py --ptk --password password --ap-mac aa:bb:cc:dd:ee:01 --sta-mac 11:22:33:44:55:66

# 重新生成测试样本（scapy 构造 M1~M4 + CCMP 加密 QoS Data 帧）
python3 tools/make_wpa2_handshake_pcap.py

# 单元测试（4.1.5 需 pycryptodome，其余纯标准库）
python3 tests/test_wpa2_handshake.py
```

阶段 4 说明：
- PMK 推导仅用 `hashlib.pbkdf2_hmac`（标准库），无第三方依赖；
- EAPOL 解析从 802.11 数据帧的 LLC/SNAP（EtherType 0x888e）提取 EAPOL-Key，
  依据 Key Info 的 ACK/Secure 位与 Nonce/MIC 状态区分 M1~M4；
- 4.1.3 PTK 用 `PRF-512(PMK, "Pairwise key expansion", min/max 排序的 MAC 与 Nonce)` 展开，
  切分为 KCK/KEK/TK，正确性由 4.1.4 的 MIC 校验间接验证；
- 4.1.4 MIC 校验：仅支持 Key Descriptor Version=2（AES/CCMP），MIC 字段清零后
  HMAC-SHA1(KCK) 取前 16 字节比对，TKIP（v1）直接跳过；
- 4.1.5 CCMP 解密：nonce = 优先级‖A2‖PN（13 字节），AAD 由 MAC 头屏蔽 FC 高字节
  可变位与 Seq 序号位得到，AES-128-CCM 拼装手写（仅引入 pycryptodome 的 AES 原语），
  解密成功以还原 LLC/SNAP（AA AA 03 00 00 00）+ IP 头为准；
- 合法边界：仅用于已知口令 / 自建网络研究学习，不做口令爆破。

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

## 协议

[MIT](LICENSE)
*（内容由AI生成，仅供参考）*
