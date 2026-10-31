# wifi_scan_sim 路线图 v3：向完整 802.11 协议支持推进

> 承接 [v2](wifi_scan_sim_roadmap_v2.md)。v2 以"买硬件、联调"为主线；v3 的目标不同：
> **在软件里尽量完整地支持 802.11 协议（帧、信息元素、加密、密钥协商），并且每一项都有可对照的标准答案。**
> 项目底线不变：学习研究用途；只处理自建网络和公开样例；不抓、不解他人流量；不做口令爆破。

## 0. 先说结论

1. **协议完整度是软件问题，不是硬件问题。** 现有的 STM32+ESP8266 只能"列出附近的 WiFi"（`AT+CWLAP`），
   看不到原始帧，所以买再多这类板子也不会让协议支持更完整。
   公开样例抓包已经覆盖了几乎所有现代协议特性，整条路线不需要买任何东西。
2. **“完整”要有尺子。** 用 Wireshark 的命令行工具 tshark 当标准答案，逐帧、逐字段对比；
   加密部分用 Wireshark 测试套件里公开的期望密钥（TK/GTK）对比。没有对照的“支持”不算支持。
3. v2 里排 P0 的“硬件联调”建议降级为可选项（见第 5 节）。

## 1. 现状基线（实测）

测量方法：下载 Wireshark 仓库 `test/captures/` 里与 802.11 / WPA 相关的 24 个公开抓包，
用 tshark 4.4.19（Debian 13 的软件包）统计里面实际出现的内容，再对照 `wifi_frame_parser.py` 的源码。

| 项目 | 样例里出现的 | 现有解析器处理的 |
|---|---|---|
| 信息元素（tag） | 23 种：0 1 3 5 7 16 42 45 47 48 50 54 55 59 61 76 90 114 127 201 221 225 244 | **4 种**：0 1 3 50（SSID、速率、信道） |
| 扩展信息元素（tag 255） | 8 种（tshark 命名）：HE Capabilities(35)、HE Operation(36)、EHT Capabilities(108)、EHT Operation(106)、Multi-Link(107)、OWE DH 参数(32)、AKM Suite Selector(114)、Rejected Groups(92) | **0 种** |
| 帧子类型 | 17 种：Beacon、QoS Data、Data、QoS Null、Probe Req/Resp、Auth、Assoc Req/Resp、Deauth、Disassoc、Action、ACK、CTS 等 | 管理帧/控制帧/数据帧主要类型已有，细节未逐帧对照过 |
| 加密套件 | WEP、TKIP、CCMP、CCMP-256、GCMP、GCMP-256、BIP（保护管理帧） | 仅 CCMP-128 |
| 认证与密钥管理 | PSK、FT-PSK/FT-EAP、EAP、SAE（WPA3）、SAE-EXT-KEY、OWE、Suite-B 192 | 仅 PSK + WPA2 四次握手 |
| radiotap | 多种 present 位组合；Wi-Fi 7 样例有多个 present 字 | 只会跳过头部，不解析字段 |
| 抓包文件格式 | 24 个文件全是 gzip，其中 18 个是 pcapng | **只认未压缩的经典 pcap：24 个样例（共 6471 帧）一个都打不开** |

这些数字是后面验收的起点：每个阶段结束时重新跑一次，数字只能往好的方向动。
重新生成：`bash tests/docker.sh bash -c "python3 tests/oracle/fetch_samples.py && python3 tests/oracle/diff.py --samples"`。

### 阶段 A 过程中发现的问题
- **控制帧、数据帧子类型表是错的**（RTS 写成 4、CTS 5、ACK 6，标准是 11、12、13；QoS Null 写成 10，标准是 12 等）。
  项目自己用同样的错误编号生成 `demo.pcap`，所以自己和自己对得上；用 tshark 对照才暴露。已修复（提交 4050928），
  并加了逐项对照 tshark 值表的测试。
- **只认经典 pcap**：这是上面 0/24 的原因，是阶段 B 的第一步（已完成，见 B0）。
- **`strip_radiotap` 是个桩**：永远剥掉固定 8 字节，真实 radiotap 头是变长的，所以任何真实抓包都会解错。已改成读头里的长度字段。

### 阶段 B0 之后的数字
24 个样例全部能打开；6461 帧里，类型 / 子类型、RA、TA、序号、分片号、时长，以及 Frame Control 的 8 个标志位，与 tshark **0 不一致、0 漏解析**。
### 帧头变体（B1）
24 个样例里 4 地址帧是 0 个、HT 控制字段 2 个、A-MSDU 1 个、分片 1 个，覆盖不到。所以用 `tests/oracle/synth.py`
按标准的字段布局手工拼了 31 种帧头（4 种 ToDS/FromDS 组合、TID 0-7、确认策略、EOSP、A-MSDU、HT 控制字段、
分片 12/13 等），仍让 tshark 当标准答案。`parse_mac_header` 改成变长帧头（addr4 / QoS Control / HT Control，
并给出 DA / SA / BSSID）；24 个样例和 31 种合成帧头与 tshark 全部一致，帧体起点用 tshark 找到的 LLC 头独立验证。
**遗留**：`wpa2_handshake.py` 的 CCMP AAD 构造仍按 3 地址帧（24/26 字节）算，4 地址帧和带 HT 控制字段的帧要在阶段 D 一并改。
### radiotap（B2）
`radiotap.py` 解析 radiotap 字段表里 0-27 位的全部字段、多位图（多天线）、厂商命名空间、TLV，以及由 HT 的 MCS 算数据速率。
与 tshark 在 24 个样例的 6471 帧上对照：头长度、TSFT、flags、速率、信道、信号、天线、rx flags、质量、MCS、A-MPDU、timestamp 全部一致。
**发现**：5 个样例的 radiotap flags 标明“帧末尾带 4 字节 FCS”（`flags & 0x10`），原来的解析器把 FCS 当成帧体；现在剥掉，并用 CRC-32 校验
（5397 帧与 tshark 的校验状态一致）。**遗留**：`wpa2_handshake.py` 有自己的偏移逻辑，不剥 FCS，阶段 D 要一并改（否则 MIC 会把 FCS 算进去）。
**没有被样例验证的**：TLV 部分起点对齐到 4 字节（按规范写，只有单元测试覆盖）；VHT / HE / HE-MU 字段只解码、没有样例对照，
也没有 VHT / HE 速率换算（这些样例里没有）。
### 信息元素遍历（C1）
`ie.py`：按出现顺序返回全部元素（重复的 ID 都保留，扩展元素带扩展 ID，被截断时前面的保留并报告），并按管理帧子类型给出固定部分长度。
旧的 `parse_tags` 用字典按 ID 存，同一帧里多个厂商元素只剩最后一个，遇到截断静默停下，也不认扩展元素；重关联请求被当成关联请求（固定部分 10 字节，不是 4）。
和 tshark 对照每一帧里**有哪些元素、什么顺序**：24 个样例 4096 帧一致；41 种合成管理帧（每个子类型、重复 ID、扩展元素、截断、加密帧体）全部一致。
**已知缺口**（测试里写成精确的数字，变好或变坏都会报错）：
| 缺口 | 帧数 | 原因 | 阶段 |
|---|---|---|---|
| 数据帧里的 EAPOL-Key，tshark 会读 Key Data 里的 RSN 元素 | 43 | 还没解析 EAPOL-Key | D |
| SAE 认证帧体不是元素序列（要按曲线组长度跳过 scalar / element） | 8 | 还没解析 SAE | E |
| Multi-Link 元素里嵌套的子元素，tshark 展开、我们不展开 | 4 | 还没解码 Multi-Link | C |
| Action 帧体里的元素（`demo.pcap` 等 2 帧） | 2 | 还没做 Action 帧各类别 | B 之后 |
对照还暴露了一个盲区：tshark 没列出元素而我们列出了（比如把加密的帧体当元素），原来会被跳过，现在算不一致。
下一步：逐个解码元素的内容（SSID、速率、DS、TIM、国家、ERP、HT、RSN……），再对照 tshark 的字段。
还没对照的帧层内容：A-MSDU 内部结构、Action 帧各类别。

## 2. 验证方法（贯穿所有阶段）

- **标准答案**：tshark 4.4.19，放进 Docker 镜像（Debian 13 软件包，固定版本）。
- **样例**：24 个公开抓包，下载脚本固定到 Wireshark 仓库的某个提交并校验 sha256。
  **不放进本仓库**：Wireshark 源码树是 GPL，本项目是 MIT，下载使用不影响许可，直接收录会。
- **差分测试**：同一个抓包，我们的解析结果与 tshark 的字段输出逐帧对比，报告“一致 / 不一致 / 我们没解析”三类数量。
- **解密对照**：Wireshark 的 `test/suite_decryption.py` 里给出了每个样例应当推导出的 TK / GTK 值（例如 `wpa3-sae` 的 TK 是 `20a2e28f…`）；我们推导出的值必须相同。密钥来源已查清（阶段 B0 实测）：24 个样例里**没有一个**带解密密钥块；Wireshark 的测试把密钥放在它自己的配置表
`test/config/80211_keys.tmpl` 里：口令 `Induction`、`test0815`、`12345678`，WEP 密钥 `1234567890`，
以及一批 `wpa-psk`（十六进制，**直接是 PMK**，用于 OWE / SAE / Suite-B / MLO 样例）和一个 `msk`（EAP 样例）。
阶段 D 开始时把这张表也按固定提交下载并校验。
**后果**：SAE 的“口令 → PMK”（hunting-and-pecking / H2E）在这些样例上**没有口令可验证**，
只能验证 PMK 之后的部分（PTK / TK / GTK）。SAE 本身的正确性要另找依据（IEEE 802.11 标准附录里的测试向量，或自建 hostapd 网络的自家抓包）。
- **变异检查**：每个新测试，故意改坏实现一处，确认测试会变红（沿用上一轮的做法）。

## 3. 阶段

按“能让多少样例通过”和依赖关系排序；串行做，每个阶段单独验收、单独提交。

### 阶段 A：验证底座
- 交付：带 tshark 的 Docker 镜像、样例下载脚本（固定提交 + sha256）、差分测试工具、基线报告（第 1 节表格自动生成）。
- 验收：一条命令生成覆盖率报告；对现有解析器给出基线数字。

### 阶段 B：帧层完整
- B0 抓包文件读取：gzip + pcapng（含 Decryption Secrets Block）。没有这一步，24 个样例一个都打不开。**已完成**：`capture.py`，6471 个包的长度、时间戳、链路类型与 tshark 一致，字节内容与 editcap 转出的 pcap 一致。
- 内容：radiotap 全字段（TSFT、速率、信道、信号、MCS/VHT/HE 等，含多个 present 字）；
  MAC 头所有变体（4 地址、QoS 控制、HT 控制、分片、顺序位）；全部管理 / 控制 / 数据子类型；Action 帧各类别；A-MSDU。
- 顺带：把单个 31KB 的 `wifi_frame_parser.py` 拆成包（`wifi80211/`：radiotap、frame、ie、action、crypto、handshake），命令行入口保持不变。
- 验收：24 个样例里每一帧的类型 / 子类型 / 地址 / 序号与 tshark 100% 一致。

### 阶段 C：信息元素
- 做法：表驱动（一张注册表，每个元素一个解码函数），未知元素原样保留而不是丢掉。
- 顺序（按样例里出现的频次）：RSN(48) → HT(45/61) → ERP(42/47)、TIM(5)、Country(7)、扩展能力(127) →
  厂商元素(221：WPA、WMM、WPS 等) → FT / 移动域(54/55)、RSNXE(244) → 扩展元素：HE(35/36)、Multi-Link(107)、EHT(106/108)、OWE DH 参数(32)、AKM Suite Selector(114)、Rejected Groups(92)。
- 验收：tshark 解出的每个 `wlan.tag.*` / `wlan.ext_tag.*` 字段，我们都有对应值；基线“4/23”变成“23/23”，扩展“0/8”变成“8/8”。

### 阶段 D：加密与密钥层（逐个套件）
按样例数量和难度排：
1. 密钥协商补全：EAPOL-Key 版本 1/2/3（MIC 用 HMAC-MD5 / HMAC-SHA1 / AES-CMAC / HMAC-SHA384）、密钥派生用 SHA-1 / SHA-256 / SHA-384、AES 密钥包装（解出 GTK）、GTK 轮换、PMKID 校验。
2. 数据面：TKIP（Michael + 密钥混合）、WEP（RC4 + CRC）、CCMP-256、GCMP-128 / 256。
3. 管理帧保护（PMF）：BIP-CMAC / GMAC，以及 IGTK。
- 验收：对应样例（`wpa2-psk-ccmp-tkip`、`wep`、`wpa-ccmp-256`、`wpa-gcmp*`、`wpa2-psk-mfp`、`wpa1-gtk-rekey`）能推导出与测试套件一致的 TK / GTK，并解出明文。

### 阶段 E：WPA3 / OWE / FT
- SAE：“hunting-and-pecking”与 H2E 两种方式，椭圆曲线组 19 / 20 / 21，commit / confirm 帧解析，PMK 推导。
- OWE：椭圆曲线 Diffie-Hellman。FT：PMK-R0 / PMK-R1 密钥层级。Suite-B 192。
- 这一阶段密码学最重，椭圆曲线先用 Python 整数手写（学习为目的，不求速度），并与 pycryptodome 的结果交叉验证。
- 验收：`wpa3-sae`、`wpa3-sae-ext-key-group21`、`wpa3-ft-sae-h2e`、`owe*`、`wpa2-ft-*`、`wpa3-suiteb-192` 在给定 PMK 的前提下推导的 TK / GTK 与测试套件一致。SAE 的口令 → PMK 另需标准测试向量或自家抓包（见第 2 节）。

### 阶段 F：解密之后的内容
- 解密后只做到能验证“解对了”：LLC/SNAP → ARP / IPv4 / IPv6 / UDP / DHCP 的最小解析。
  Wireshark 的测试用 “Who has 192.168.5.18”（ARP）和 “DHCP ACK” 断言解密成功，我们断言同样的内容。
- 不做 TLS 等更上层的内容。

### 阶段 G（可选）：Wi-Fi 7 与其他
- MLO（Multi-Link）：`wpa-mlo-ccmp`、`wpa3-mlo`；TDLS（`wpa-test-decode-tdls`）；Mesh 元素；Extended Key ID（`wpa_ptk_extended_key_id`）。

## 4. 完成度矩阵（每阶段结束更新）

| 协议能力 | 阶段 | 对照样例 | 状态 |
|---|---|---|---|
| 帧层逐帧与 tshark 一致 | B | 全部 24 个 | 待做 |
| 信息元素 23/23 + 扩展 8/8 | C | 全部 24 个 | 待做（现 4/23、0/8） |
| WPA2-PSK / CCMP-128 | 已有 | `wpa-Induction`、`wpa-test-decode` | 已有，但公开样例要先能打开（阶段 B0）才能复验 |
| 阶段 A：标准答案与差分工具 | A | 全部 24 个 | **已完成**（tshark 4.4.19、固定提交的样例下载、差分工具、基线 0/24） |
| TKIP、WEP | D | `wpa2-psk-ccmp-tkip`、`wep` | 待做 |
| CCMP-256、GCMP | D | `wpa-ccmp-256`、`wpa-gcmp*` | 待做 |
| PMF（BIP） | D | `wpa2-psk-mfp` | 待做 |
| WPA3-SAE | E | `wpa3-sae*` | 待做 |
| OWE | E | `owe*` | 待做 |
| FT（802.11r） | E | `wpa2-ft-*`、`wpa3-ft-*` | 待做 |
| Suite-B 192 | E | `wpa3-suiteb-192` | 待做 |
| MLO / TDLS / Mesh | G | 对应样例 | 可选 |

## 5. 硬件怎么看（给不熟悉硬件的读者）

- **STM32 + ESP8266（v2 阶段 7）**：只能“列出附近的 WiFi”，看不到原始帧。对“完整协议”没有帮助，
  只能验证“串口 + 解析”这条小链路，而这条链路仿真测试已经覆盖。建议降为可选。
- **ESP32（v2 阶段 9）**：有混杂模式，能收到原始 802.11 帧，价格便宜，可以把收到的帧送给上面的解析器。
  限制：普通 ESP32 只有 2.4GHz，看不到 5GHz / 6GHz 的帧。适合做“真实帧进来”的演示，不是协议完整度的前提。
- **电脑 + 支持监听模式的 USB 网卡（Linux）**：才是抓真实 5GHz / WPA3 帧的办法，仅限自建网络。
  可以等阶段 D / E 做完后再决定要不要买，那时候再按实际需要选型。
- 结论：阶段 A–F 完全不用硬件。硬件放到阶段 G 之后，并且只在需要“真实帧”时再买。

## 6. 范围与边界

- 解密和密钥推导只用于：已知口令的自建网络，或公开样例里已公开的密钥。**不实现口令爆破**；
  PMKID 只用来校验“已知口令是否正确”，不做离线猜测。
- 不追求速度：Python 参考实现，以可读、可对照为先。需要上 MCU 的部分（帧头、基础元素）以后再单独移植成 C。
- 不收录第三方抓包文件（GPL），只收录下载脚本与校验值。

## 7. 与 v2 的关系

| v2 阶段 | v3 处理 |
|---|---|
| 7 硬件联调（STM32+ESP8266） | 降为可选，放在阶段 G 之后 |
| 8 真实抓包 + 解密实操 | 阶段 A 先用公开样例复验；自建网络抓包放在阶段 D / E 之后 |
| 9 ESP32 实现 | 保留，作为“真实帧输入”，在阶段 C 之后再做才有价值 |
| 10 可视化 | 不变，价值随解析完整度提升 |
| 11 SDR 频谱 | 与协议完整度无关，维持 P2 |
