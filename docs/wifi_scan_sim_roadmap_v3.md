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
### 元素内容（C2a）
已解码并与 tshark 的字段对照：SSID、支持速率、扩展速率、DS（信道）、TIM、国家（含运行类别三元组）、ERP。
24 个样例里这些字段 0 不一致（SSID 4058 帧、DS 3973、TIM 3885、国家 3289、ERP 3878、速率 4086 帧）；
唯一的差异是前面那几帧 Multi-Link 嵌套（速率各 2 帧，已登记）。合成帧（隐藏 SSID、32 字节非 UTF-8 SSID、基本速率位、
TIM 偏移与位图、国家的运行类别三元组与填充、负的最大功率、ERP 各位）全部一致。
合成帧立刻抓出一个我写错的地方：TIM 位图偏移是 bits 1-7 的数值（右移 1 位），我只做了掩码；样例里的偏移全是 0，看不出来。
### RSN 元素（C2b）
`ie.decode_rsn`：版本、组密码套件、成对密码套件列表、AKM 套件列表、能力（每一位：预认证、MFPR、MFPC、OCVC、扩展 Key ID 等）、
PMKID 列表、组管理密码套件。套件表示成 (OUI, 类型)，OUI 为 0x000fac 的是 IEEE 802.11 自己的套件。版本之后的字段都可选，元素可以在任何一处结束。
和 tshark 在 24 个样例上对照：版本、组密码、成对套件、能力、MFPR / MFPC 3929 帧一致，AKM 3929 帧一致，PMKID 计数 24、组管理套件 11。
唯一缺的是 6 帧 SAE 认证里的扩展元素 114（AKM Suite Selector，tshark 也按 AKM 列出），归阶段 E。
11 种合成 RSN（WPA2、WPA3 + PMF 必需、带 PMKID、TKIP + CCMP 混合、Suite-B 192、OWE、FT-PSK、厂商 OUI、各处截断）全部一致。
合成帧还抓出一个我的缺陷：RSN 在能力字段之前结束时，结果里缺少 mfpr 等键，调用方会 KeyError；现在键总是齐的，缺的是 None。
`demo.pcap` 里 scapy 生成的 RSN 元素本身是畸形的（AKM 计数 1 而只剩 3 字节）：tshark 报畸形但仍给出已读到的字段，我们同样保留已读到的部分
（并带 `malformed` 标记）；tshark 之后还继续读出了能力字段，我们不照抄，登记为 `demo.pcap` 的已知差异。
### HT 能力、HT 操作、扩展能力（C2c）
`decode_ht_cap`（45，26 字节：12 个单独的能力位、SM 省电、RX STBC、A-MPDU 参数、MCS 集含最高速率与发送 MCS 集、扩展能力、波束成形、天线选择）、
`decode_ht_op`（61，22 字节：主信道、次信道偏移、任意宽度、RIFS、HT 保护、OBSS、双信标 / 双 CTS / PCO、基本 MCS 集）、
`decode_ext_caps`（127，变长位图）加 `ext_cap_bit(n)`。
与 tshark 在 24 个样例上逐字段一致：HT 能力 3449 帧（含 12 个能力位各自对照）、HT 操作 3410 帧、扩展能力 3602 帧（按「哪些位被置位」对照，位号表取自 tshark 自己的字段表）。
合成帧（每个 HT 能力位单独置位、各种 MCS 集、HT 操作的各字段、扩展能力在 1/3/8/10/11 字节下的位 0/19/62/70/84）全部一致。
这一步的变异检查暴露了测试自己的三个盲区，都已补上：
- 单元测试用模块自己的位号表造输入，等于自己验证自己；现在用标准里的字面位号，差分测试也加了 tshark 的逐位布尔字段。
- HT 操作里「任意宽度」和 RIFS 两位，测试帧里同时置位，互换看不出来；现在各自单独置位。
- tshark 的 `wlan.extcap` 字段不是每个字节都输出，不能拿来当完整字节列表对照，改成对照位集合。
另外 tshark 会把 HT 操作里的「基本 MCS 集」也按 MCS 集字段输出，所以合成的 HT 操作帧要先放 HT 能力元素（真实信标帧本来就是这个顺序）。
### 厂商专用元素（C2d）
`decode_vendor` 通用解码（OUI、类型、数据），`vendor_elements` 返回一帧里**全部**厂商元素（按出现顺序），
再按 OUI 0x0050f2 挂上专用解码：WMM（信息元素与参数元素：QoS 信息、U-APSD、参数集计数，BE/BK/VI/VO 四个访问类别各自的 AIFSN、ACM、ACI、ECWmin/max、TXOP）和
WPA（WPA1：版本、组密码、成对套件、AKM；布局同 RSN，套件 OUI 是 0x0050f2）。
与 tshark 在 24 个样例上一致：WMM 3438 帧（其中参数元素 3412 帧，四个访问类别的每个参数都对照）、WPA 490 帧、厂商元素 OUI 列表 3970 帧。
唯一的差异是前面那几帧 Multi-Link 嵌套里的厂商元素（1 帧，已登记）。
这一步发现并修掉：WMM 参数元素的长度下限我写成 19，少 1 字节时会越界（真实帧都完整，样例看不出来，单元测试抓到）；
`decode_wmm` 在信息元素时没有 `uapsd` 键（同 RSN 一样：键必须总是齐）。
**Wireshark 的一个命名问题**：WPA 元素的 AKM 类型被登记在 `wlan.wfa.ie.wpa.type` 这个名字下（和元素类型同名），
`wlan.wfa.ie.wpa.akms.type` 永远是空的；差分工具改用同一棵树里完整的 32 位套件值 `wlan.wfa.ie.wpa.akms`。
还没做的厂商元素：WPS（0x0050f2 类型 4）、Wi-Fi 联盟 0x506f9a 的 P2P / MBO / Hotspot 2.0 等，目前只有通用的 OUI / 类型 / 数据。
### 移动域、BSS 最大空闲周期、RSNXE（C2e）
`decode_mobility_domain`（54：移动域 ID、通过 DS 的 FT、资源请求协议）、`decode_bss_max_idle`（90：周期、受保护保活）、
`decode_rsnxe`（244：长度字段、受保护 TWT、SAE hash-to-element、SAE-PK；其余位保留原样不命名）。
与 tshark 在 24 个样例上一致：移动域 38 帧、BSS 最大空闲 26 帧、RSNXE 25 帧（H2E 位在 WPA3 样例里置位）。
这三种在样例里数量不多，所以另造了 16 个合成帧，把每一位单独置位逐个对照 tshark（RSNXE 的 bit4 / 5 / 6 各自单独验证了位号）。
**没做**：「支持的运行类别」（59）。FT 元素（55）在阶段 E 做了，见下一节。
tshark 里它们的字段名没有规整的前缀，找不到可靠的对照字段；FTE 本身和 FT 握手的密钥层级相连，留到阶段 E 一起做。
### 快速切换元素 FTE（E1a）
`ie.decode_ft`：MIC Control(2)（字节 0 的 bit0 = RSNXE 已用，bit1-3 = MIC 长度编码 0 / 1 / 2 = 16 / 24 / 32 字节，字节 1 = 元素个数）‖ MIC ‖ ANonce(32) ‖ SNonce(32) ‖ 子元素；
子元素 1 = R1KH-ID、2 = GTK、3 = R0KH-ID、4 = IGTK。对照 tshark 在 4 个 FT 样例里的 16 个带 FTE 的管理帧（`tests/oracle/test_ft_diff.py`）：
wpa2-ft-eap、wpa2-ft-psk、wpa3-ft-sae-h2e 的 11 帧所有字段相同。**wpa3-ft-sae-ext-key-group20 的 5 帧是 24 字节 MIC（编码 1），tshark 4.4 只当 16 字节读，
后面的 ANonce / SNonce / 子元素全部错位 8 字节（R1KH-ID 读不出来）**——以我们的为准，因为子元素用我们的长度恰好把数据用尽（R1KH-ID 00:01:02:03:04:06、R0KH-ID "nas1.w1.fi" 可读），
差异固定成列表。对解码的 10 个改动做变异检查，抓住 9 个，第 10 个（多加一个无意义的子元素名）是等价改动。

### Multi-Link（C3）
`decode_multi_link`（扩展元素 107，Wi-Fi 7）：控制类型（basic / probe request / reconfiguration / TDLS / priority access）、
公共信息长度、MLD MAC 地址、链路 ID，以及每个站点配置（链路 ID、完整配置位、STA MAC、STA 信息长度、固定字段、**嵌套的元素**）。
`flatten` 把嵌套元素展开在 Multi-Link 元素之后（tshark 列元素编号的顺序），元素编号、速率、厂商元素的列表因此与 tshark 一致。
**关键发现**：每站点配置里，STA 信息之后、嵌套元素之前，还有外层帧自己的固定字段（关联请求 2 字节能力；关联响应 4 字节能力 + 状态码；
信标 / 探测响应 2 字节能力），我第一次没算这些，把能力字段当元素解出了垃圾。固定字段长度现在由外层帧的子类型决定
（`ML_PROFILE_FIXED`）：关联请求 / 响应由样例对照，重关联、探测响应、信标由合成帧对照 tshark。
为避免依赖草案阶段会变的存在位图细节，定位只用各部分自带的长度字节（公共信息长度、STA 信息长度）。
结果：前面登记的 Multi-Link 嵌套缺口全部关闭——元素编号 / 扩展元素 / 速率 / 扩展速率 / 厂商元素在 24 个样例上 0 不一致；
Multi-Link 的类型、公共信息长度、MLD MAC、链路 ID、站点配置控制字段与 tshark 一致。
剩下的 Multi-Link 缺口只有 4 帧 SAE 认证里带的（要先解 SAE 认证帧体，阶段 E）。
**没做**：Multi-Link 公共信息里的其它可选字段（EML 能力、MLD 能力等）和 probe request / reconfiguration 类型的内部结构；HE / EHT 元素的内容。
### HE 能力与操作（C4）
`decode_he_cap`（扩展 35，Wi-Fi 6）：MAC 能力（48 位）、PHY 能力（11 字节）、HE-MCS 与 NSS 表（80MHz 及以下一对；PHY 第 0 字节的 0x08 位多一对 160MHz，0x10 位多一对 80+80MHz，先 160 后 80+80）、PPE 门限（原样）。
`decode_he_op`（扩展 36）：参数（默认 PE 时长、要求 TWT、TXOP RTS 门限、VHT 操作信息 / 共址 BSS / ER SU 禁用 / 6GHz 信息存在位）、BSS 颜色信息、基本 MCS 与 NSS 表，以及可选的 VHT 操作信息、最大共址 BSSID 指示、6GHz 操作信息。
`he_mcs_map` 把 16 位的表拆成 8 个空间流各自的 MCS 上限。
与 tshark 在 24 个样例上一致：MAC 能力 / 信道宽度集 / 80MHz 表 20 帧，HE 操作 3 帧。样例里没有 160 / 80+80 表，所以 9 个合成 HE 操作帧和 7 个合成 HE 能力帧让 tshark 验证了
这两位的位置、两张表同时存在时的顺序，以及 HE 操作三个可选部分的顺序。
**没做 / 没验证的**：
- MAC 能力（46 个字段）和 PHY 能力（77 个字段）里的单个位没有逐个命名，只有原始值。
- BSS 颜色三个字段按标准解码，但 tshark 没有对应字段，**没有被独立验证**。
- PPE 门限、6GHz 能力、EHT（Wi-Fi 7：108 / 106）的内容都没解码；EHT 在样例里是草案 D3.0 的格式，和正式标准有差别，等有正式格式的对照再做。
到这里，样例里出现的信息元素基本都有了内容解码，缺的是：FT 元素（55）、支持的运行类别（59，样例里 298 帧）、网状网元素（114 等）、
挑战文本（16）以及上面列的 HE/EHT 细节。
### Action 帧（B3）
新模块 `action.py`：类别 + 动作码，类别最高位是「错误响应」标志（0x83 = Block Ack 的错误响应），类别名称表，
**Block Ack**（ADDBA 请求 / 响应、DELBA：对话令牌、A-MSDU、立即 / 延迟、TID、缓冲区数、超时、起始序列控制、状态 / 原因码）和
**High Throughput**（通知信道宽度、SM 省电）的内容解码；其余类别只给出名称、动作码和原始内容。
与 tshark 在 24 个样例上一致：37 个 Action 帧（块确认 29、HT 8）的类别、动作码和全部内容字段；另有 2 个受保护的帧体是密文，不解码。
20 个合成 Action 帧（各种块确认参数、错误响应类别、DELBA、HT 的四种 SM 控制值、Action No Ack、其它类别、受保护帧）全部一致。
**发现并修掉的**：
- 旧的类别名称表有几处错：16 写成 DMS Action（应为 DMG）、17 写成 WMM Action（应为 Management Notification）、19 写成 Unprotected Action（应为 Robust AV Streaming）、20 写成 WNM（应为 Unprotected DMG），
  缺 21 以后的类别；现在与 tshark 的值表逐项对照。
- 旧代码没有处理 Action No Ack（子类型 14），也把受保护的 Action 帧体（密文）当明文读；现在跳过，差分对比还会检查「tshark 没给类别、我们却解出来了」。
**没做**：其它类别（公共动作、无线电测量、快速切换、SA 查询、WNM、TDLS、Mesh 等）的内容；HT 的 PSMP、CSI、波束成形动作。
这些类别在样例里没有出现，合成帧只验证了类别 / 动作码。
### A-MSDU（B4）
`amsdu.py`：QoS Control 的 A-MSDU 位置位时，帧体是一串子帧（目的地址 6 + 源地址 6 + 长度 2 大端 + 数据 + 填充到 4 字节，最后一个没有填充）。
解出每个子帧的地址、长度和数据；头部完整但数据被截断的子帧仍然列出并标 `truncated`（tshark 也是这样）。
**样例里唯一的 A-MSDU 帧是 CCMP 加密的**（`wpa-mlo-ccmp`），子帧要解密后才看得到——所以这一步完全靠明文的合成帧让 tshark 验证：
12 个合成 A-MSDU 帧（1-3 个子帧、四种填充长度、最后一个子帧带填充、截断、FromDS、DSAP 与 SSAP 不同的 LLC、受保护的密文）的子帧个数、
每个子帧的 DA / SA / 长度、以及第一个子帧数据的首字节（独立验证子帧数据的偏移）与 tshark 一致。
**与 tshark 的两处不同，都是有意的**：长度为 0 的子帧，tshark 在那里停止解析，我们继续往下读（标准没有要求停）；这种帧实际不会出现，测试里钉住了我们的行为。
**限制**：Mesh 数据帧的 A-MSDU 带 Mesh 控制字段，没处理；受保护的帧不解（阶段 D 解密后再解）。
下一步：把单文件拆成 `wifi80211/` 包，再进入阶段 D（加密与密钥层）。
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

### 阶段 D 的标准答案与基线（D1）
`tests/oracle/decrypt_oracle.py`：让 tshark 用 Wireshark 测试套件公开的密钥表（口令、WEP 密钥、PMK、msk）解密，从 `tshark -x` 输出里取出它解出来的明文
（每个解出的帧是一个单独的「Decrypted … data」数据源）。我们之后实现的解密，逐帧、逐字节与它对照。
**基线**：tshark 在 20 个样例上共解出 **1286 帧**明文——CCMP、TKIP、WEP、GCMP 四种；4 个样例它解不出
（`wpa-mlo-ccmp`、`wpa3-mlo`、`wpa3-ft-sae-ext-key-group20`、`wpa3-sae-ext-key-group21`：要 64 字节 PMK 或 tshark 4.4 没有的功能）；另有部分解出的：`wpa3-ft-sae-h2e` 16 帧里 10 帧，`wpa-test-decode` 936 帧里 756 帧，`wpa-Induction` 280 帧里 276 帧，`owe-3-dh-groups` 3 帧里 1 帧。
精确的每个样例的帧数钉在 `test_decrypt_oracle.py` 里（tshark 版本变了会显形）。
**我们自己的解密目前只有 CCMP-128（`wpa2_handshake.py`）**，而且只认 3 地址帧、不剥 FCS。
**踩到的坑**：
- 样例的密钥表里有两把 64 字节的 `wpa-psk`，Debian 的 tshark 4.4 加载不了——**一把这样的密钥会让整张表都加载失败**（所有样例变成 0 帧）；工具把它们去掉，依赖它们的样例没有标准答案。
- tshark 的行内选项 `-o uat:80211_keys:…` 的解析器也拒绝这种长度，所以密钥表写进临时的 Wireshark 配置目录（`XDG_CONFIG_HOME`）。
- `tshark -x` 对只有一个数据源的帧不打标题，不能按标题分帧，要按空行分块。
- `wpa-Induction` 是 WPA/WPA2 混合模式：单播 CCMP（203 帧），组播 TKIP（73 帧）。

### 加密原语（D2）
`crypto80211.py`：CCM（CCMP-128 与 CCMP-256：AES-128 / 256，MIC 8 / 16 字节）、GCM（GCMP-128 / 256，GHASH 手写）、RC4、CRC-32、WEP、
TKIP 的密钥混合（第 1、2 阶段，S 盒由 AES S 盒推出）和 Michael。AES 单块用 pycryptodome，其余手写。这里只有算法，不含帧头怎么构造 nonce 和 AAD。
**验证**：CCM 用 RFC 3610 的官方向量，加上 144 组随机输入（AES-128 / 256，MIC 8 / 16，含空 AAD）与 pycryptodome 的 CCM 逐字节对照；
GCM 用 NIST 测试用例 1-3，加上 120 组随机输入与 pycryptodome 的 GCM 对照；RC4（RFC 6229）、CRC-32 标准校验值；
Michael 用 802.11i 附录 H 的 6 个链式向量（密钥是上一步的输出，消息长度 0-7，覆盖所有填充情形）。
**还没被独立验证的**：TKIP 的密钥混合（第 1、2 阶段）。它没有我能可靠引用的独立向量，现在的测试只有性质（确定性、种子前三字节的结构、加密再解密）；
变异检查里 4 个针对混合函数细节的变异存活（第 1 阶段的 `+ i`、轮次奇偶、第 2 阶段的 `rotr1`、种子第 3 字节的移位）——
它们**必须在 D4 用真实 TKIP 帧（`wpa-Induction` 73 帧、`wpa1-gtk-rekey` 22 帧、`wpa2-psk-ccmp-tkip` 4 帧）对照 tshark 的明文来杀死**，在那之前不能算验证过。
**一个预告**：旧的 `wpa2_handshake.py` 的 `ccmp_build_aad` 把 FC 高字节只保留 ToDS / FromDS（`& 0x03`），标准里 Protected 位在 AAD 里是置 1 的、分片位也保留；
旧实现很可能只是自己加密自己解密才对得上，会在真实帧上 MIC 失败。AAD 的规则放到 D4 用真实帧裁决，不凭记忆写。

### 密钥推导原语（D3a）
`kdf80211.py`：PRF-SHA1（WPA / WPA2 的 PTK 推导）、KDF-SHA256 / 384 / 512（SAE、PSK-SHA256、Suite-B 192 等）、AES-CMAC（EAPOL-Key 的 MIC 版本 3、BIP）、
AES key wrap（EAPOL-Key 的 Key Data，描述符版本 2、3、0）、RC4 密钥解包（描述符版本 1 / WPA1）。
**验证**：AES-CMAC 用 RFC 4493 的两个子密钥和四个向量，加 100 组随机输入与 pycryptodome 的 CMAC 对照；AES key wrap 用 RFC 3394 的三个向量（128 / 256 位 KEK，128 / 256 位密钥）。
**PRF / KDF 目前没有独立的验证**：我没有能可靠引用的向量，测试只核对了定义（计数从哪开始、字节序、拼接顺序）。
它们由 D4 用 tshark 在 EAPOL 帧上给出的 KCK / KEK、在数据帧上给出的 TK（`wlan.analysis.kck / kek / tk`，`wpa3-sae` 的 TK `20a2e28f…` 与 Wireshark 测试里的期望值一致）逐把对照。
**tshark 的密钥字段**：KCK / KEK 在 EAPOL 帧上，PMK / TK / GTK 在数据帧上。这把尺子对所有套件通用。

### EAPOL-Key 解析（D4a）
`eapol.py` + `frames80211.py`（按帧读抓包：去 radiotap、去 FCS、解 MAC 头、取 LLC/SNAP + 0x888e 之后的 EAPOL）。
24 个样例共 **109 个 EAPOL-Key 帧**（描述符类型 2 和 254；Key Info 版本 0 / 1 / 2 / 3；MIC 16 / 24 字节），版本、类型、长度、描述符、Key Info、Key Length、Replay Counter、
Nonce、RSC、Key ID、MIC、Key Data 长度与内容、握手消息号，与 tshark **全部一致**。
**旧的 `parse_eapol_key` 是错的**：它把 Key Info、Replay Counter 等多字节字段按小端读，而 EAPOL-Key 的字段都是大端（WPA2 的 M1 是 `00 8a` = 0x008a）。
旧代码的测试帧是自己用小端拼的，所以对得上，对真实抓包会把标志位全读错——又一个「自己生成自己解析」的错误。
**MIC 长度**：16（多数）、24（HMAC-SHA-384，Suite-B 192）、32（SHA-512）。不先知道认证方式也能由「长度字段 = 固定部分 + MIC + 2 + Key Data」推出来，歧义时取最短；
握手流程里 MIC 长度应由认证方式给定（`parse(buf, mic_len=…)`）。有一个真实帧（Suite-B 192 的第一个 M1）Key Data Length 写 0 但尾部多 22 字节，长度关系推不出，必须靠认证方式——测试里钉成「恰好 1 帧」。
**消息号**：成对 M1-M4、组密钥 G1 / G2。M4 靠 Secure 位识别；WPA1 的 M4 没有 Secure 位，靠 Nonce 全 0 与 M2 区分。

### 握手跟踪与 PTK 推导（D4b）
`handshake80211.py`：从抓包里配对 M1 / M2（地址、Replay Counter），从 M2 的 Key Data 里的 RSN / WPA 元素读出认证方式（AKM）和密码套件，
对每个候选 PMK（口令 + SSID 经 PBKDF2；直接给的 PMK；EAP 的 MSK）推导 PTK = KCK ‖ KEK ‖ TK，用 KCK 重算 M2 的 MIC。
**MIC 吻合就证明了整条链**（PMK、地址、两个 nonce、哈希选择、KCK 长度）全对——AP 用真密钥算出的值，不依赖任何第三方实现。
**结果：23 个握手全部通过**，覆盖 TKIP / CCMP-128 / CCMP-256 / GCMP-128 / GCMP-256 各套件，样例分布见 `tests/oracle/test_handshake_oracle.py` 的表：
WPA2-PSK、EAP（msk）、WPA1/TKIP（HMAC-MD5）、PSK-SHA256、SAE、Suite-B 192（3 个握手，HMAC-SHA-384）、OWE 的三个 group、SAE-EXT-KEY 的两个样例（含多链路）。
**第二把尺子**：其中 19 个的 KCK 或 TK 也与 tshark 打在帧上的完全相同；另 4 个 tshark 4.4 没给出可对照的值（owe-3-dh-groups 的 2 个、wpa3-sae-ext-key-group21、wpa3-mlo 各 1 个），只有 MIC 自证。
**踩到的坑**：
- OWE（AKM 18）的第 0 版描述符用的是 HMAC，不是 AES-CMAC（SAE 才是 CMAC）：MIC 算法由 AKM 决定，不是描述符版本。我只对 group 20 / 21 做对了，group 19 靠对照 tshark 的 KCK 才发现：
  **我们的 KCK 和 tshark 的完全相同、MIC 却对不上**，说明推导没错、MIC 算法错了。
- 多链路设备推导 PTK 用双方的 **MLD 地址**（关联请求 / 响应里的 Multi-Link 元素），不是各条链路的地址。
- tshark 只在验证 M3 时才打 KCK：只有 M1 / M2 的抓包，要用 TK 来印证。TKIP 的 TK 是 32 字节，tshark 只打前 16 字节。
**还没做**：
- **重新握手**：它的 EAPOL 帧已被当前 PTK 加密，要边解密边跟踪。tshark 比我们多打出的 KCK / KEK / TK 都在这类样例里
  （表中"多出"列：wpa-eap-tls 2 / 2 / 2、wpa-test-decode 1 / 1 / 2、wpa_ptk_extended_key_id 2 / 2 / 2），下一步（D4c）关闭。
- 快速切换（FT）的 PTK 走 PMK-R0 / PMK-R1，阶段 E：wpa2-ft-eap、wpa2-ft-psk、wpa3-ft-sae-h2e 的握手我们一个也不处理，tshark 各有 1 组；TDLS 的 TPK 握手（wpa-test-decode-tdls 里 tshark 多 1 个 TK）。
- 还没验证 KEK（M3 的 Key Data 解包）和 TK（数据帧 MIC）——下一步。

### CCMP / GCMP 数据帧解密（D4c-1）
`decrypt80211.py`：用握手推出的 TK 解密单播数据帧。CCMP 的 nonce = 优先级 ‖ A2 ‖ PN（高位在前），GCMP 的 IV = A2 ‖ PN；
AAD = 帧控制（第 1 字节只留 `& 0x8F`；第 2 字节清掉重试 / 省电 / 更多数据，QoS 帧再清顺序位）‖ A1 A2 A3 ‖ 序号控制只留分片号 ‖ [A4] ‖ [QoS 控制只留 TID]。
**结果**：样例里 tshark 解出明文的 AEAD 数据帧，549 帧与它的明文逐字节相同、MIC 全部通过。AAD 规则一次就对了，没有靠试错凑。
另有 3 帧 tshark 解不开、我们解开了（owe-3-dh-groups 2 帧、wpa3-sae-ext-key-group21 1 帧）：它们用 64 字节的 PMK，tshark 4.4 加载不了。
**没解开的，固定成数字**（`tests/oracle/test_decrypt_diff.py`）：
- stale 506 帧：重新握手之后换了 PTK（wpa-test-decode 464、wpa-eap-tls 31、wpa_ptk_extended_key_id 11）——D4c-2 已全部解开，见下。
- no_hs 115 帧：组播 / 广播 92 帧（GTK，要从 M3 / 组密钥握手的 Key Data 里解出）、FT 单播 21 帧（阶段 E）、TDLS 对端直连 2 帧（TPK）。
- mgmt 6 帧：受保护的管理帧（PMF），nonce 和 AAD 的规则不同（wpa-test-decode-mgmt 3、wpa3-suiteb-192 3）。
**测试**：`tests/test_decrypt.py` 用 pycryptodome 当独立加密方并手写 AAD，覆盖样例里没有的形态（非 QoS、四地址、HT 控制、子类型 10、被屏蔽的各位、分片号）；
对 `decrypt80211.py` 的 13 处改动做了变异检查：全部被抓住（子类型掩码这一个起初只有空缺的测试漏掉，补了子类型 10 的用例后抓住）。

### 重新握手：边解密边跟踪（D4c-2）
重新握手（换 PTK）的 EAPOL 是被当前 PTK 加密的数据帧。`track()` 遇到受保护的数据帧，先用已推出的握手解开，是 EAPOL 就照常配对 M1 / M2、验 MIC。
`decrypt80211.decrypt_frame` 对同一对地址从新到旧逐个 PTK 试，靠 MIC 分辨——新密钥装上之前的帧、Extended Key ID 下新旧两把密钥同时有效，都用得上，不用去读 Key ID。
**结果**：握手 23 -> 30 个（wpa-eap-tls 1 -> 4，wpa-test-decode 1 -> 3，wpa_ptk_extended_key_id 1 -> 3），30 个全部 MIC 自证，其中 26 个也被 tshark 印证；
tshark 多出来的 KCK / KEK / TK 在这三个样例里归零（剩下的只有 FT 和 TDLS）。数据帧：与 tshark 明文逐字节相同的 AEAD 帧 549 -> 1055，stale 506 -> 0。
**踩到的坑**：重新握手的 M2 也带 Secure 位（密钥装过了），按 Key Info 的老规则会被当成 M4——M2 带 SNonce 和 Key Data（RSN 元素），M4 的 Key Data 为空，分类加上这一条（与 tshark 对 109 个 EAPOL 的消息号仍一致）。
变异检查：分类条件、"受保护帧才去解密"的接线被抓住；有两个等价改动没被抓：去掉 `any(nonce)`（后面一行的兜底使结果相同），以及"解出来是不是 LLC / EAPOL"的检查（非 EAPOL 的明文交给 eapol.parse 也得 None）。

### 组密钥：GTK / IGTK 与组播帧（D4c-3）
`groupkeys80211.py`：M3 和组密钥握手（G1）的 Key Data 用 KEK 保护（版本 1 = RC4 丢 256 字节，其余 = AES 密钥包装；WPA1 的 G1 总是 RC4）。
先用 KCK 验 M3 / G1 的 MIC，再让 KEK 过一遍密钥包装的完整性校验（A6A6… 头）——**能解出来本身就是自证**；然后解析 KDE（GTK 类型 1、IGTK 类型 9，跳过 RSN 元素和填充）。
组密码套件取自信标 / 探测响应的 RSN（WPA1 是厂商）元素，没有信标的抓包（wpa-eap-tls）退而用关联请求里的，再没有就猜成成对套件（猜错了 MIC 过不去，不会解出假明文）；组播帧按帧头里的密钥序号找 GTK，装上时间在帧之前的从新到旧试，MIC 决定。
**结果**：24 个样例共解出 34 个组密钥（M3 与 G1 合计，含同一 GTK 在多个握手里重复出现），tshark 打出的 GTK 有 12 个与我们的相同（`tests/oracle/test_groupkeys_oracle.py` 逐样例固定）。
组播 / 广播数据帧 82 帧与 tshark 的明文逐字节相同（`group` 一列），此外 tshark 解不了而我们解开的 4 帧（64 字节 PMK 的单播 3 帧 + 组播 1 帧）。
**我们有而 tshark 没有**：64 字节 PMK 的握手（owe-3-dh-groups、wpa3-sae-ext-key-group21，tshark 4.4 加载不了）、Suite-B 192 与 PMF 的 IGTK、
wpa-eap-tls 里加密重新握手中的 G1（tshark 不跟踪）——它们只有 MIC + 密钥包装的自证。
**我们没有而 tshark 有**：FT 的 GTK（阶段 E），以及 wpa1-gtk-rekey 的 3 个：WPA1 的 G1 在 TKIP 加密的数据帧里，等 TKIP 解密做完（下一小步）。
还有 10 帧组播属于 FT 样例；wpa-mlo-ccmp 与 wpa3-mlo 没有解出组密钥（多链路的 GTK 在另一种 KDE 里，tshark 也没有打出），留着。
**测试**：`tests/test_groupkeys.py` 手拼 KDE、用 `aes_key_wrap` / RC4 独立包装，并用 pycryptodome 加密组播帧；20 处变异检查，起初 7 个存活（取第一个 GTK、填充之后停读、密钥序号 / 时间 / AP 的筛选、ToDS+FromDS、组地址位），
补用例后全部抓住——其中组地址位这一条是用例里"单播"地址 0x11 的最低位其实是 1，帮我发现了测试自己的错；唯一没抓住的是 `x.anonce == e["nonce"]`（它只是少试几个握手的优化，MIC 不对照样过不去）。

### TKIP（D4c-4）
`decrypt80211.decrypt_tkip`：32 字节 TK = TEK(16) ‖ AP 发送的 Michael 密钥(8) ‖ STA 发送的 Michael 密钥(8)；组密钥同理（GTK 的 [16:24] 是 AP 的发送密钥）。
解密 = 两阶段混合 → RC4 → ICV（CRC-32）；Michael 的输入是 DA ‖ SA ‖ 优先级 ‖ 000 ‖ MSDU，密钥看发送方向（FromDS 用 [16:24]，否则 [24:32]）；
分片帧的 Michael 要重组后才能校验，返回 None，整体只看 ICV。`decrypt_any` 把 AEAD 与 TKIP 统一成「明文 + 完整性是否通过」，`decrypt_frame` / `decrypt_group` 都走它。
**结果**：wpa-Induction、wpa1-gtk-rekey、wpa2-psk-ccmp-tkip 里 tshark 解出的 TKIP 帧全部逐字节相同（ICV 和 Michael 都过）；
与 tshark 明文相同的数据帧：单播 1055 -> 1071、组播 82 -> 165。wpa1-gtk-rekey 的 3 个 WPA1 G1（在 TKIP 帧里）解开了，GTK 与 tshark 的 3 个全部相同：
解出的组密钥 34 -> 37 个、与 tshark 相同的 GTK 12 -> 15 个。
**遗留的 4 个 TKIP 变异体全部杀掉**，但不是靠真实样例：样例里的 TSC 都很小（高位全 0），第 1 阶段里 TSC 高两个字的顺序、`seed[1]` 的 `& 0x7F` 等改动真实帧测不出来。
新增 `tests/oracle/test_tkip_oracle.py`：用我们的 `tkip_encrypt` 加密 27 个合成帧（TSC 高低位、TSC1 = 0x40 / 0x7F / 0xFF、随机 TEK / TA），让 tshark 用同一把 TEK（密钥类型 `tk`，16 字节）解密——tshark 的实现是独立的。
对混合代码的 10 个改动做变异检查：全部被抓住（含起初漏掉的两个：TSC 高两个字对调、`seed[1]` 的掩码）。
`tests/test_decrypt.py` 另用独立构造的帧测 Michael 的密钥方向、DA / SA、优先级、分片，解密模块的 9 个改动，只剩一个没抓住：ToDS 与 FromDS 同时置位（四地址）时 Michael 取哪把密钥——规范里没有明确，样例里也没有这种帧，保持现状。

### 受保护的单播管理帧（PMF）与 WEP（D4c-5）
**管理帧**：CCMP 的 nonce 第 1 字节，数据帧是 QoS 的 TID，管理帧是 0x10（nonce 标志的管理位）；AAD 里帧控制第 1 字节，数据帧要屏蔽子类型的 b4-b6，管理帧整个保留
（管理帧的子类型本身就占着这几位，屏蔽了就错）。两处都是靠对照 tshark 的 6 个真实帧定下来的（先试四种组合，只有一种让 MIC 通过且明文相同），再写成规则。
wpa-test-decode-mgmt 的 CCMP（解除关联 / 解除认证）3 帧、wpa3-suiteb-192 的 GCMP-256（解除认证）3 帧，MIC 通过，明文与 tshark 相同。
**WEP**：帧体 = IV(3) ‖ 密钥序号 ‖ 密文 ‖ ICV(4)，ExtIV 位为 0；数据帧和共享密钥认证的第 3 帧（管理帧）都用。密钥表里只收十六进制的 5 / 13 / 16 字节，逐把试，ICV 通过的就是。
wep.pcapng 的 11 帧（10 数据 + 1 认证）与 tshark 明文逐字节相同。
至此样例里 tshark 能解的受保护帧，我们都解开了且完全一致：单播 1071、组播 165、PMF 管理帧 6、WEP 11 帧；还有 4 帧 tshark 解不了而我们解开的。
剩下的 33 帧是 FT（31 帧，阶段 E）和 TDLS 对端直连（2 帧）。
**测试**：`tests/test_decrypt.py` 的独立构造扩到管理帧（5 种套件 / 子类型）和 WEP（pycryptodome 的 ARC4 + zlib.crc32）；对这部分的 11 个改动做变异检查，起初 2 个存活——
一个是 `wep_keys` 没真正过滤非 WEP 条目（测试里的反例本身不是合法十六进制，所以过滤与否都一样），换成合法十六进制的 wpa-psk 后抓住；
另一个是 `decrypt_wep` 里多余的帧类型判断，ICV 校验已足够，删掉了。
**BIP**（D4c-6，见下）已补上；管理帧带 HT 控制（顺序位）时 AAD 怎么处理，规范没有样例可对，保持不屏蔽。

### BIP：广播 / 组播管理帧的完整性（D4c-6）
这类帧不加密，帧末尾带 Management MIC 元素（76）：密钥序号(2) ‖ IPN(6) ‖ MIC；用 IGTK（M3 / G1 的 Key Data 里的 IGTK KDE）保护。
`decrypt80211.verify_bip`：被保护的是 AAD = 帧控制（重试 / 省电 / 更多数据清零）‖ A1 ‖ A2 ‖ A3，后接帧体（MIC 字段清零）。
CMAC 套件：AES-CMAC(IGTK, AAD ‖ 帧体)，BIP-CMAC-128 取前 8 字节、BIP-CMAC-256（32 字节密钥）取 16 字节；GMAC 套件：AES-GCM 无明文，IV = A2 ‖ IPN（高位在前，帧里是小端所以要反过来），tag 16 字节。
套件取自 RSN 元素的组管理套件（6 = CMAC-128、11 = GMAC-128、12 = GMAC-256、13 = CMAC-256）。
**验证**：tshark 只显示 MME 不校验，所以没有它的答案可对。样例里带 MME 的帧我们找到的个数与 tshark 一致（wpa3-mlo 2、wpa3-suiteb-192 1，共 3 帧）；
suiteb 的 1 个 BIP-GMAC-256 解除认证帧，用 M3 解出的 IGTK 校验通过——**真实 MIC 吻合**。起初我把套件号弄错（以为 12 是 CMAC-256），用 CMAC 怎么算都对不上，
看到 beacon 里组管理套件是 12 才改成 GMAC-256（12 = GMAC-256、13 = CMAC-256）；GMAC 的 IV 字节序（A2 ‖ IPN 反过来）是在这个真实帧上六种组合里试出唯一吻合的。
wpa3-mlo 的 2 个信标没有可用的 IGTK（多链路的 IGTK 在另一种 KDE 里），不能判断。
**CMAC-128 / CMAC-256 / GMAC-128 没有真实帧**：用 pycryptodome 的 CMAC / GCM 独立构造，消息构造（AAD、清零的 MIC）与真实帧上验证过的 GMAC-256 是同一套，算法本身有 RFC 4493 / NIST 向量。
对 BIP 代码的 18 个改动做变异检查，全部被抓住。

### 快速切换（FT）的初始握手（E1b）
`ft80211.py`：XXKey -> PMK-R0 / PMKR0Name -> PMK-R1 / PMKR1Name -> PTK（公式见模块说明；PTK 的上下文是 SNonce ‖ ANonce ‖ BSSID ‖ STA，Nonce 不排大小、地址不排大小）。
`handshake80211` 把 FT 的 AKM（3 / 4 / 9 / 13 / 19 / 25）接进 `track()`：从（重）关联响应取移动域 ID 和 FTE 里的 R0KH-ID / R1KH-ID（`ft_contexts`），
SSID 取信标，XXKey 取自密钥表（FT-PSK：PSK；FT-SAE：SAE 的 PMK；FT-802.1X：**MSK 的第二个 256 比特**），用 M2 的 MIC 验证；
M2 的 RSN 元素里的 PMKID 应当等于推出的 PMKR1Name，这是**第二个独立的证明**（`frames["pmkr1name_ok"]`）。
**结果**：4 个 FT 样例的初始握手全部通过 MIC，PMKR1Name 也全部吻合；其中 wpa2-ft-eap、wpa2-ft-psk、wpa3-ft-sae-h2e 的 KCK / TK 与 tshark 相同，
wpa3-ft-sae-ext-key-group20（AKM 25，48 字节 PMK，SHA-384）tshark 4.4 没有答案，只有这两把尺子。握手 30 -> 34 个（tshark 印证 26 -> 29）。
数据帧：与 tshark 明文相同的单播 1071 -> 1088、组播 165 -> 174；解出的组密钥 37 -> 41（FT 样例的 M3 都解开了）。
**踩到的坑**：wpa2-ft-eap 一开始对不上。IEEE 的规则是 FT-802.1X 的 XXKey 取 MSK 的**后** 256 比特，前 256 比特是普通 PMK；tshark 打出的 PMK 是前一半，我最初沿用了。
这个结论是靠 M2 的 PMKID 吻合确认的（逐个试变体时，PMKR1Name 比 KCK 好用：它不需要 tshark 给答案，也不需要 Nonce）。AKM 13（FT-802.1X-SHA384）按同样的规则取 MSK[32:80]，样例里没有，有合成测试。
**测试**：`tests/test_ft.py`——真实抓包的已知答案（wpa2-ft-eap：PMKR1Name 是真实设备算出的，KCK / TK 是 tshark 的；group20：整个 PTK 由真实 M2 的 MIC 验证）+ 用 hmac 手写的公式对照 + 每个输入都起作用；
`tests/test_handshake.py` 里合成 8 种 FT 握手（AKM 3 / 4 / 9 / 13 / 19 / 25×3 个哈希档位）、错的 / 缺的 PMKID、缺关联响应；
对 ft80211 的 14 个改动和 FT 跟踪代码的 14 个改动做变异检查，起初 3 个存活（PMKID 比较写死 True、AKM 13 的哈希与 XXKey 长度），补合成测试后全部抓住。
**空中漫游**见下一节；漫游后的 GTK 还没做。

### FT 空中漫游（E2）
漫游（FT 协议）不走 4 次握手：STA 发认证（算法 2）和重关联请求，新 AP 的 PTK 由已有的 PMK-R0 换上新 AP 的 R1KH-ID 推出。
`handshake80211._ft_roam`：重关联请求带 RSNE（PMKID = 新 AP 的 PMKR1Name）、MDE、FTE（ANonce、SNonce、新 AP 的 R1KH-ID、R0KH-ID、MIC）。
用 FT 初始握手保存下来的 PMK-R0（`Handshake.ft`）推 PMK-R1 和 PTK，再验证 FTE 的 MIC：
MIC = CMAC（AKM 3 / 4 / 9）或 HMAC（其余，哈希同 KDF）(KCK, STA ‖ AP ‖ 序号 5 ‖ RSNE ‖ MDE ‖ FTE（MIC 清零）‖ [RSNXE])。
**踩到的坑**：wpa2-ft-psk 一次就对，两个 WPA3 样例的 MIC 对不上，但 PMKR1Name 吻合——说明密钥推导没错，是 MIC 的内容不对。
看 FTE 的 MIC Control：元素个数是 4、「RSNXE 已用」位置位（H2E 的样例），**RSNXE 也在 MIC 的覆盖范围里，排在 FTE 之后**。加上就吻合。
**结果**：3 个 FT 样例各 1 次漫游全部验证（FTE 的 MIC + PMKR1Name 两把尺子）；握手 34 -> 37 个（tshark 印证 29 -> 30：wpa2-ft-psk 的漫游 TK 与 tshark 相同，
wpa3-ft-sae-h2e 的漫游 tshark 没有打出 TK，ext-key-group20 的 tshark 本来就没有答案）。数据帧：与 tshark 明文相同的单播 1088 -> 1092；
tshark 解不了而我们解开的 6 -> 13 帧（h2e 漫游后的 6 帧、group20 漫游后的 1 帧），它们的完整性靠 CCMP 的 MIC。
**测试**：`tests/test_handshake.py` 合成漫游（AKM 4 / 9 / 25 / 19，MIC 由测试用 pycryptodome 的 CMAC 与 hmac 独立算），覆盖 RSNXE 在 / 不在 MIC 里、MIC 错、R0KH-ID 或移动域 ID 不同、
R1KH-ID 长度不对、PMKID 不对、缺 MDE / RSNE / FTE、受保护的帧、没有初始握手；对 `_ft_roam` 的 22 个改动做变异检查，起初 7 个存活，补用例后只剩 2 个等价改动
（按 STA 地址筛初始握手：别的 STA 的 PMK-R0 会让 MIC 对不上；初始握手的排序：同一个 XXKey 推出的 PMK-R0 相同）。
**漫游后新 AP 的 GTK**（E2b）：重关联响应的 FTE 里，子元素 2 = GTK（密钥序号 2 字节 ‖ 长度 1 字节 ‖ RSC 8 字节 ‖ AES 包装的 GTK），子元素 4 = IGTK（序号 2 ‖ IPN 6 ‖ 长度 1 ‖ 包装的密钥）。
`groupkeys80211._ft_group_key` 用这对地址的握手（含漫游得到的）的 KEK 解，完整性校验通过且长度字节吻合才收，来源记为 "FT"。
**结果**：3 个 FT 样例的漫游后组密钥都解出来了（组密钥 41 -> 44，与 tshark 相同的 GTK 18 -> 19；wpa2-ft-psk 的漫游 GTK 与 tshark 的第二个 GTK 相同）；
wpa2-ft-psk 漫游后最后一帧组播解开，与 tshark 明文相同的组播帧 174 -> 175，没有解不开的 FT 帧了（只剩 TDLS 对端直连 2 帧）；group20 漫游后又多 1 个 tshark 没有答案、靠 MIC 判断的帧（14 帧）。
变异检查 15 个改动，起初 4 个存活（密钥序号掩码、包装长度 8 的倍数检查、IGTK 的校验、重复子元素取第一个），补用例后全部抓住；
只剩一个等价改动：多个握手时按 M2 帧号从新到旧试 KEK（同一对地址、同一个 PMK-R0 推出的 KEK 相同）。

### SAE 与 OWE 的公开部分（E3）
**先说做不到的**：SAE 和 OWE 的 PMK 来自双方的**私有随机数**（SAE 的 rand / mask，OWE 的 DH 私钥），抓包里只有公开的标量、元素和公钥。
Wireshark 的测试套件也因此直接给 PMK（密钥表里的 wpa-psk 项）。所以 PMK 的推导（hunting-and-pecking / H2E、k、keyseed、KCK ‖ PMK）无法用这些样例验证；
SAE 的 confirm 要用 KCK，同样验不了。OWE 的 M1 / M2 / 关联帧里也没有 PMKID 可以对。口令 -> PMK 只能靠标准测试向量（我没有可靠来源的数值），这部分**没做，也不假装做了**。
**做了的（抓包里看得见、能独立检查的）**：
- `sae80211.parse_auth`：认证帧（算法 3）的 commit（状态码、组、[反阻塞令牌]、标量、元素 x‖y、后面的元素）和 confirm（send-confirm、按组的哈希长度切 confirm）。状态码 0 / 76 / 77 / 126（H2E）。
- 曲线检查：组 19 / 20 / 21 = P-256 / P-384 / P-521（常量与 pycryptodome 的表交叉核对），commit 的标量在 [1, n-1]，元素 (x, y) 在曲线上；OWE 的 DH 公钥（只有 x）有对应的曲线点（欧拉判别）。
- `ie.decode_owe_dh`：OWE 的 DH 参数元素（扩展元素 32）：组 + 公钥。
**对照 tshark**（`tests/oracle/test_sae_diff.py`）：7 个样例里全部 SAE / OWE 内容（5 个 SAE 样例：4 个带 H2E 状态 126、1 个传统 SAE，共 10 个 commit、10 个 confirm；2 个 OWE 样例）
与 tshark 的消息类型、组、标量、元素、send-confirm、confirm 逐个相同；OWE 的 8 个 DH 元素（组 19 / 20 / 21）组与公钥相同、长度与组一致。
**独立的证明**：每个 commit 的元素都在曲线上、标量都合法，每个 OWE 公钥的 x 都有对应的点——如果标量 / 元素的偏移或长度错了，这些检查不可能全部通过，而且它们不依赖 tshark。
**测试**：`tests/test_sae.py` 用 pycryptodome 生成合法的点（标量 × 生成元），覆盖各种篡改（x / y 改动、坐标 >= p、标量 0 或 n、截断、状态 76 / 77 / 126、不认识的组、confirm 长短）；
对解析与曲线代码和 OWE 元素解码的二十多个改动做变异检查，起初存活 2 个：状态 77 但组认识且字节够的情形没有用例，补上后抓住；另一个（`rhs == 0` 的特判）等价——素数阶曲线没有 y = 0 的点。

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

### 多链路（MLO）与 Wireshark 公布的答案（G-MLO）
**Wireshark 自己公布的答案**（`tests/oracle/test_published_keys.py`）：它的测试套件对每个样例用 `wlan.analysis.tk == …` / `wlan.analysis.gtk == …` 过滤，这些值就是作者认定的 TK 和 GTK，
而且不依赖我们装的 tshark 版本（tshark 4.4 解不开的 FT 漫游、多链路、48 / 64 字节 PMK 样例也有）。**21 个公布的 TK 和 20 个公布的 GTK，全部被我们推出来**——包括 FT 漫游后的 TK、
wpa3-mlo 的 1 个 TK 和 4 个 GTK、wpa3-ft-sae-ext-key-group20 的 SHA-384 密钥。（wpa-mlo-ccmp 的 TK 是用户直接给的，算已知输入。）
**多链路 M3 / G1 的 Key Data**：链路 KDE（0x13）给出链路 ID 对应的 AP 链路 MAC；MLO GTK KDE（0x10）= 密钥序号 / Tx / 链路 ID（高 4 位）‖ RSC(6) ‖ GTK；
MLO IGTK（0x11）/ BIGTK（0x12）KDE = 密钥序号(2) ‖ IPN(6) ‖ 链路 ID（高 4 位）‖ 密钥。只有 M3 带链路 KDE，G1 靠调用方记下的链路表（`mlo_keys(links=…)`）。
**地址规则（由 wpa3-mlo 的真实帧确定，只有这样 MIC 才通过）**：多链路设备之间的**单播**帧，CCMP 的 nonce 里的 A2 和 AAD 里的 A1 / A2 / A3 / A4 都换成 **MLD 地址**（帧头里是链路地址）；
**组播**帧用每条链路自己的 GTK，地址保持链路地址。EAPOL 的配对同样要把链路地址换成 MLD 地址。
**结果**：wpa3-mlo 的 8 个受保护数据帧全部解开（4 个单播、4 个组播，其中 2 个是加密的 G1 / G2 EAPOL），ICMPv6 校验和全部吻合；组密钥 41 -> 48 个（含 IGTK / BIGTK 条目），
tshark 4.4 对这个样例没有任何答案，解出的帧 14 -> 22（靠 CCMP 的 MIC、校验和、Wireshark 公布的值）。
**用户直接给 TK**（密钥表里的 `tk` 项）：`decrypt_user_tk` 按 TK 长度试套件，MIC 决定；对照 tshark 的 5 个样例（4 个单 TK 样例 + wpa-mlo-ccmp）帧号与明文逐字节相同。
wpa-mlo-ccmp 的 4 个多链路数据帧 tshark 和我们都解不开：抓包里没有关联帧，拿不到 MLD 地址；只有受保护的解除认证帧（管理帧用链路地址）两边都解得开。
**BIP 的补充**：之前只信「装上时间在帧之前」的密钥；信标常常比关联早抓到，所以改成先试之前的、再试之后的，MIC 吻合就是 ok；不知道组管理套件时按 MIC 和密钥长度推。
**没解决的**：wpa3-mlo 的 2 个信标用 BIGTK（密钥序号 6）保护，我试了 BIP-CMAC-128 在帧控制屏蔽、时间戳清零、MIC 清零或去掉、IPN 前缀等组合，用每一把解出的 IGTK / BIGTK 都对不上——
信标保护的 MIC 范围规则没弄清，结果标成 `unsupported`，不假装验证了。
**测试**：`tests/aead_build.py` 的独立构造支持 MLD 地址；`tests/test_decrypt.py`（MLD 映射的各种缺项、user TK）、`tests/test_groupkeys.py`（`mlo_keys`）；
对这批代码的 34 个改动做变异检查，起初 4 个存活：3 个补用例后抓住（链路 ID 占 4 位、6 字节的链路 KDE、管理帧不用 MLD 表），1 个等价（`_infer_bip` 里按 MIC 长度过滤——长度不对的套件验证本来就会失败）。

### TDLS（G-TDLS）
两个站点经 AP 交换三条建立帧（数据帧，以太类型 0x890d，先由各自的 PTK 保护），推出对等密钥 TPK 后直接互发加密帧（`tdls80211.py`）。
Nonce 在 FTE 里（Response 带 ANonce 和 SNonce）：**TPK-Key-Input = SHA-256(min ‖ max(两个 Nonce))；TPK = KDF-256(Key-Input, "TDLS PMK", min ‖ max(两个 MAC) ‖ BSSID)，前 128 比特是 TPK-KCK、后 128 比特是 TPK-TK**（CCMP-128）。
FTE 的 MIC = AES-128-CMAC(TPK-KCK, 发起方 ‖ 响应方 ‖ 序号(Response 2、Confirm 3) ‖ 链路标识元素 ‖ RSNE ‖ 超时间隔元素 ‖ FTE（MIC 清零）)——元素的排列是在真实的 Response 和 Confirm 上试出来的，两个 MIC 都吻合。
**结果**（wpa-test-decode-tdls）：推出的 TPK-TK 就是 tshark 额外打出的那把 TK（握手测试里「tshark 多出 1 个 TK」）；对端直连的 2 个帧解出，与 tshark 明文逐字节相同，IPv4 / ICMP 校验和吻合。
至此样例里 tshark 能解的受保护帧里没有留下任何一个解不开的（`no_hs` 归零）。流水线 `decrypt_capture` 最后一步用 TPK 解直连帧（`how = "tdls"`）。
**测试**：`tests/test_tdls.py`（MIC 用 pycryptodome 的 CMAC、KDF 用 hmac 手写、直连帧用独立构造）；对 TDLS 模块的 30 多个改动做变异检查，起初存活 5 个：
成对套件检查（测试里 MIC 没跟着改，所以检查没起作用）、去重键里的令牌、SNAP 前缀检查、缺链路标识的容错——补用例后抓住；`pipeline` 里「已解开的帧跳过」是等价的优化。

### 阶段 F：解密之后的内容（已完成）
- 解密后只做到能验证“解对了”：LLC/SNAP → ARP / IPv4 / IPv6 / UDP / TCP / ICMP / ICMPv6 / DHCP 的最小解析（`net80211.py`），以及把前面各层接起来的 `pipeline80211.decrypt_capture`
  （握手 + 重新握手 + FT 漫游 → PTK，M3 / G1 / FT 响应 → GTK，WEP 密钥；逐帧试 WEP / 单播 / 组播；A-MSDU 拆开）。不做 TLS 等更上层的内容。
- **结果**（`tests/oracle/test_net_diff.py`）：24 个样例共解开 1291 个受保护的数据帧，逐层是：ARP 110、IPv4/ICMP 510、IPv4/UDP 241（其中 DHCP 83）、IPv4/TCP 67、IPv4 其它 48、IPv6/ICMPv6 94、IPv6/UDP 68、
  生成树 BPDU 18、别的以太类型（EAPOL 等）135。和 tshark 的协议字段逐帧一致：ARP 操作码与地址、IP 源目的地址与协议号、UDP / TCP 端口与标志、ICMP / ICMPv6 类型、DHCP 报文类型与 xid；
  tshark 多解的层（ICMP 差错报文里嵌套的原包、Teredo 隧道里的 IPv6）不比，只允许它多、不允许它不一样。
- **「解对了」的独立证明**：所有解出来的 IPv4 头、UDP、TCP、ICMP、ICMPv6 校验和全部吻合——解密错一个比特就对不上，不依赖 tshark。**14 个 tshark 解不开的帧**（64 字节 PMK、FT 漫游、ext-key 等）
  就靠这个加上 CCMP 的 MIC 来判断：owe-3-dh-groups 的 2 帧是下面那种图案 ICMP（IPv4 头校验和对），其余 12 帧校验和都对——ICMPv6 4 帧（含伪头）、UDP 2 帧、wpa3-ft-sae-h2e 漫游后的 6 帧（ARP / DHCP / ICMP）。
- **唯一的例外**：13 个 ICMP 回显应答（owe-3-dh-groups 3 个、wpa_ptk_extended_key_id 10 个）的 ICMP 校验和不对，但 IPv4 头校验和是对的，tshark 也报「Checksum Status: Bad」——
  负载是 00 01 02 03… 的测试图案，ICMP 头本身不合规，是样例自己的性质，不是解密的问题（解密由 CCMP 的 MIC 保证）。
- **测试**：`tests/test_net.py` 用 scapy 构造 IPv4 / IPv6 / UDP / TCP / ICMP / ICMPv6 / ARP / DHCP（校验和由 scapy 算）；`tests/test_pipeline.py` 用 WEP 合成帧测接线（含 A-MSDU）。
  对 `net80211.py` 近 60 个改动做变异检查，起初 10 个存活（校验和进位只折一次、IPv6 链路层填充、目的地选项扩展头、分片头保留位、UDP 长度超界、TCP 的 NS 标志位、DHCP 重复选项、DHCP 端口、LLC 控制字段），
  补用例后全部抓住；`pipeline80211` 11 个改动只剩 1 个等价（`type != 2` 之外的 `not protected` 检查，后面的解密函数本来就拒绝未受保护的帧）。
- 还没做：Wireshark 测试套件里对解密结果的具体断言（如「Who has 192.168.5.18」「DHCP ACK」的出现次数）没有逐条照搬，我们对 tshark 的逐帧字段对照覆盖了同样的东西，但不是它们的原话。

### 阶段 G（可选）：Wi-Fi 7 与其他
- MLO（Multi-Link）、TDLS、Extended Key ID 已完成（见上面各节）。Mesh 元素没有样例，用合成帧对照 tshark 做了 Mesh ID 和 Mesh Configuration（`ie.decode_mesh_id` / `decode_mesh_config`）；对等管理和 AMPE 没做。

### 阶段 H：解密之后认出「去了哪里」（`docs/家里WiFi流量分析方案_review.md` 的目标）
只做被动识别：设备查了什么域名、连了哪个服务器的哪个域名；不看 TLS 的内容，不解密 QUIC 的应用数据。24 个样例里只有 DNS / mDNS 和一条明文 HTTP，没有一条 TLS / QUIC 流，
所以 H3、H4、H5 的 TLS 与 QUIC 部分靠公开向量（RFC 8448、RFC 9001）和合成流对照 tshark，真实抓包的验证要等监听网卡。
- **H1 DNS / mDNS**（`dns.py`）：名字压缩（指针只能指回前面，成环或指向后面一律拒绝）、A / AAAA / CNAME / NS / PTR；mDNS 的服务名是 UTF-8。
  3 个样例 40 个帧与 tshark 逐字段一致（id、QR、rcode、名字、类型、各区记录数、A / AAAA / CNAME，tshark 的地址字段涵盖三个记录区）；wpa3-sae-ext-key-group21 的 2 帧 tshark 解不开（64 字节 PMK），只有我们解出。
- **H2 TCP 流重组**（`tcpstream.py`）：32 位序号回绕、乱序、重传、重叠、没抓到 SYN、SYN 带数据；校验和不对的段丢掉；缺口不接起来，而是记下缺了多少字节。
  对 tshark 的 Follow TCP Stream 逐字节相同：wpa-Induction 的 5 条连接 10 个方向 29427 字节（其中 4 个方向样例自己漏抓了包，缺的字节数和 tshark 报的一样），另有 6 条合成连接 12 个方向。
- **H3 TLS ClientHello**（`tls.py`）：SNI、ALPN、版本（含 supported_versions）、套件数、扩展类型、ECH / ESNI 是否出现；握手消息可被拆在多个 TLS 记录里。
  RFC 8448 的真实字节加 20 种合成形状与 tshark 逐字段一致。
- **H4 QUIC Initial**（`quic.py`）：由目的连接 ID 推出 Initial 密钥（v1 与 v2），去头保护，AES-GCM 解 CRYPTO 帧，几个包的 CRYPTO 按偏移拼起来（Chrome 的 ClientHello 要两个包）。
  RFC 9001 附录 A 的密钥和整包与向量一致；11 个数据报 8 个连接与 tshark 一致。
- **H5 访问时间线**（`activity.py`）：每个解密后的数据帧归到设备（发往 AP 的取源地址，AP 发来的取目的地址；AP 转发的组播副本、WDS、IBSS 不归任何设备），
  产生 dns / mdns / tls / quic 事件；没有 SNI 时用这台设备自己先前 DNS 应答里的 IP -> 域名补名字（`via` 标 dns）；`sessions` 按间隔合并，`summary` 按设备统计。
  wpa-Induction 里设备发出的 17 个 DNS / mDNS 查询（1 台设备、13 个不同名字，不含 H5b 的 HTTP）帧号、MAC、名字与 tshark 逐帧一致。
- **H6 域名到应用**（`apps.py`、`rules/apps.json`、`tools/build_app_rules.py`）：规则不手写，从 v2fly/domain-list-community（MIT）的固定提交（2026-10-09）下载 145 个清单文件（逐个核对 sha256），
  按脚本里的应用表归到 44 个应用 / 类别，生成 `rules/apps.json`（7049 条后缀、702 条完全匹配；广告 / 统计域名 420 条、关键字 / 正则 12 条跳过；同一域名被多个应用收录的 475 处按表里的顺序先到先得）。
  匹配：完全匹配优先，再从最长的后缀找起，必须落在标签边界上；自己的规则文件优先于自带的（`apps.load("my.json")`）。`annotate` 给事件标应用，`usage` 估计每台设备每个应用的使用段数和时长
  （相邻不超过 gap 秒算一段；这是网络活动推出的估计，不是屏幕时间），`unmatched` 列出没规则的常见域名，拿来补自己的规则。归属偏粗是事实：腾讯、Google、Apple、Microsoft 是整家公司的归类，CDN 与 SDK 域名共用。
- **H5b 更多事件源**（`activity.py`）：明文 HTTP 的请求（Host、方法、路径，`kind="http"`）、53 端口 TCP 上的 DNS（带 2 字节长度前缀，`transport="tcp"`）、853 端口的 DNS over TLS（`kind="dot"`，只认 ClientHello，不看内容）。
  HTTP 在真实抓包上对照 tshark：wpa-Induction 的 5 条连接、4 台服务器共 11 个请求，方法、Host、路径逐项相同（其中一条连接漏抓了 467 字节，缺口前后各读到一个请求）；
  TCP 上的 DNS 样例里没有，用 6 条合成连接（拆开的长度前缀、一段两条消息、没有 SYN）对照 tshark，11 项一致；DoT 只有合成测试。tshark 不重组乱序到达的 TCP DNS，我们按序号拼，测试里固定了这一差异。
  变异检查约 45 处，起初 12 处存活，补用例后只剩 5 处等价改动（IPv6 冒号个数判断、循环边界、53 端口预过滤、两处找到客户端方向后的 break）。
- **一条命令出报告**（`report.py`、`keyfile.py`）：`python3 -m wifi80211.report 抓包文件 --keys 密钥文件 [--rules 自己的规则] [--gap 60] [--format table|json|csv]`，
  每台设备列出应用（类别、段数、事件数、估计时长、起止时间）和没有规则的域名；密钥文件是 Wireshark 的 `"类型","值"` 格式（wpa-pwd / wpa-psk / msk / wep / tk），错误信息不回显密钥。
  口令对时在 wpa-Induction 上 280 个受保护数据帧解开 276 个，得到 1 台设备 28 个事件（13 个 DNS、4 个 mDNS、11 个 HTTP）；口令错时退出码 3 并说明有多少帧一个也没解开；输出里写明「时长是估计，DoH / DoT / ECH 看不到」。
  变异检查 48 处，起初 20 处存活，补用例后全部抓住。
- **端到端对照**（`tests/oracle/test_wifi_e2e_diff.py`）：样例里没有 TLS / QUIC 流，所以合成了一个 CCMP 加密的 802.11 抓包（独立加密方），里面有 DNS、拆成两段的 TLS ClientHello、明文 HTTP、QUIC Initial，只给一把 TK，
  走完整条链（解密 -> 事件），读出的 4 个域名与 tshark 用同一把 TK 解密后读到的逐项相同。这一步还发现 `pipeline.decrypt_capture` 一直没用密钥表里的 `tk` 项（`decrypt_user_tk` 只有测试在调），
  现在补上了：没有握手也能解单播帧，`how` 标 `user_tk`。
- **nDPI 交叉对照**（`tests/oracle/test_ndpi_diff.py`）：tshark 只认协议，不认应用；nDPI（ntopng 用的深度包检测库，开发镜像里用固定的 6.0 版本编译，`ndpiReader`）认应用。同一批合成流量（46 个名字 × TLS 的 SNI / QUIC Initial 的 SNI / 明文 HTTP 的 Host，共 138 条流），
  先确认 nDPI 把它们识别成 TLS / QUIC / HTTP 且读到的主机名与我们放进去的逐条相同（顺带独立验证了我们的 TLS / QUIC / HTTP 构造），再比应用名：**84 条一致**（28 个名字，其中 12 个靠 11 项显式的名字对照表才算同一个，如 Github/GitHub、NetFlix/Netflix、iQIYI/爱奇艺）、
  **48 条只有我们认得**（16 个名字：抖音、快手、哔哩哔哩、百度、小红书、京东、拼多多、美团、优酷、虎牙、斗鱼、网易、AcFun、B 站图床，加 OpenAI，nDPI 只说 TLS / QUIC / HTTP）、3 条只有 nDPI 认得（Wikipedia）、3 条都不认得（example.com）、说法真正不一样的 0 条。
  结论：国内应用（正是你最关心的抖音、快手）nDPI 完全不认，我们的规则有；Tencent / Google / Apple / Microsoft 这类大公司，我们归整家公司，nDPI 更细（如微信域名 nDPI 归到 QQ）；两边都是按域名认的，TLS / QUIC / HTTP 结论相同。
  所以：应用级统计用 nDPI 打底并不省事——要同时保留我们的国内应用规则；反过来 nDPI 的细分（它分得更细的国外应用）可以当我们规则的补充来源。
- **网关抓包与流量统计**（`plain.py`、`traffic.py`）：报告也能读以太网 / Linux cooked 抓包（在你自己的网关或局域网一侧用 tcpdump 抓的，不需要密钥），按源是局域网地址还是公网地址判断上下行并认出设备 MAC；
  新增逐流的包数和 L3 字节（上行 / 下行），按设备、按应用汇总，没有名字的流写「未命名 对端 IP」。在路由器 WAN 一侧或 NAT 之后抓，所有包的 MAC 都是路由器的，设备分不开，认不出时设备为空，不乱归。
  对照 tshark：14 个样例 102 条流 325 个包 74552 字节，每条流上下行包数和 IP 层字节逐条相同（3 个包只有我们解得开，不在比较里）；合成的以太网抓包（另存 cooked v1 / v2 各一份）里 4 个域名和设备的 5 条流 15 个包 4046 字节与 tshark 逐项相同。
  字节含 IP / TCP / UDP 头和重传，不含链路层头，没有按 TCP 序号去重。变异检查约 60 处，补用例后全部抓住，另有 2 个死分支已删除。
- **加密 DNS**：`rules/encrypted_dns.json` 手写了 5 家公开 DoH / DoT 服务（Google、Cloudflare、Quad9、AdGuard、阿里），域名都在服务商说明页上核对过，类别「加密 DNS」；设备连这些名字时我们只能说「它的 DNS 被加密了」。
- **还没做**：ECH 看不到；非公开的 DoH 服务器认不出；HTTP/3 之外的 UDP 协议。
- 变异检查：`apps` 25 处，起初 4 处存活，补用例后全部抓住（剩下的是文档字符串里的字和重复的类型检查）；`dns` 12 处改动 2 处等价；`tcpstream` 15 处 3 处等价；`activity` 约 35 处，等价的有 DNS 端口检查重复（`net.describe` 已按端口判断）、1200 字节下限（`quic` 自己会拒绝）、同一连接里设备不变、找到 ClientHello 后的 `break`。

## 4. 完成度矩阵（每阶段结束更新）

| 协议能力 | 阶段 | 对照样例 | 状态 |
|---|---|---|---|
| 阶段 A：标准答案与差分工具 | A | 全部 24 个 | **已完成**（tshark 4.4.19、固定提交的样例下载、差分工具） |
| 帧层（抓包格式、radiotap、MAC 头变体、FCS、A-MSDU、Action） | B | 全部 24 个 | **已完成**，与 tshark 逐帧一致，已知差异固定在表里 |
| 信息元素与扩展元素 | C | 全部 24 个 | **已完成**（含 RSN、HT、HE、Multi-Link、FTE、移动域等），逐字段对照 tshark |
| 4 次握手与 PTK（AKM 1–25 各档哈希、MIC 算法） | D | 全部 | **已完成**：34 个握手 + 3 次 FT 漫游共 37 个，全部由 M2 的 MIC 自证，29–30 个也有 tshark 的 KCK / TK |
| CCMP-128/256、GCMP-128/256、TKIP（含 Michael）、WEP | D | `wpa-*`、`wpa2-psk-ccmp-tkip`、`wep` | **已完成**：tshark 能解的帧全部逐字节一致，另有 22 个 tshark 解不了的帧靠 MIC 判断 |
| PMF：受保护的管理帧、BIP-CMAC / GMAC | D | `wpa2-psk-mfp`、`wpa3-suiteb-192` | 管理帧解密 **已完成**；BIP 在 IGTK 上已验证（1 帧真实 MIC 吻合），**BIGTK 保护的信标（2 帧）规则未弄清，标 unsupported** |
| 组密钥（M3 / G1 / FT 响应；GTK / IGTK / MLO 每链路） | D / G | 全部 | **已完成**：Wireshark 公布的 20 个 GTK 全部被推出 |
| FT（802.11r）：PMK-R0 / R1、初始握手、空中漫游 | E | `wpa2-ft-*`、`wpa3-ft-*` | **已完成**（PMKR1Name 与 MIC 双证明，漫游由重关联请求的 FTE MIC 验证） |
| Suite-B 192 / OWE / SAE-EXT-KEY 的握手 | E | `wpa3-suiteb-192`、`owe*`、`wpa3-sae-ext-key-group21` | **已完成**（给定 PMK） |
| SAE / OWE 的 PMK 推导（口令、私有随机数） | E | — | **做不到**（样例只公开了 PMK，没有私有值）；公开部分（commit / confirm、曲线上的点）已做 |
| MLO（多链路） | G | `wpa3-mlo`、`wpa-mlo-ccmp` | wpa3-mlo **已完成**（Wireshark 公布的 1 个 TK、4 个 GTK 全部推出）；wpa-mlo-ccmp 的数据帧缺关联帧（拿不到 MLD 地址），只能解管理帧 |
| TDLS | G | `wpa-test-decode-tdls` | **已完成**（TPK、两个 MIC、直连帧） |
| Extended Key ID | G | `wpa_ptk_extended_key_id` | **已完成**（新旧两把 PTK 靠 MIC 区分） |
| 解密后的内容（ARP / IP / UDP / TCP / ICMP / DHCP）与校验和 | F | 全部 | **已完成**：1301 个数据帧，校验和全部吻合（13 个测试图案的 ICMP 例外，tshark 同报 Bad） |
| Mesh 元素（Mesh ID、Mesh Configuration） | G | 无样例 | **已完成**，用 26 个合成帧逐字段对照 tshark（每一位单独变化）；Mesh 对等管理 / 认证（AMPE）没做，无样例也无合成参照 |
| 解密后认出访问了什么（DNS / mDNS、TCP 重组、TLS SNI、QUIC Initial、按设备的时间线） | H | `wpa-Induction` 等 3 个样例；TLS / QUIC 用公开向量和合成流 | **已完成**（H1–H6）；样例里没有 TLS / QUIC 流，真实抓包验证等监听网卡；域名到应用的映射（H6）规则来自 v2fly 公开清单 |
| 包 `wifi80211/` | — | — | **已完成**（模块列表见 `wifi80211/__init__.py`；`wpa2_handshake.py` 是早期实现，保留作历史） |

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
