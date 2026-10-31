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
**没做**：FT 元素（55，FTE：MIC、ANonce、SNonce 和子元素）和「支持的运行类别」（59）。
tshark 里它们的字段名没有规整的前缀，找不到可靠的对照字段；FTE 本身和 FT 握手的密钥层级相连，留到阶段 E 一起做。
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
