---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 0bd2c4904e701d4269608d4ce4d80073_bea003cbd56e11f180d5525400248c00
    ReservedCode1: 4PGLZUFXHpAsSd7dbFBIxzQ5rpXPFXjiAdXRWfQwLSNtzYEV2Rh8uh5vEX/Y806zORkVFVLtCpKyN3naQfk3R/ahh2Zd3ubPqObB+tZscG3+tdzrnIanmf2p5QT+En2ojlUpQqkWOwNBwMSDDdPmlGh5F6xdSxgQ+C0i7Tnq/tbbR+U7W888goRUswA=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 0bd2c4904e701d4269608d4ce4d80073_bea003cbd56e11f180d5525400248c00
    ReservedCode2: 4PGLZUFXHpAsSd7dbFBIxzQ5rpXPFXjiAdXRWfQwLSNtzYEV2Rh8uh5vEX/Y806zORkVFVLtCpKyN3naQfk3R/ahh2Zd3ubPqObB+tZscG3+tdzrnIanmf2p5QT+En2ojlUpQqkWOwNBwMSDDdPmlGh5F6xdSxgQ+C0i7Tnq/tbbR+U7W888goRUswA=
---



# 家庭 WiFi 流量分析方案（Review 版，2026-11 订正）

> 目标：在自家 WiFi 网络内，识别全屋设备「访问了哪些网站和应用、流量多少、用了多久」，用于个人时间管理（如抖音 / 快手使用时长统计）等合法用途。
> 结论先行：**可行。路由器是黑盒（改不了设置）时有两条路：监听空口（要监听网卡 + Linux 机器），或在黑盒路由器后面接一台自己的网关。** 软件部分（解密、识别、归应用、报告）已经做完并有测试，现在等真实数据。

## 订正记录（相对第一版）

| 第一版的说法 | 订正 |
|---|---|
| 「macOS 无法监听」 | 不绝对。macOS 自带的 Wireless Diagnostics 嗅探器和 `tcpdump -I -i en0` 在部分机型上能用，但不稳定；项目 README 记录了在这台 Apple Silicon Mac 上的实测：`tcpdump -I -i en0` 收到 0 个帧。网上也有 macOS 26 加 Wi-Fi 7 新机型监听失效的报告。结论不变：监听抓包按 Linux 机器计划，Mac 用来运行分析。 |
| 「WPA3-SAE 离线解密很难」 | 更准确：**做不到**。SAE 的 PMK 依赖双方的私有随机数，被动抓包即使知道口令也推不出来。路由器要用 WPA2 或 WPA2/WPA3 混合模式（多数设备会协商 WPA2）。 |
| 「推荐 RTL8812AU」 | 它需要自己装外部驱动（DKMS）。改推 **MT7921AU 系**（如 Alfa AWUS036AXML）：Wi-Fi 6E，多篇评测说内核 5.18 以上自带驱动；但评测多为推广页，下单前要核对芯片和内核。AR9271 只有 2.4GHz，仅适合练手。 |
| 「缺解密后 DNS / SNI 识别一层，对应阶段 F」 | 阶段编号对不上：路线图里的阶段 F 是「解密到 IP 层」，已完成。DNS / SNI 识别是**阶段 H**，现已完成（DNS、mDNS、TCP 重组、HTTP、TLS SNI、QUIC SNI、按设备汇总、域名归应用、流量统计、一条命令出报告）。 |
| 只讲监听空口一条路 | 补上**路线 A（自己的网关）**，以及现成开源工具（ntopng + nDPI、AdGuard Home、Zeek）。见下。 |
| 「时长统计」 | 时长只是**从网络活动推出的估计**，不是屏幕时间。 |

## 一、总体判断

- 解密、协议分析本身有成熟开源工具（aircrack-ng、tshark、Wireshark）；本项目自己实现了每一层，并拿 tshark 当标准答案逐项对照。
- 识别靠三条证据：**DNS 明文查询 + TLS / QUIC 的 SNI + IP 归属（DNS 应答里的 IP 到域名映射）**，综合到「域名 / 应用」级精度。
- 现成的 nDPI（ntopng 用的识别引擎）**不认识国内应用**（抖音、快手、哔哩哔哩等只说 TLS），所以国内应用要靠我们的规则（`rules/apps.json`，由 v2fly 公开清单生成）。

## 二、两条路线

| | 路线 A：自己的网关 | 路线 B：监听空口 |
|---|---|---|
| 做法 | 黑盒路由器后面接一台自己的路由器 / 小主机，设备改连它的 WiFi；在它上面 tcpdump | 监听网卡抓空口加密帧，自己解密 |
| 是否要解 802.11 | 不要 | 要，且必须抓到设备连入的握手 |
| 覆盖 | 迁过来的设备 | 听得到的信道上的全部设备 |
| 现成工具 | ntopng + nDPI、AdGuard Home（只看 DNS） | aircrack-ng、tshark |
| 本项目入口 | `python3 -m wifi80211.report 网关抓包.pcap`（不需要密钥） | `python3 -m wifi80211.report 抓包.pcap --keys 密钥文件` |

```
路线 B：家里 WiFi（WPA2 加密）
   ↓ 监听网卡调到 AP 所在信道（Linux）
tcpdump / tshark 抓包 → all.pcap（先让一台设备断开重连，抓到握手）
   ↓ 回到任何机器（Mac 自带 Python 3.9 就能跑）
解密 → 明文 IP/TCP/UDP → DNS、TCP 重组、SNI（TLS / QUIC）、HTTP Host
   ↓
按设备汇总 → 域名归应用 → 流量与使用时长估计 → 报告
```

## 三、工具链职责

| 工具 | 角色 | 是否参与实际抓家流量 |
|---|---|---|
| aircrack-ng（airmon-ng / airdecap-ng） | 开监听模式、抓包、离线解密 | 是 |
| tshark / Wireshark | 抓包、解密、协议分析 | 是；也是本项目的标准答案（4.4.19） |
| ntopng + nDPI | 网关上的流量和应用统计 | 路线 A；nDPI 6.0 在本项目开发容器里用作第二个标准答案 |
| mac80211_hwsim | 内核级虚拟 WiFi，仅测试 / 仿真 | 否 |
| hostapd / wpa_supplicant | 虚拟 AP / STA，测试链路 | 否 |

## 四、识别能力与限制

| 证据 | 能看出 | 限制 |
|---|---|---|
| DNS 明文查询 | 客户端访问的域名 | DoH / DoT 加密 DNS 看不到内容（公开服务器能认出并标「加密 DNS」）；应用自带的 DNS 也可能绕过 |
| TLS / QUIC 的 SNI | 服务器域名 | ECH 部署后看不到（目前极少） |
| 明文 HTTP 的 Host | 网站 | 家里已很少 |
| IP 归属 | 兜底 | CDN 共享，精度低；只在没有名字时用 DNS 应答里的 IP 补名字 |

**关键技术现实：**
1. **单网卡单信道**：同一时刻只听一个信道。家里单 AP 信道固定时基本够用；多 AP 或换信道会漏包。
2. **WPA2 可离线解密（已知口令 + 抓到握手）；WPA3-SAE 做不到**（见订正记录）。
3. **必须抓到握手**：设备已经连着时，只抓到后面的数据解不开（除非直接给 TK）。抓包前让一台自己的设备断开重连。
4. **监听抓包用 Linux**；Mac 运行分析。

## 五、监听网卡说明

监听网卡 = 支持 **monitor mode** 的无线网卡，捕获信道上所有 802.11 帧。能否监听由**芯片 + 驱动**决定，与品牌 / 价格无关。

| 芯片 | 频段 | 说明 |
|---|---|---|
| MT7921AU（如 AWUS036AXML） | 2.4 / 5 / 6GHz | **首选**：多篇评测说内核 5.18+ 自带驱动，6GHz 监听仍在成熟中。下单前核对芯片和内核 |
| MT7612U 系 | 2.4 / 5GHz | 评测对具体型号用的是 MT7612U 还是 MT7610U 说法矛盾，必须核对 |
| AR9271 | 仅 2.4GHz | 最稳、资料最多，但家里设备多在 5G，只适合练手 |
| RTL8812AU | 2.4 / 5GHz | 需要自己装外部驱动，能用但麻烦 |
| Intel AX200 / 9260 等内置卡 | — | 内置卡的监听支持因驱动而异，没有核实，不推荐依赖 |

价格（参考搜索结果，波动大）：以美元计，路线 A 的 OpenWrt One 约 $68–125，GL.iNet Beryl AX 约 $99；监听网卡的价格没有可靠来源，下单时现查。

## 六、设备清单与成本

| 用途 | 设备 | 成本 |
|---|---|---|
| 抓包机 | Mac 上的 Linux 虚拟机（USB 直通，未验证），退路是树莓派或旧笔记本装 Ubuntu | 0–600 元 |
| 监听网卡 | 2×2、支持 5 GHz 和路由器信道宽度的 USB 网卡（MT7612U / MT7921AU 系；1×1 的不选），型号见 `docs/路线B实施方案.md` | 现查 |
| 路线 A 的网关（可选） | 到 openwrt.org 硬件表确认被支持的路由器 | 现查 |

## 七、与 wifi_scan_sim 的关系与建议顺序

1. **已完成（零成本、纯软件）**：阶段 A–H，全套 71 个测试通过，`v0.2.0` 已打 tag。详见 `docs/技术路线.md` 和 `docs/wifi_scan_sim_roadmap_v3.md`。
2. **下一步（当前主线，路线 B）**：按 `docs/路线B实施方案.md`：先确认网络是 WPA2、记下信道和链路速率，买 2×2 的监听网卡，用 Mac 上的 Linux 虚拟机抓第一份真实数据，用 `python3 -m wifi80211.report` 出报告；报告里没认出的域名（`apps.unmatched`）补进自己的规则。
3. **之后**：按需要做路线 A，拿到应用级和流量级的完整统计。

## 八、合法边界

- 自建家庭网络、自有设备、已知口令：合法。
- 访客和家人的设备流量也会被捕获：涉及他人流量需知情同意，不对外传播分析结果；发日志给别人前加 `--redact`。
- 不爆破口令、不抓他人 / 公共网络流量（与 README 的合法性边界一致）。

---

**已决定 / 待决定：**
- [x] SAE 这条路不走（做不到）；阶段 H 已完成。
- [x] 买监听网卡：决定买，推荐 MT7921AU 系，下单前核对芯片 / 内核。
- [ ] 路线 A 要不要做：等第一份真实数据后再定。

*（内容由AI生成，仅供参考）*
*（内容由AI生成，仅供参考）*
