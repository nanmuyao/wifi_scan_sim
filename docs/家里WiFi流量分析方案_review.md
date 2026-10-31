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



# 家庭 WiFi 流量分析方案（Review 版）

> 目标：在自家 WiFi 网络内，捕获全屋设备的无线流量，解密后识别出"流量去了哪些网站"，用于个人时间管理（如抖音/快手使用时长统计）等合法用途。
> 结论先行：**可行、成熟，成本约 100-200 元**（需 Linux 机器 + 双频监听网卡）。

---

## 一、总体判断

- 链路所需每一环节都有成熟开源工具（aircrack-ng / tshark / Wireshark），无需自研基础能力。
- 识别网站靠三条证据：**DNS 明文查询 + TLS SNI + IP 归属**，综合可达"网站/应用级"精度。
- 与 wifi_scan_sim 的关系：解密部分项目已完整实现（可对拍验证），缺"解密后 DNS/SNI 识别"一层，对应阶段 F。

## 二、完整链路

```
家里 WiFi（WPA2/WPA3 加密）
   ↓ 监听网卡调到 AP 所在信道
Linux 抓包机：airmon-ng start → tshark -i mon0 -w all.pcap
   ↓ 离线（回到 macOS 亦可）
解密：airdecap-ng / wpa_supplicant / tshark 解密选项
   ↓ 明文 IP/TCP/DNS/TLS
识别网站：DNS 查询 + TLS SNI + IP 归属
```

## 三、工具链职责（含 hwsim 澄清）

| 工具 | 角色 | 是否参与实际抓家流量 |
|---|---|---|
| aircrack-ng（airmon-ng / airdecap-ng） | 开监听模式、抓包、离线解密 | 是 |
| tshark / Wireshark | 抓包、解密、协议分析 | 是 |
| mac80211_hwsim | 内核级虚拟 WiFi，仅测试/仿真 | **否**（不参与实际抓包） |
| hostapd / wpa_supplicant | 虚拟 AP/STA，测试链路 | 否（测试用） |

### 现成可用的开源工具（完整清单）

| 开源工具 | 用途 | 与本项目关系 |
|---|---|---|
| **Wireshark / tshark** | 抓包 + 解析 + 解密全功能 | 已在用：v3 的 oracle 差分标准答案（tshark 4.4.19） |
| **aircrack-ng**（含 airdecap-ng） | WEP/WPA 离线解密 pcap、监听模式管理 | 可直接替代手写解密的"现成品"；本项目代码是复刻学习 |
| **Scapy** | 802.11 帧构造/解析 | 已在用：仿真造包、测试样例 |
| **Kismet** | 无线网络检测/嗅探/IDS | 真实抓包场景可选用 |
| **hostapd / wpa_supplicant** | 虚拟 AP / STA（配 hwsim） | 已在路线中：搭虚拟 WiFi 验证链 |
| **mac80211_hwsim** | 内核级虚拟 WiFi | 已在路线中：无硬件抓包方案 |

## 四、识别能力与限制

| 证据 | 能看出 | 限制 |
|---|---|---|
| DNS 明文查询 | 客户端访问的域名 | DoH/DoT 加密 DNS 则失效；家庭路由器默认多为明文 DNS |
| TLS SNI | HTTPS 服务器域名 | ECH 部署极少，暂可忽略 |
| IP 归属 | 应用级判断（抖音/快手等 CDN 段） | CDN IP 共享，精确度到"应用"级 |

**关键技术现实：**
1. **单网卡单信道**：一张监听网卡同一时刻只听一个信道。2.4G/5G 双频、设备分散会漏包。家庭单 AP 场景（信道固定）基本可行；全量覆盖需双网卡或确认所有设备同频段。
2. **WPA2 可离线解密（已知口令）；WPA3-SAE 离线解密很难**。建议路由器用 WPA2/WPA3 混合模式，多数设备会协商 WPA2。
3. 抓包机需 Linux；macOS 无 RFMON，无法监听。

## 五、监听网卡说明

监听网卡 = 支持 **monitor mode（监听模式）** 的无线网卡，捕获信道上所有 802.11 帧（不限发给自己的）。

- 能否监听由**芯片 + 驱动**决定，与品牌/价格无关。
- macOS 自带网卡（Broadcom）驱动不开放 RFMON → 不可用。
- 选购认芯片：

| 芯片 | 频段 | 说明 |
|---|---|---|
| AR9271 | 2.4GHz only | 便宜经典（WN722N v1），停产需淘二手 |
| RTL8812AU | 2.4 + 5GHz | 推荐：双频、USB、驱动好，约 50-100 元 |
| Intel AX200 / 9260 | 2.4 + 5GHz | 笔记本内置卡，Linux 原生支持 |

## 六、设备清单与成本

| 用途 | 设备 | 成本 |
|---|---|---|
| 抓包机 | 树莓派 4B/5 或旧笔记本装 Linux（有旧机则 0 元） | 0-600 元 |
| 监听网卡 | RTL8812AU 双频 USB 网卡 | 50-100 元 |
| 合计 | — | **约 100-200 元** |

## 七、与 wifi_scan_sim 的关系与建议顺序

1. 现阶段（阶段 E 收尾 / 阶段 F）：纯代码推进，零成本——先补"解密后 LLC/SNAP → DNS/SNI/IP 归属识别"（阶段 F）。
2. 阶段 F 完成后：上抓包机做实景验证（Linux + 监听网卡）。
3. 实景应用（短视频时长统计）：解密 + DNS/SNI 识别即可落地。

## 八、合法边界

- 自建家庭网络、自有设备、已知口令：合法。
- 访客设备流量也会被捕获：涉及他人流量需知情同意，不对外传播分析结果。
- 不爆破口令、不抓他人/公共网络流量（与 wifi_scan_sim README 合法性边界一致）。

---

**待决策项：**
- [ ] 阶段 E 收尾（SAE 参考 hostapd 源码）还是直接进阶段 F？
- [ ] 是否现在就采购监听网卡（RTL8812AU），还是等阶段 F 完成后再买？
*（内容由AI生成，仅供参考）*
*（内容由AI生成，仅供参考）*
