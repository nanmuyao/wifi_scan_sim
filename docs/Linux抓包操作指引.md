---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 0bd2c4904e701d4269608d4ce4d80073_2dbcaed2d51411f180d5525400248c00
    ReservedCode1: +pw8g5pZdwzU17ERlbEWeaRVqm73oazYQ6DE7DjWbtKvCvHTF5g2jpfP6KhJYL8Ae8KLkvJEMdGcuDQVwE06JLMbRjyZjl0hifBq0iemVL+LS+wXRrsqhwrt123ZTFif17iCXpjVERlNgieMV3T2rdAwehZED635+dh/lJHmXfuuecRXy6F4jKxtgJ0=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 0bd2c4904e701d4269608d4ce4d80073_2dbcaed2d51411f180d5525400248c00
    ReservedCode2: +pw8g5pZdwzU17ERlbEWeaRVqm73oazYQ6DE7DjWbtKvCvHTF5g2jpfP6KhJYL8Ae8KLkvJEMdGcuDQVwE06JLMbRjyZjl0hifBq0iemVL+LS+wXRrsqhwrt123ZTFif17iCXpjVERlNgieMV3T2rdAwehZED635+dh/lJHmXfuuecRXy6F4jKxtgJ0=
---

# Linux 抓包操作指引：监听模式抓 802.11 帧并用现有解析器验证

> 阶段 3（P0）：在支持监听模式的 Linux 机器上抓取真实 802.11 帧（重点：Probe Request /
> Beacon / WPA2 握手 EAPOL），回传后用仓库内 `wifi_frame_parser.py` 做字节级验证。
> macOS 网卡通常不支持真 RFMON（详见 README「macOS 监听模式限制」），因此抓包环节在 Linux 完成。

## 1. 目标

1. 开启网卡 **monitor（监听）模式**，抓取本机可见的 802.11 管理帧与 EAPOL 帧；
2. 保存为 `.pcap`（建议带 Radiotap 头）；
3. 回传到本项目所在机器，执行：

```bash
python3 wifi_frame_parser.py --pcap capture.pcap
```

4. 预期输出：逐帧列出 Beacon / Probe Request / Authentication / EAPOL（阶段 4 扩展）等，
   与抓包现场环境可对应。

## 2. 前置条件

- **Linux**（Ubuntu / Debian / Kali 均可），内核 ≥ 4.0；
- 一张支持监听模式的无线网卡。检查方法：

```bash
iw list | grep -A 12 "Supported interface modes"
```

输出中需包含 `monitor`。常见支持：Intel AX200/AX210、Atheros AR9271（USB）、
MediaTek MT7612U（USB）、Ralink RT5370（USB）等。**不支持的网卡（多数笔记本板载
Realtek）会报 `Operation not supported`**。

- 工具：`iw`（`sudo apt install iw`）、`tcpdump`（`sudo apt install tcpdump`），
  可选 `airodump-ng`（`sudo apt install aircrack-ng`）。

## 3. 操作步骤

### 3.1 停用网络管理（避免干扰）

NetworkManager / wpa_supplicant 会周期性切信道、发探测，先停掉：

```bash
sudo systemctl stop NetworkManager
sudo nmcli radio wifi off        # 等效：iw dev wlan0 set power_save off
```

### 3.2 进入监听模式

```bash
export IF=wlan0                  # 按实际网卡名替换
sudo ip link set $IF down
sudo iw dev $IF set type monitor
sudo ip link set $IF up
sudo iw dev $IF set channel 6    # 2.4G 常用信道；也支持 36/149 等 5G 信道
```

确认模式：

```bash
iw dev $IF info                  # type 应为 monitor
```

> 提示：`set channel` 失败提示 `Device or resource busy` 时先执行 3.1 停用网络管理。
> 想全信道轮换抓包可用 `airodump-ng $IF`（自动跳信道）替代固定信道。

### 3.3 抓包

方式 A（tcpdump，推荐，生成标准 pcap）：

```bash
sudo tcpdump -i $IF -y IEEE802_11_RADIO -w capture.pcap
```

- `-y IEEE802_11_RADIO`：强制 Radiotap 头，与 `wifi_frame_parser.py` 支持的链路层一致；
- 默认抓所有帧（含 Probe Request/Response、Beacon、Auth、EAPOL 数据帧）；
- 只抓管理帧：`type mgt`；只抓 Probe：`type mgt subtype probe-req`；
- 抓握手 EAPOL：`ether proto 0x888e` 或 `wlan type data subtype qos-data` 配合 `port 888e`。

方式 B（airodump-ng，方便看信道/AP）：

```bash
sudo airodump-ng $IF --band 2g -w capture --output-format pcap
```

抓够 1~3 分钟（覆盖周围 Probe 探测与可能的握手）后 `Ctrl+C`。

### 3.4 恢复网卡

```bash
sudo ip link set $IF down
sudo iw dev $IF set type managed
sudo ip link set $IF up
sudo systemctl start NetworkManager   # 恢复网络管理
```

### 3.5 回传并验证

把 `capture.pcap`（或 `capture-01.cap`）拷贝到本项目根目录，然后：

```bash
python3 wifi_frame_parser.py --pcap capture.pcap
```

若抓包时同时做了 WPA2 连接（见 4），阶段 4 的 `wpa2_handshake.py --pcap capture.pcap`
可进一步解析握手报文（1/4、2/4、3/4、4/4 及 ANonce/SNonce/MIC/Key Info）。

## 4. 抓一份「四次握手」样本（供阶段 4 验证）

1. 准备一台已知口令的 WPA2 AP（自建路由器或手机热点）；
2. 监听模式锁定该 AP 所在信道（`airodump-ng` 可显示 AP 信道）；
3. 终端 B 发起连接（如 `nmcli dev wifi connect <SSID> password <口令>` 或手机连接）；
4. 终端 A 的 tcpdump 会抓到 EAPOL 帧（wlan type 带 LLC/SNAP 的 0x888e 数据帧），
   典型特征为 4 条连续的 `EAPOL` 报文；
5. 停止抓包，回传验证。

> 合法性边界：仅允许抓取**自建网络 / 已获授权的网络**的握手，禁止对他人网络实施
> 抓包与破解。

## 5. 常见问题

| 现象 | 原因 | 处理 |
|------|------|------|
| `set type monitor` 报 Operation not supported | 网卡/驱动不支持监听模式 | 换网卡（见前置条件），或使用 USB 外置网卡 |
| 抓包 0 packets | 信道未锁定 / 网络管理干扰 | 3.1 停管理、3.2 显式 set channel；必要时 `iw dev $IF set power_save off` |
| tcpdump Permission denied | 未用 root | `sudo tcpdump ...` |
| 只有 Beacon 没有 Probe | 周围设备未主动扫描 / 信道未覆盖 | 延长抓包时间；锁定 2.4G 信道 1/6/11 轮流抓 |
| 解析器报 Unknown linktype | 抓包未带 Radiotap 头 | 加 `-y IEEE802_11_RADIO` 重抓 |
| 抓包文件巨大 | 全信道 + 长时间 | 用 `-c 5000` 限制包数，或只抓目标帧类型 |

## 6. 与解析器的对应关系

| 抓包产物 | 解析器验证点 |
|----------|--------------|
| `capture.pcap`（Radiotap 容器） | `read_pcap` 容器解析：magic / 版本 / 链路类型 / 时戳 |
| Probe Request（含空 SSID 广播） | 管理帧解析：SSID、STA MAC、RSSI 来源字段 |
| Beacon | 管理帧解析：SSID、信道、加密能力 |
| EAPOL M1~M4 | 阶段 4 `wpa2_handshake.py`：握手序号、ANonce/SNonce、MIC、Key Info |
*（内容由AI生成，仅供参考）*
