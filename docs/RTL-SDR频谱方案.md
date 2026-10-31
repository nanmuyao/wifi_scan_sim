---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: 0bd2c4904e701d4269608d4ce4d80073_b7ed4463d52111f1a0da525400393706
    ReservedCode1: YfBJYt2FUUENEQtL6h1hpYJM+MvduZyeHE5wd6oPeBv3bvlGm4HhEAm0AgLlJpcWk5MteBYoMHINuq2v9eFi9D61VDdOgub8C9eN8K+aXvXfvbR5lWzx62u3R29ukQUTb2JYIVFU05iqQu3jDxbYLp53yagKGWQPm59wdjw8tHoe8Kd6LsP8TJyugJs=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: 0bd2c4904e701d4269608d4ce4d80073_b7ed4463d52111f1a0da525400393706
    ReservedCode2: YfBJYt2FUUENEQtL6h1hpYJM+MvduZyeHE5wd6oPeBv3bvlGm4HhEAm0AgLlJpcWk5MteBYoMHINuq2v9eFi9D61VDdOgub8C9eN8K+aXvXfvbR5lWzx62u3R29ukQUTb2JYIVFU05iqQu3jDxbYLp53yagKGWQPm59wdjw8tHoe8Kd6LsP8TJyugJs=
---



# RTL-SDR 频谱方案可行性文档（阶段 6 · 路线B）

## 1. 目标与范围

- **目标**：验证"RTL-SDR 下变频 + STM32 FFT"路线 B 是否值得投入硬件，给出**方案对比、硬件需求与成本、数据率/FFT 瓶颈分析、软件架构建议、无硬件仿真路径**，并给出明确结论。
- **范围**：研究学习用途，仅用于分析**自建实验网络**与合法可观测频段；不做解调他人受保护内容、不爆破（见第 9 节合法性边界）。
- **与项目关系**：阶段 1-5 解决的是 802.11 **协议层**扫描（AT 摘要、帧解析、WPA2 离线解密、ESP32 直扫）；本阶段验证的是**物理层频谱观测**路线——RTL-SDR 把射频下变频为基带 I/Q，由 FFT 观察信道能量分布。两者互补：频谱图回答"2.4GHz 频段里有什么能量"，802.11 解析回答"这些能量属于哪个 AP/STA"。

## 2. 方案对比

| 维度 | A：STM32F7 直解（完整 SDR） | B：PC 端 rtl_power 出图（备选） | C：混合（STM32 做前端，PC 做处理） |
|------|------------------------------|--------------------------------|-------------------------------------|
| 形态 | STM32F7-Discovery + RTL-SDR 棒，USB Host 直驱，板上 FFT + LCD 频谱 | PC 装 librtlsdr，`rtl_power` 宽带扫描出 CSV/热力图 | STM32 只做调谐控制/采集缓冲，I/Q 经 USB/UART 送 PC 处理 |
| 参考实现 | vpecanins/stm32f7-rtlsdr（半成品，USB Host 驱动 + 调谐器驱动已验证，FFT/DMA 未完成） | rtl_power（Osmocom librtlsdr 官方工具，成熟稳定） | 无现成样板，需自研 |
| 硬件投入 | 高：F7-Discovery（¥300-500）+ RTL-SDR 棒（¥50-100） | 低：仅 RTL-SDR 棒（¥50-100）+ PC | 中：F4/F7 板 + 棒 + 串口/USB 线 |
| 带宽能力 | 实时 2.4-3.2 MS/s 频谱，窄带观察（单窗口 ~2-3 MHz） | 宽带拼接扫描（可跨百 MHz 频段，靠重调谐缝合） | 取决于 PC 端处理能力，可接近 rtl_power |
| 便携性 | 好（独立设备，自带 LCD） | 差（依赖 PC） | 中 |
| 工程量 | 大：需移植 USB Host 自定义类 + RTL2832/E4000 驱动 + FFT + 显示 | 小：装包即用 | 大：协议与搬运自研 |
| 教学价值 | 最高：完整理解 USB Host、寄存器级调谐、DSP 流水线 | 低：只学工具用法 | 中 |
| 主要风险 | RTL-SDR 无法直接覆盖 2.4GHz WiFi（见 8.2）；项目半成品需补 DMA/FFT | WiFi 2.4GHz 同样超频段，需 upconverter；只能出图不能实时 | 同左，且工程量叠加 |

**初判**：若目标只是"看到频谱"，选 B；若目标是"理解 USB Host + DSP 全链路"（本项目研究学习定位），选 A，但必须正视 **2.4GHz 频段覆盖问题**（见 8.2），否则只能做 ≤1.7GHz 的通用频谱仪验证。

## 3. 参考项目研读：vpecanins/stm32f7-rtlsdr

> 仓库：github.com/vpecanins/stm32f7-rtlsdr（~41 Star / 11 Fork，约 2016 年停止维护）。作者目标：把 STM32F7-Discovery 变成便携 SDR——USB Host 直驱 RTL-SDR 棒，演示 F7 DSP 能力 + 在 STM32Cube USB Host Middleware 上实现自定义 USB 设备类（RTL-SDR 非标准 USB 类）。

### 3.1 已实现（可借鉴）

| 模块 | 文件 | 内容 |
|------|------|------|
| USB Host 自定义类 | `usbh_rtlsdr.c/.h` | 在 ST USB Host 框架注册 RTLSDR 类；枚举识别棒（VID/PID）；修改底层处理 **stalled control transfer**（I2C 探测调谐器芯片时的 stall 状态） |
| RTL2832U 基带控制 | `rtl.c/.h` | 移植 librtlsdr 逻辑：经控制传输读写解调器寄存器（块 0x00/0x01/0x10），采样率/FIR/数字 AGC 设置；I2C repeater 开/关 |
| E4000 调谐器驱动 | `tuner_e4k.c/.h` | 移植 librtlsdr：Fractional-N PLL（Fvco=Fosc×(Z+X/65536)，Fosc=28.8MHz）、频段切换（VHF2/VHF3/UHF/L-Band）、8 级增益（LNA→Mixer→IF）、芯片 ID 探测（寄存器 0x02==0x40） |
| 数据通路 | `main.c` | 枚举 → 配 RTL2832 → I2C 探测 E4000 → **EP1 bulk 批量传输**把 I/Q 样本拷贝到板载 SDRAM（首次测试提交记录：Stalled pipe） |

### 3.2 未完成（本项目需补齐，也是工程量主体）

- README 的 "Next tasks" 明确列出：**FFT 频谱显示未实现、DMA 加速未实现**。即原项目只打通"USB 搬运到 SDRAM"，DSP 与显示全链路仍是半成品。
- `E4K_tune_freq` 频率调谐被作者标注"需进一步验证"。

### 3.3 结论

原项目是**概念验证/教学型**半成品：USB Host 自定义类 + 寄存器级调谐器驱动是现成蓝本（约占硬件侧 50% 工作量），但 DMA 乒乓、CMSIS-DSP FFT、LCD 频谱显示需从零设计。**引用时必须标注为参考蓝本，不是可直接编译运行的成品**。

## 4. 硬件需求与成本

### 4.1 核心部件

| 部件 | 规格 | 参考价 | 用途 |
|------|------|--------|------|
| STM32F746-Discovery（或 F767） | Cortex-M7 @216MHz，FPU/DSP/SIMD，USB OTG FS/HS，板载 SDRAM + TFT-LCD | ¥300-500 | 主控：USB Host、FFT、显示 |
| RTL-SDR 棒 | RTL2832U + R820T2（或 E4000） | ¥50-100 | 射频前端：下变频 + I/Q 输出 |
| （可选）上变频器 | Ham It Up / 谐波混频 upconverter | ¥400-600 | 把 2.4GHz WiFi 频段搬到 RTL-SDR 可覆盖范围（关键，见 8.2） |
| USB OTG Host 线缆/座 | 标准 USB-A 母座（OTG 模式） | ¥10-30 | 连接 RTL-SDR 棒 |

合计（不升频）：约 ¥400-600；含 upconverter：约 ¥800-1200（接近采购清单"进阶档 ¥1300 频谱版"）。

### 4.2 芯片选型结论（沿用 roadmap 已知结论）

- **STM32F103 不足**：Cortex-M3 @72MHz、无 FPU、USB 仅 FS Device（无 Host OTG HS），搬运 4.8-6.4 MB/s + 实时 FFT 完全不现实；
- **路线 B 最低 F4/F7**：F407（M4 @168MHz + FPU + USB OTG HS）勉强可行但总线争用紧；**推荐 F746**（M7 @216MHz + 更强的 DSP/SIMD + 板载 SDRAM/LCD 免外围）。

## 5. 数据率与 FFT 瓶颈分析

### 5.1 RTL-SDR 数据率天花板

| 参数 | 数值 | 说明 |
|------|------|------|
| ADC 分辨率 | 8-bit I/Q | 理论动态范围约 48 dB，是 RTL2832U 主要瓶颈 |
| 稳定采样率 | ~2.4 MS/s | USB 2.0 带宽约束下的工程稳定值 |
| 标称最大采样率 | 3.2 MS/s | 名义上限，多数主机丢样本 |
| I/Q 流字节率 | 采样率 × 2 B/s | 2.4 MS/s → 4.8 MB/s；3.2 MS/s → 6.4 MB/s |
| 传输形态 | USB 2.0 bulk（EP1） | 实时可持续流上限约 6.4 MB/s |

### 5.2 STM32F7 算力评估（参照 ST AN4841 实测）

| FFT 点数 | 格式 | F746@216MHz 量级 |
|----------|------|------------------|
| 256 | Float-32 | 约百 μs |
| 1024 | Float-32 | 约 0.3-0.5 ms |
| 4096 | Float-32 | 数 ms 内可实时 |

- 帧周期 = FFT 点数 / 采样率。例：1024 点 @ 2.048 MS/s → 0.5 ms/帧，与 FFT 耗时（0.3-0.5 ms）**在同一量级，算力勉强够但余量小**；降采样率至 1.024 MS/s 或改用 Q15 定点 FFT 可拉开余量。
- **结论：CPU 算力不是瓶颈，余量取决于 FFT 点数与采样率组合。**

### 5.3 真正的瓶颈：USB 搬运与总线争用

1. **纯 CPU 拷贝不可行**：4.8-6.4 MB/s 逐字节软件搬运会吃掉大量 MIPS 且易丢样本；
2. **必须 USB DMA + 乒乓缓冲**：USB OTG HS 控制器 DMA 模式把 EP1 数据直接写 SDRAM，CPU 从另一缓冲读帧做 FFT，两块缓冲交替（ping-pong）；
3. **内存布局**：FFT 工作缓冲放 CCM/DTCM 或单独 SDRAM 区，避免与 USB DMA 争用总线；板载 SDRAM 容量远大于所需环形缓冲；
4. 这正是原项目列为 "Next tasks" 的两块未完成工作，也是**本项目最大的工程风险点**。

## 6. 软件架构建议

```
┌────────────────────────────────────────────────────────────┐
│ 显示层：LCD 频谱柱状图（LTDC/DMA2D 绘制）                    │
├────────────────────────────────────────────────────────────┤
│ 分析层：CMSIS-DSP FFT（arm_rfft_fast_f32）→ 功率谱 → 平滑/峰值 │
├────────────────────────────────────────────────────────────┤
│ 缓冲层：SDRAM 乒乓缓冲（USB DMA 写一块，CPU 读另一块）        │
├────────────────────────────────────────────────────────────┤
│ 搬运层：USB Host 自定义类（usbh_rtlsdr）EP1 bulk + DMA       │
├────────────────────────────────────────────────────────────┤
│ 控制层：RTL2832 寄存器（控制传输）→ I2C 中继 → E4000 调谐/增益 │
└────────────────────────────────────────────────────────────┘
```

| 模块 | 职责 | 参考 |
|------|------|------|
| `usbh_rtlsdr` | USB Host 枚举 + EP1 bulk 批量接收（DMA 模式） | vpecanins 源码移植 + ST USB Host 中间件 |
| `rtl2832` | 采样率/FIR/AGC 寄存器配置 | librtlsdr `rtlsdr_demod_*` |
| `tuner_e4k`（或 `r820t2`） | 频段/PLL/增益控制；I2C repeater 透传 | librtlsdr `tuner_e4k.c` |
| `sdr_buffer` | 乒乓缓冲管理 + 帧边界同步（避免 FFT 窗口跨采样断裂） | 自研 |
| `fft_spectrum` | `arm_rfft_fast_f32` + 对数功率谱 + 峰值/底噪统计 | CMSIS-DSP / omer-acarr Audio-Spectrum-Analyzer |
| `lcd_ui` | 频谱柱状图 + 频率/增益刻度 | F7-Discovery BSP |

**关键设计决策**：
- 调谐器访问全部走控制传输（端点 0），频率切换期间暂停批量接收，避免 I/Q 流与寄存器写冲突；
- 采样率默认 2.4 MS/s、FFT 1024 点起步（0.43 ms 帧周期 vs ~0.4 ms 计算），验证通过后再评估 3.2 MS/s 或 4096 点；
- 频谱输出预留串口协议（`+SPECTRUM:<freq_start>,<freq_step>,<n>,<dbm...>`），与 `tools/serial_wifi_plot.py` 上位机兼容，作为 LCD 之外的兜底输出。

## 7. 无硬件仿真路径（沿用"先仿真、后硬件"策略）

| 层 | 环境 | 做法 | 验证点 |
|----|------|------|--------|
| L1 工具链验证 | PC（librtlsdr） | 装 librtlsdr + rtl_power；有棒则扫 FM/航空频段，无棒则用官方测试向量/录制 raw 文件 | 熟悉 I/Q 格式、FFT 窗口、频率校正（`rtl_test -p`） |
| L2 算法仿真 | PC（Python/numpy） | 用预置 I/Q raw 数据（录制的或合成的 OFDM/单音）跑 FFT 功率谱，与 rtl_power 输出对比；先做"PC 端 rtl_power 出图"闭环 | 验证"下变频→FFT→频谱图"信号链路的正确性 |
| L3 固件仿真 | Wokwi/qemu + 桩数据 | 把 FFT/乒乓缓冲/串口协议移植为 C，注入桩 I/Q（环形数组），PC 侧 gcc 单测断言功率谱峰值位置 | USB 之外的算法与缓冲逻辑在无硬件下全部验证 |
| L4 硬件联调 | STM32F7-Discovery + 棒（采购后） | USB Host 枚举 → E4000 调谐 → DMA 乒乓 → FFT → LCD/串口 | 真实 I/Q 流全程跑通 |

- **仿真意义**：L1-L3 可覆盖 FFT 算法、缓冲管理、输出协议约 70% 工作量；USB Host 类驱动与调谐器驱动只能硬件验证（vpecanins 代码作为移植起点可显著缩短调试周期）；
- **验收口径**：L1-L3 全部通过后再采购 F7 板，避免"先买板再踩坑"（与阶段 5 一致）。

## 8. 可行性结论与建议

### 8.1 结论

| 问题 | 结论 |
|------|------|
| STM32F7 能否做 USB Host 搬运 + FFT？ | **能**。M7@216MHz 的 FFT 算力充足（1024 点约 0.3-0.5 ms），USB OTG HS + DMA 乒乓可支撑 4.8-6.4 MB/s I/Q 流；工程风险集中在 DMA/乒乓与总线争用，不是算力 |
| vpecanins/stm32f7-rtlsdr 可否直接复用？ | **半成品，可作蓝本**：USB Host 自定义类、RTL2832/E4000 寄存器级驱动可直接移植；FFT 与 DMA 需自研 |
| 与阶段 1-5 的关系？ | **互补但不耦合**：频谱方案回答物理层"有没有能量"，不能替代 802.11 帧解析；无法直接复用阶段 1-5 的解析代码 |
| PC 端 rtl_power 能否作为替代？ | **可**，且是成本最低的"看到频谱"路径；但教学价值低，且宽带拼接非实时 |

### 8.2 关键风险：2.4GHz WiFi 频段覆盖

- RTL2832U 常见调谐器覆盖上限：E4000 实测约 **64-1700 MHz**（标称可达 2200 MHz 但实际不稳），R820T2 约 **24-1766 MHz**；
- **WiFi 2.4 GHz 频段超出两者直接调谐范围**，不升频收不到；
- 对策：
  1. **加 upconverter**（如 Ham It Up）把 2.4 GHz 搬移到 100-500 MHz 中频，成本 ¥400-600；
  2. **降级目标**：先做 ≤1.7 GHz 通用频谱仪（FM/航空/ISM 902-928 MHz 等）验证 USB Host + FFT 架构，WiFi 频谱作为后续升级；
  3. **混合路线**：WiFi 频谱直接交给 PC 端 rtl_power（加 upconverter）或 ESP32 直扫（阶段 5 已覆盖 2.4 GHz 协议层）。

### 8.3 建议

1. **不立项硬件采购**，先完成 L1-L2（PC 端 rtl_power + numpy FFT 仿真），确认"下变频→FFT→频谱"链路理解到位；
2. 若后续要做，**选 F746-Discovery + R820T2 棒**（成本最低、文档最多），先跑通用频谱仪验证 DMA 乒乓，再评估 upconverter 上 WiFi；
3. 把"RTL-SDR 覆盖上限 ~1.7 GHz"写进采购清单与 README，避免误买；
4. 本项目阶段 6 的**可交付成果**定为：本文档（可行性结论）+ L1-L2 仿真脚本（可选），不依赖硬件。

## 9. 合法性边界（与项目整体一致）

- 仅观察**自建实验网络**、公共广播频段（FM/航空/ISM）与法律允许的频谱能量分布；
- 不抓取并解调他人受保护内容、不爆破口令、不用于未经授权的频谱监控；
- 使用 upconverter/直采仅限合法实验用途。
*（内容由AI生成，仅供参考）*
*（内容由AI生成，仅供参考）*
