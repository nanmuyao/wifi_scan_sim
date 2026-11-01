# -*- coding: utf-8 -*-
"""
wifi80211：802.11 帧的解析、解密与密钥推导（纯标准库，Python 参考实现）。

  capture / radiotap / frames / parser    抓包文件读取、radiotap、逐帧迭代、MAC 头与管理帧解析
  ie / action / amsdu                     信息元素、Action 帧、A-MSDU
  crypto / kdf                            加密原语（CCM / GCM / RC4 / TKIP / Michael）、密钥派生（PRF / KDF / CMAC / 密钥包装）
  eapol / handshake / ft / groupkeys      EAPOL-Key、四次握手与 PTK、快速切换（FT）、组密钥（GTK / IGTK / MLO）
  decrypt / tdls                          数据帧与管理帧解密（CCMP / GCMP / TKIP / WEP / BIP / 用户 TK）、TDLS
  sae                                     SAE 认证帧与曲线检查
  net / pipeline                          解密后的 LLC / ARP / IP / UDP / TCP / ICMP / DHCP，以及把以上各层接起来的 decrypt_capture
  dns / tcpstream / tls / quic            解密后的内容识别：DNS / mDNS 报文、TCP 流重组、TLS ClientHello（SNI）、QUIC Initial
  plain / traffic                         明文抓包（以太网 / Linux cooked）读成包并认设备；每台设备每条流的包数和字节、按应用汇总
  activity / apps                         把以上读出的 DNS 查询和 SNI 按设备（MAC）汇总成事件和访问时间线；域名归到应用（rules/apps.json）并估计使用时长

  logs                                    日志：setup() 装处理器、遮密钥、--redact、运行头（规范见 docs/日志规范.md）

用法：from wifi80211 import pipeline；pipeline.decrypt_capture(frames, keys)（见 docs/architecture 和路线图）。
"""
import logging

__version__ = "0.1.0"
logging.getLogger(__name__).addHandler(logging.NullHandler())          # 库本身不配置日志；命令行用 logs.setup()
