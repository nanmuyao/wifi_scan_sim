# -*- coding: utf-8 -*-
"""
快速切换（802.11r，FT）的密钥层级（IEEE 802.11-2020 12.7.1.7）。纯标准库。

  XXKey      FT-PSK：PSK；FT-802.1X：MSK 的前 256（SHA-384 套件 384）比特；FT-SAE：SAE 的 PMK
  R0-Key-Data = KDF(XXKey, "FT-R0", SSID长度(1) ‖ SSID ‖ MDID(2) ‖ R0KH-ID长度(1) ‖ R0KH-ID ‖ S0KH-ID(6，STA 的 MAC))，输出 PMK 长度 + 128 比特
      PMK-R0 = 前 PMK 长度；PMK-R0Name-Salt = 后 128 比特
  PMKR0Name  = 前 128 比特( Hash("FT-R0N" ‖ PMK-R0Name-Salt) )
  PMK-R1     = KDF(PMK-R0, "FT-R1", R1KH-ID(6) ‖ S1KH-ID(6，STA 的 MAC))，输出 PMK 长度
  PMKR1Name  = 前 128 比特( Hash("FT-R1N" ‖ PMKR0Name ‖ R1KH-ID ‖ S1KH-ID) )
  PTK        = KDF(PMK-R1, "FT-PTK", SNonce ‖ ANonce ‖ BSSID ‖ STA 的 MAC)，输出 KCK ‖ KEK ‖ TK  （注意：SNonce 在前，地址不排大小）
Hash 与 KDF 用同一个：SHA-256（AKM 3 / 4 / 9）、SHA-384（13 / 19）、25 由 MIC 长度（ECC 组）决定。
"""
import hashlib

from . import kdf

DIGEST_LEN = {"sha256": 32, "sha384": 48, "sha512": 64}


def derive_r0(xxkey, hash_name, ssid, mdid, r0kh_id, s0kh_id):
    """返回 (PMK-R0, PMKR0Name)。mdid 是元素里的 2 个原始字节。"""
    n = DIGEST_LEN[hash_name]
    context = bytes([len(ssid)]) + bytes(ssid) + bytes(mdid) + bytes([len(r0kh_id)]) + bytes(r0kh_id) + bytes(s0kh_id)
    data = kdf.kdf(hash_name, xxkey, b"FT-R0", context, (n + 16) * 8)
    pmk_r0, salt = data[:n], data[n:]
    name = getattr(hashlib, hash_name)(b"FT-R0N" + salt).digest()[:16]
    return pmk_r0, name


def derive_r1(pmk_r0, hash_name, r0_name, r1kh_id, s1kh_id):
    """返回 (PMK-R1, PMKR1Name)。"""
    n = DIGEST_LEN[hash_name]
    pmk_r1 = kdf.kdf(hash_name, pmk_r0, b"FT-R1", bytes(r1kh_id) + bytes(s1kh_id), n * 8)
    name = getattr(hashlib, hash_name)(b"FT-R1N" + bytes(r0_name) + bytes(r1kh_id) + bytes(s1kh_id)).digest()[:16]
    return pmk_r1, name


def derive_ptk(pmk_r1, hash_name, snonce, anonce, bssid, sta, kck_len, kek_len, tk_len):
    """返回 (KCK, KEK, TK)。"""
    data = kdf.kdf(hash_name, pmk_r1, b"FT-PTK", bytes(snonce) + bytes(anonce) + bytes(bssid) + bytes(sta), (kck_len + kek_len + tk_len) * 8)
    return data[:kck_len], data[kck_len:kck_len + kek_len], data[kck_len + kek_len:]
