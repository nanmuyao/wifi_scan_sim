#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tdls80211：建立帧解析、TPK 推导、FTE MIC、对端直连帧解密。MIC 与帧用 pycryptodome（CMAC / CCM）独立构造；真实抓包见 tests/oracle/test_tdls_oracle.py。"""
import hashlib
import hmac
import os
import struct
import sys

from Crypto.Hash import CMAC
from Crypto.Cipher import AES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
import tdls80211 as t  # noqa: E402
from aead_build import A1, A2, A3, build, frame  # noqa: E402

failures = []


def check(ok, msg):
    print("  [%s] %s" % ("PASS" if ok else "FAIL", msg))
    if not ok:
        failures.append(msg)


INIT, RESP, BSS = bytes([2, 0, 0, 0, 0, 0x99]), bytes([2, 0, 0, 0, 0, 0x11]), bytes([2, 0, 0, 0, 0, 0xbb])
MACS = lambda b: ":".join("%02x" % x for x in b)                          # noqa: E731
SN, AN = bytes(range(32)), bytes(range(100, 132))
SNAP = b"\xaa\xaa\x03\x00\x00\x00\x89\x0d"
RSNE = bytes([48, 20]) + bytes.fromhex("0100000fac070100000fac040100000fac070c02")
TIMEOUT = bytes([56, 5, 2, 0xc0, 0xa8, 0, 0])
LINK = bytes([101, 18]) + BSS + INIT + RESP


def fte(sn, an, mic=bytes(16)):
    return bytes([55, 82]) + b"\x00\x03" + mic + an + sn


def tpk(sn=SN, an=AN, init=INIT, resp=RESP, bss=BSS):
    """独立的公式：hmac 手写的 KDF-256。"""
    ki = hashlib.sha256(min(sn, an) + max(sn, an)).digest()
    ctx = min(init, resp) + max(init, resp) + bss
    out = hmac.new(ki, struct.pack("<H", 1) + b"TDLS PMK" + ctx + struct.pack("<H", 256), hashlib.sha256).digest()
    return out[:16], out[16:]


KCK, TK = tpk()


def mic(kck, seq, init, resp, link, rsne, timeout, fte_zero):
    return CMAC.new(kck, ciphermod=AES, msg=init + resp + bytes([seq]) + link + rsne + timeout + fte_zero).digest()


def request():
    return SNAP + bytes([2, 12, 0, 1]) + b"\x20\x04" + bytes([1, 2, 12, 24]) + RSNE + fte(SN, bytes(32)) + TIMEOUT + LINK


def response(good=True, link=LINK, rsne=RSNE, token=1, sn=SN, an=AN):
    kck = tpk(sn, an)[0]
    f0 = fte(sn, an)
    m = mic(kck, 2, INIT, RESP, LINK, rsne, TIMEOUT, f0)
    return SNAP + bytes([2, 12, 1]) + b"\x00\x00" + bytes([token]) + b"\x21\x24" + bytes([1, 2, 12, 24]) + rsne + fte(sn, an, m if good else bytes(16)) + TIMEOUT + link


def confirm(good=True):
    f0 = fte(SN, AN)
    m = mic(KCK, 3, INIT, RESP, LINK, RSNE, TIMEOUT, f0)
    return SNAP + bytes([2, 12, 2]) + b"\x00\x00" + bytes([1]) + bytes([61, 2, 0, 0]) + RSNE + fte(SN, AN, m if good else bytes(16)) + TIMEOUT + LINK


print("== 密钥推导 ==")
kck, tk = t.derive_tpk(SN, AN, INIT, RESP, BSS)
check((kck, tk) == (KCK, TK) and len(kck) == 16 and len(tk) == 16, "TPK-KCK 前 128 比特、TPK-TK 后 128 比特（对照 hmac 手写的 KDF-256）")
check(t.derive_tpk(AN, SN, INIT, RESP, BSS) == (KCK, TK), "两个 Nonce 谁是 SNonce 谁是 ANonce 不影响（取 min / max）")
check(t.derive_tpk(SN, AN, RESP, INIT, BSS) == (KCK, TK), "发起方 / 响应方互换不影响（取 min / max）")
check(t.derive_tpk(SN, AN, INIT, RESP, bytes(6))[1] != TK and t.derive_tpk(SN, AN, INIT, bytes(6), BSS)[1] != TK and t.derive_tpk(SN, bytes(32), INIT, RESP, BSS)[1] != TK, "BSSID、地址、Nonce 变了结果变")

print("== 建立帧解析 ==")
rq = t.parse_action(request()[8:])
check((rq["action"], rq["status"], rq["token"], rq["bssid"], rq["initiator"], rq["responder"]) == (0, None, 1, MACS(BSS), MACS(INIT), MACS(RESP)), "Setup Request：动作 0、没有状态、令牌、链路标识（BSSID ‖ 发起方 ‖ 响应方）")
check(rq["fte"]["snonce"] == SN and rq["rsne"]["akm"] == [(0x000fac, 7)], "Request 的 FTE 里是发起方的 SNonce；RSNE 的认证方式是 7（TDLS）")
rs = t.parse_action(response()[8:])
check((rs["action"], rs["status"], rs["token"]) == (1, 0, 1) and rs["fte"]["anonce"] == AN and rs["fte"]["snonce"] == SN, "Setup Response：状态 2 字节在令牌之前，能力 2 字节之后才是元素；FTE 里 ANonce 和 SNonce")
cf = t.parse_action(confirm()[8:])
check((cf["action"], cf["status"], cf["token"]) == (2, 0, 1) and cf["fte"]["mic"] != bytes(16), "Setup Confirm：状态、令牌，元素紧跟其后（没有能力字段）")
bad_status = t.parse_action((response()[8:11] + b"\x01\x00" + response()[13:]))
check(bad_status["status"] == 1, "状态按小端读")
check(t.parse_action(bytes([2, 12, 3, 0, 0, 0])) is None and t.parse_action(bytes([2, 13, 0, 1, 0, 0])) is None and t.parse_action(bytes([3, 12, 0, 1, 0, 0])) is None and t.parse_action(b"\x02\x0c") is None, "拆除（动作 3）/ 别的类别 / 别的类型 / 太短：None")
check(t.parse_action(request()[8:-3]) is None, "元素被截断：None")
noln = t.parse_action((SNAP + bytes([2, 12, 0, 1]) + b"\x20\x04" + RSNE + fte(SN, bytes(32)) + TIMEOUT)[8:])
check(noln["bssid"] is None and noln["link_raw"] is None, "没有链路标识：地址为 None")
short_link = t.parse_action((SNAP + bytes([2, 12, 0, 1]) + b"\x20\x04" + bytes([101, 17]) + bytes(17))[8:])
check(short_link["bssid"] is None, "链路标识不是 18 字节：不当地址用")

print("== MIC ==")
msg_r = t.parse_action(response()[8:])
check(t.mic_of(KCK, t.SETUP_RESPONSE, msg_r) == msg_r["fte"]["mic"], "Response（序号 2）的 MIC 与独立的 CMAC 一致")
msg_c = t.parse_action(confirm()[8:])
check(t.mic_of(KCK, t.SETUP_CONFIRM, msg_c) == msg_c["fte"]["mic"], "Confirm（序号 3）的 MIC 与独立的 CMAC 一致")
check(t.mic_of(KCK, t.SETUP_CONFIRM, msg_r) != msg_r["fte"]["mic"] and t.mic_of(bytes(16), t.SETUP_RESPONSE, msg_r) != msg_r["fte"]["mic"], "序号用错 / KCK 用错：不一致")

print("== track：推 TPK 并验证 ==")
M = lambda *ms: {i + 17: [m] for i, m in enumerate(ms)}                  # noqa: E731
keys = t.track(M(request(), request(), response(), response(), confirm(), confirm()))
check(len(keys) == 1 and keys[0].tk == TK and keys[0].kck == KCK and (keys[0].initiator, keys[0].responder, keys[0].bssid, keys[0].cipher) == (MACS(INIT), MACS(RESP), MACS(BSS), "CCMP-128"), "三件套（各出现两次：STA→AP、AP→STA）去重后得到一把 TPK")
check(keys[0].frames == {"response": 19, "confirm": 21, "response_mic_ok": True, "confirm_mic_ok": True}, "记录 Response / Confirm 的帧号（取第一次出现），两个 MIC 都通过")
only_r = t.track(M(request(), response(), confirm(good=False)))
check(len(only_r) == 1 and only_r[0].frames["response_mic_ok"] and not only_r[0].frames["confirm_mic_ok"], "Confirm 的 MIC 不对但 Response 的对：仍然收，记下哪个通过")
only_c = t.track(M(request(), response(good=False), confirm()))
check(len(only_c) == 1 and not only_c[0].frames["response_mic_ok"] and only_c[0].frames["confirm_mic_ok"], "Response 的 MIC 不对但 Confirm 的对：仍然收")
check(t.track(M(request(), response(good=False), confirm(good=False))) == [], "两个 MIC 都不对：不收")
check(t.track(M(request(), response(good=False))) == [], "只有 Response 且 MIC 不对：不收")
check(len(t.track(M(request(), response()))) == 1 and t.track(M(request(), response()))[0].frames["confirm"] is None, "没有 Confirm、Response 的 MIC 对：收，confirm 为 None")
check(t.track(M(request(), confirm())) == [], "没有 Response 就拿不到 ANonce：不收")
wrong_cipher = RSNE[:10] + bytes([0, 0x0f, 0xac, 2]) + RSNE[14:]                # 成对套件 2（TKIP）：RSNE 头 2 字节 + 版本 2 + 组套件 4 + 成对套件数 2 之后
check(t.track(M(response(rsne=wrong_cipher))) == [], "成对套件不是 CCMP-128：不收（TDLS 规定 CCMP）")
check(t.track({1: [b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + response()[8:]], 2: [b"\x01\x02"], 3: [response()[:7]]}) == [], "以太类型不是 0x890d / 太短 / 不是 SNAP：不当 TDLS")
check(t.track({}) == [], "没有 MSDU：空")
nolink = SNAP + bytes([2, 12, 1]) + b"\x00\x00" + bytes([1]) + b"\x21\x24" + bytes([1, 2, 12, 24]) + RSNE + fte(SN, AN) + TIMEOUT
check(t.track({1: [nolink]}) == [], "没有链路标识的 Response：不知道是谁和谁，不收（也不崩溃）")
check(t.track({1: [b"\x00\x00\x00\x00\x00\x00\x89\x0d" + response()[8:]]}) == [], "不是 AA AA 03 开头（不是 SNAP）、以太类型位置恰好是 0x890d：不当 TDLS")
SN2, AN2 = bytes(range(40, 72)), bytes(range(150, 182))
two_dialogs = t.track({1: [response()], 2: [response(token=2, sn=SN2, an=AN2)]})
check(len(two_dialogs) == 2 and {k.tk for k in two_dialogs} == {TK, tpk(SN2, AN2)[1]}, "同一对站点两次建立（令牌不同、Nonce 不同）：两把密钥都留")
two = t.track({1: [response()], 2: [confirm()], 3: [response().replace(bytes([0x99]), bytes([0x98]), 1)]})
check(len(two) == 1, "第三条的链路标识被改了、MIC 对不上：不收")

print("== 直连帧解密 ==")
tk = keys[0]
dframe = frame(build("CCMP-128", TK, 5, b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + bytes(20), qos=0x0000, to_ds=0, from_ds=0, a1=A1))
# builder 的地址是 A1（可改）/ A2 / A3：令发起方 / 响应方 / BSSID 为 A2 / A1 / A3
key_for = t.TdlsKey(MACS(A2), MACS(A1), MACS(A3), KCK, TK, "CCMP-128", {})
got = t.decrypt_frame([key_for], dframe)
check(got is not None and got[1] == b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + bytes(20) and got[0] == key_for, "两个对端互发、A3 = BSSID：用 TPK-TK 解开")
check(t.decrypt_frame([key_for._replace(tk=bytes(16))], dframe) is None, "TK 不对：None")
check(t.decrypt_frame([key_for._replace(bssid=MACS(INIT))], dframe) is None, "A3 不是这条链路的 BSSID：不用这把密钥")
check(t.decrypt_frame([key_for._replace(responder=MACS(INIT))], dframe) is None, "地址对不上：None")
check(t.decrypt_frame([key_for._replace(initiator=MACS(A1), responder=MACS(A2))], dframe) is not None, "发起方 / 响应方互换也配得上（谁发给谁不限）")
check(t.decrypt_frame([], dframe) is None and t.decrypt_frame([key_for], dframe._replace(h=dict(dframe.h, protected=0))) is None and t.decrypt_frame([key_for], dframe._replace(h=dict(dframe.h, type=0))) is None, "没有密钥 / 未受保护 / 不是数据帧：None")
short = dframe._replace(body=dframe.body[:10])
check(t.decrypt_frame([key_for], short) is None, "帧体太短：None（不崩溃）")

print("\n结果: %s（%d 项失败）" % ("全部通过" if not failures else "存在失败", len(failures)))
sys.exit(0 if not failures else 1)
