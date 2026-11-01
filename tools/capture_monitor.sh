#!/usr/bin/env bash
# 监听模式抓包（Linux）：切监听模式、锁定信道和宽度、按时间滚动保存 pcap，退出时恢复网卡。
#
#   sudo bash tools/capture_monitor.sh -i wlan1 -c 44 --width 80 -d ./caps
#   bash tools/capture_monitor.sh -i wlan1 -c 44 --dry-run          只打印要执行的命令，不改任何东西
#
# 选项：
#   -i IFACE        网卡名（必须）；用 `iw dev` 查
#   -c CHANNEL      信道号（必须），例：6、44、149；先在 Mac 上用 system_profiler SPAirPortDataType 查路由器的信道
#   --width W       信道宽度：20、40+、40-、80（默认 80）；要和路由器一致，否则收不全
#   -d DIR          抓包文件目录（默认当前目录）
#   -r SECONDS      每隔多少秒换一个文件（默认 600）
#   --duration S    抓 S 秒后自动停止（默认一直抓，Ctrl-C 停止）
#   --dry-run       只打印命令
#
# 没有在真实网卡上跑过：命令格式对照 iw 6.7 的 `iw help` 和 NetworkManager 手册核对过，
# 退出时恢复网卡的流程用假命令测过（tests/test_capture_script.py）。第一次在真机上用，请留意输出。
# 只能抓自己的网络；抓下来的文件里有全部流量，不要提交到仓库。

set -u

IFACE=""
CHANNEL=""
WIDTH="80"
OUTDIR="."
ROTATE=600
DURATION=""
DRY=0

die() { echo "错误：$*" >&2; exit "${2:-2}"; }

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        -i) IFACE="${2:-}"; shift 2 || die "-i 后面要网卡名" ;;
        -c) CHANNEL="${2:-}"; shift 2 || die "-c 后面要信道号" ;;
        --width) WIDTH="${2:-}"; shift 2 || die "--width 后面要宽度" ;;
        -d) OUTDIR="${2:-}"; shift 2 || die "-d 后面要目录" ;;
        -r) ROTATE="${2:-}"; shift 2 || die "-r 后面要秒数" ;;
        --duration) DURATION="${2:-}"; shift 2 || die "--duration 后面要秒数" ;;
        --dry-run) DRY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "不认识的参数：$1（-h 看用法）" ;;
    esac
done

[ -n "$IFACE" ] || die "缺少 -i 网卡名（用 \`iw dev\` 查）"
[ -n "$CHANNEL" ] || die "缺少 -c 信道号"
case "$CHANNEL" in ''|*[!0-9]*) die "信道号要是数字：$CHANNEL" ;; esac
[ "$CHANNEL" -ge 1 ] && [ "$CHANNEL" -le 233 ] || die "信道号不在 1–233：$CHANNEL"
case "$IFACE" in *[!A-Za-z0-9_.-]*) die "网卡名里有不该有的字符：$IFACE" ;; esac
case "$ROTATE" in ''|*[!0-9]*|0) die "-r 要是大于 0 的整数秒：$ROTATE" ;; esac
if [ -n "$DURATION" ]; then
    case "$DURATION" in ''|*[!0-9]*|0) die "--duration 要是大于 0 的整数秒：$DURATION" ;; esac
fi
case "$WIDTH" in
    20) IW_WIDTH="HT20" ;;
    40+) IW_WIDTH="HT40+" ;;
    40-) IW_WIDTH="HT40-" ;;
    80) IW_WIDTH="80MHz" ;;
    *) die "--width 只能是 20、40+、40-、80：$WIDTH" ;;
esac

# 执行一条命令；--dry-run 只打印
run() {
    if [ "$DRY" = 1 ]; then
        echo "+ $*"
        return 0
    fi
    "$@"
}

if [ "$DRY" = 0 ]; then
    [ "$(id -u)" = 0 ] || die "要用 root 运行（sudo bash $0 ...）"
    for c in iw ip tcpdump; do
        command -v "$c" >/dev/null 2>&1 || die "没找到 $c（sudo apt install iw iproute2 tcpdump）"
    done
    iw dev "$IFACE" info >/dev/null 2>&1 || die "找不到网卡 $IFACE（\`iw dev\` 看看有哪些）"
fi

HAVE_NMCLI=0
command -v nmcli >/dev/null 2>&1 && HAVE_NMCLI=1
[ "$DRY" = 1 ] && HAVE_NMCLI=1          # 空跑时也列出这一步，方便看全流程

restore() {
    # 退出（含 Ctrl-C、出错）时一定走一遍，让网卡回到平时的样子；每一步失败都不影响后面的步骤
    echo "恢复网卡 $IFACE ..." >&2
    run ip link set "$IFACE" down
    run iw dev "$IFACE" set type managed
    run ip link set "$IFACE" up
    if [ "$HAVE_NMCLI" = 1 ]; then
        run nmcli device set "$IFACE" managed reset
    fi
}
trap restore EXIT
trap 'exit 130' INT TERM

echo "网卡 $IFACE，信道 $CHANNEL，宽度 $WIDTH，每 ${ROTATE} 秒换一个文件，保存到 $OUTDIR" >&2

# 1. 只让网络管理忽略这一张网卡（不停整个 NetworkManager，免得虚拟机自己断网）
if [ "$HAVE_NMCLI" = 1 ]; then
    run nmcli device set "$IFACE" managed no || echo "提示：nmcli 没能让 $IFACE 脱离管理，信道可能被改动" >&2
fi

# 2. 监听模式、锁信道和宽度
run ip link set "$IFACE" down || die "ip link down 失败" 3
run iw dev "$IFACE" set type monitor || die "切监听模式失败：网卡或驱动不支持，或被网络管理占用（见 docs/Linux抓包操作指引.md）" 3
run ip link set "$IFACE" up || die "ip link up 失败" 3
run iw dev "$IFACE" set channel "$CHANNEL" "$IW_WIDTH" || die "锁定信道 $CHANNEL ($WIDTH) 失败：网卡不支持这个信道或宽度，或被网络管理占用" 3

if [ "$DRY" = 0 ]; then
    info="$(iw dev "$IFACE" info 2>&1)"
    echo "$info" | grep -E "type|channel" >&2
    echo "$info" | grep -q "type monitor" || echo "警告：网卡没有处于监听模式" >&2
    echo "$info" | grep -q "channel $CHANNEL " || echo "警告：当前信道不是 $CHANNEL，请对照上面的输出" >&2
fi

# 3. 抓包，按时间滚动（文件名里的时间格式由 tcpdump 的 strftime 展开）
run mkdir -p "$OUTDIR" || die "建不了目录 $OUTDIR" 3
CAP=(tcpdump -i "$IFACE" -y IEEE802_11_RADIO -s 0 -B 16384 -n -G "$ROTATE" -w "$OUTDIR/cap-%Y%m%d-%H%M%S.pcap")
if [ -n "$DURATION" ]; then
    CAP=(timeout -s INT "$DURATION" "${CAP[@]}")
fi
echo "开始抓包（Ctrl-C 停止）。抓包期间，让要观察的设备把 WiFi 关掉再打开一次，才能抓到握手。" >&2
run "${CAP[@]}"
rc=$?
# timeout 到点会返回 124，这是正常结束
[ "$rc" = 124 ] && rc=0
if [ "$DRY" = 0 ]; then
    echo "抓包结束，文件在 $OUTDIR：" >&2
    ls -l "$OUTDIR"/cap-*.pcap 2>/dev/null >&2
    echo "下一步：python3 -m wifi80211.report 文件.pcap --keys 密钥文件" >&2
fi
exit "$rc"
