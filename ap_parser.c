/*
 * ap_parser.c —— 纯 C 的 CWLAP 解析库（无 HAL 依赖，PC 可直接编译测试）
 *
 * 设计说明：
 *   这是 STM32 工程里的核心解析逻辑，刻意与硬件解耦：
 *     - 输入：ESP8266 返回的完整 CWLAP 响应文本（含多个 +CWLAP 行）
 *     - 输出：解析后的 AP 结构体数组
 *   在 STM32 上使用时，只需把 UART 收到的字节填进 buf 即可复用本文件。
 *
 * 实现要点（对应真实固件的三个坑）：
 *   1. 空 SSID：+CWLAP:(0,"",-70,...) —— sscanf 的 %[^"] 无法匹配空串，必须手写解析
 *   2. 转义字符：SSID 内逗号/引号输出为 \, 和 \" —— 需去转义还原
 *   3. strncpy 不保证 NUL 结尾 —— 拷贝后必须显式补 '\0'
 *
 * PC 测试：
 *   gcc -o test_ap_parser test_ap_parser.c ap_parser.c
 *   ./test_ap_parser
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ap_parser.h"

static const char *skip_spaces(const char *p)
{
    while (*p == ' ' || *p == '\t') {
        p++;
    }
    return p;
}

/* 解析单行 +CWLAP 格式（含转义处理），成功返回 1 */
static int parse_cwlap_line(const char *line, ap_info_t *ap)
{
    const char *p;
    int enc = 0, rssi = 0, ch = 0;
    char ssid[33];
    char mac[18];
    int ssid_len = 0, mac_len = 0;

    if (strncmp(line, "+CWLAP:", 7) != 0) {
        return 0;
    }
    p = line + 7;
    p = skip_spaces(p);
    if (*p != '(') {
        return 0;
    }
    p++;

    /* 1. 加密方式 */
    if (sscanf(p, "%d", &enc) != 1) {
        return 0;
    }
    while (*p != '\0' && *p != ',') p++;
    if (*p == ',') p++;

    /* 2. SSID：支持空串与转义（\, \"） */
    p = skip_spaces(p);
    if (*p != '"') {
        return 0;
    }
    p++;
    while (*p != '\0' && *p != '"' && ssid_len < 32) {
        if (*p == '\\' && (p[1] == '"' || p[1] == ',')) {
            ssid[ssid_len++] = p[1];
            p += 2;
            continue;
        }
        ssid[ssid_len++] = *p++;
    }
    if (*p != '"') {
        return 0;
    }
    ssid[ssid_len] = '\0';
    p++;
    if (*p == ',') p++;

    /* 3. RSSI */
    if (sscanf(p, "%d", &rssi) != 1) {
        return 0;
    }
    while (*p != '\0' && *p != ',') p++;
    if (*p == ',') p++;

    /* 4. MAC */
    p = skip_spaces(p);
    if (*p != '"') {
        return 0;
    }
    p++;
    while (*p != '\0' && *p != '"' && mac_len < 17) {
        mac[mac_len++] = *p++;
    }
    if (*p != '"') {
        return 0;
    }
    mac[mac_len] = '\0';
    p++;
    if (*p == ',') p++;

    /* 5. 信道 */
    if (sscanf(p, "%d", &ch) != 1) {
        return 0;
    }

    ap->enc     = (uint8_t)enc;
    ap->rssi    = (int8_t)rssi;
    ap->channel = (uint8_t)ch;
    strncpy(ap->ssid, ssid, 32);
    ap->ssid[32] = '\0';   /* strncpy 不保证 NUL 结尾，必须显式补 */
    strncpy(ap->mac, mac, 17);
    ap->mac[17] = '\0';
    return 1;
}

/* 解析整段 CWLAP 响应，返回解析到的 AP 数量 */
int parse_cwlap(const char *buf, ap_info_t *aps, int max_aps)
{
    int count = 0;
    const char *p = buf;
    const char *line_start = buf;

    if (!buf || !aps || max_aps <= 0) {
        return 0;
    }

    while (*p != '\0' && count < max_aps) {
        /* 找行尾 */
        while (*p != '\0' && *p != '\n' && *p != '\r') {
            p++;
        }

        /* 提取一行（不含换行符） */
        size_t len = (size_t)(p - line_start);
        char line[512];
        if (len >= sizeof(line)) {
            len = sizeof(line) - 1;
        }
        memcpy(line, line_start, len);
        line[len] = '\0';

        if (parse_cwlap_line(line, &aps[count])) {
            count++;
        }

        /* 跳过换行符 */
        while (*p == '\n' || *p == '\r') {
            p++;
        }
        line_start = p;
    }

    return count;
}

/* buf 末尾是否为独立成行的 tok（前一字符是换行或缓冲起点） */
static int ends_with_token(const char *buf, int len, const char *tok)
{
    int tl = (int)strlen(tok);
    if (len < tl || memcmp(buf + len - tl, tok, (size_t)tl) != 0) {
        return 0;
    }
    return len == tl || buf[len - tl - 1] == '\n';
}

/* 判断 AT 响应是否收完。响应字节连续到达，不能靠"换行前有空闲间隔"判尾，
 * 而要看终止行：OK / ERROR / FAIL。 */
int at_response_complete(const char *buf, int len)
{
    if (!buf || len <= 0 || buf[len - 1] != '\n') {
        return 0;
    }
    while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n')) {
        len--;
    }
    return ends_with_token(buf, len, "OK") ||
           ends_with_token(buf, len, "ERROR") ||
           ends_with_token(buf, len, "FAIL");
}

/* 格式化打印一个 AP（STM32 侧可换成 HAL_UART_Transmit 输出） */
void ap_print(const ap_info_t *ap)
{
    const char *enc_names[] = {"OPEN", "WEP", "WPA", "WPA2", "WPA/WPA2"};
    const char *enc = (ap->enc <= 4) ? enc_names[ap->enc] : "UNKNOWN";
    printf("[ch=%-3d rssi=%-4d %-10s] %-16s %s\n",
           ap->channel, ap->rssi, enc,
           ap->ssid[0] ? ap->ssid : "<hidden>", ap->mac);
}
