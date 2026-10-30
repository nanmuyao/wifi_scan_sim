/*
 * ap_parser.h —— CWLAP 解析库头文件
 */
#ifndef AP_PARSER_H
#define AP_PARSER_H

#include <stdint.h>

typedef struct {
    uint8_t  enc;      /* 加密方式: 0=开放 1=WEP 2=WPA 3=WPA2 4=WPA/WPA2 */
    char     ssid[33]; /* SSID，空串表示隐藏网络 */
    int8_t   rssi;     /* 信号强度 dBm */
    char     mac[18];  /* BSSID "aa:bb:cc:dd:ee:ff" */
    uint8_t  channel;  /* 信道 1-13(2.4G) / 36-165(5G) */
} ap_info_t;

/* 解析整段 CWLAP 响应，返回解析到的 AP 数量 */
int parse_cwlap(const char *buf, ap_info_t *aps, int max_aps);

/* 格式化打印一个 AP */
void ap_print(const ap_info_t *ap);

#endif /* AP_PARSER_H */
