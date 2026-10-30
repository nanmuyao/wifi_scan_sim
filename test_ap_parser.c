/*
 * test_ap_parser.c —— PC 端单元测试（gcc 编译，无需任何嵌入式依赖）
 *
 * 编译运行：
 *   gcc -o test_ap_parser test_ap_parser.c ap_parser.c
 *   ./test_ap_parser
 *
 * 覆盖场景：
 *   1. 正常多 AP（含 2.4G 与 5G 信道）
 *   2. 隐藏 SSID（空引号）
 *   3. SSID 内含逗号 / 引号（转义后的真实格式）
 *   4. 无 AP（只有 OK）
 *   5. 干扰行（其它 AT 输出混入）
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "ap_parser.h"

#define MAX_AP 32

static int failures = 0;

static void check(int cond, const char *msg)
{
    if (!cond) {
        printf("  [FAIL] %s\n", msg);
        failures++;
    } else {
        printf("  [PASS] %s\n", msg);
    }
}

int main(void)
{
    ap_info_t aps[MAX_AP];
    int n;

    printf("== test 1: 正常多 AP（2.4G + 5G 混合） ==\n");
    const char *resp1 =
        "+CWLAP:(3,\"Paul-Home-2.4G\",-38,\"a4:83:e7:11:22:02\",6)\r\n"
        "+CWLAP:(3,\"Paul-Home-5G\",-42,\"a4:83:e7:11:22:01\",149)\r\n"
        "+CWLAP:(4,\"TP-LINK_5G\",-66,\"6c:e8:73:12:34:56\",157)\r\n"
        "OK\r\n";
    n = parse_cwlap(resp1, aps, MAX_AP);
    check(n == 3, "解析出 3 个 AP");
    if (n == 3) {
        check(aps[0].channel == 6  && aps[0].rssi == -38, "AP0 ch=6 rssi=-38");
        check(strcmp(aps[0].ssid, "Paul-Home-2.4G") == 0, "AP0 SSID 正确");
        check(aps[1].channel == 149, "AP1 为 5G 信道 149");
        check(strcmp(aps[2].mac, "6c:e8:73:12:34:56") == 0, "AP2 MAC 正确");
    }

    printf("== test 2: 隐藏 SSID ==\n");
    const char *resp2 =
        "+CWLAP:(0,\"\",-70,\"e8:28:ca:77:88:99\",3)\r\nOK\r\n";
    n = parse_cwlap(resp2, aps, MAX_AP);
    check(n == 1, "解析出 1 个 AP");
    if (n == 1) {
        check(aps[0].ssid[0] == '\0', "隐藏 SSID 为空串");
        check(aps[0].enc == 0, "开放网络 enc=0");
    }

    printf("== test 3: SSID 内含转义逗号/引号（真实固件用 \\ 转义） ==\n");
    /* 文本行实际为: +CWLAP:(4,"AP\,with\"quote",-55,"00:11:22:33:44:55",1) */
    const char *resp3 =
        "+CWLAP:(4,\"AP\\,with\\\"quote\",-55,\"00:11:22:33:44:55\",1)\r\nOK\r\n";
    n = parse_cwlap(resp3, aps, MAX_AP);
    check(n == 1, "转义 SSID 行解析出 1 个");
    if (n == 1) {
        check(strcmp(aps[0].ssid, "AP,with\"quote") == 0,
              "转义已还原为 AP,with\"quote");
        check(aps[0].rssi == -55 && aps[0].channel == 1, "RSSI/信道正确");
    }

    printf("== test 4: 无 AP（只有 OK） ==\n");
    n = parse_cwlap("OK\r\n", aps, MAX_AP);
    check(n == 0, "无 AP 返回 0");

    printf("== test 5: 混入其它 AT 输出 ==\n");
    const char *resp5 =
        "AT+CWLAP\r\n"
        "+CWLAP:(2,\"Office_WPA\",-61,\"00:1f:33:44:55:66\",11)\r\n"
        "WIFI CONNECTED\r\n"
        "+CWLAP:(4,\"iPhone-13\",-55,\"3c:06:30:ab:cd:ef\",1)\r\n"
        "OK\r\n";
    n = parse_cwlap(resp5, aps, MAX_AP);
    check(n == 2, "干扰行不影响解析，得到 2 个 AP");

    printf("== test 6: 空指针/非法参数 ==\n");
    check(parse_cwlap(NULL, aps, MAX_AP) == 0, "NULL 输入安全返回 0");
    check(parse_cwlap("+CWLAP:(3,\"x\",-1,\"aa:bb:cc:dd:ee:ff\",1)\r\nOK\r\n",
                      NULL, MAX_AP) == 0, "NULL 输出安全返回 0");

    printf("\n结果: %s（%d 项失败）\n",
           failures == 0 ? "全部通过" : "存在失败", failures);
    return failures == 0 ? 0 : 1;
}
