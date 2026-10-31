/**
 * main.c —— STM32F103 + ESP8266 WiFi 扫描（修正版）
 *
 * 说明：
 *   1. 使用 ap_parser.c/h 解析 CWLAP（纯 C，无 HAL 依赖），与本仓库 PC 仿真
 *      验证的是同一份解析逻辑；
 *   2. 修正历史隐患：
 *      a) 逐字节接收缓冲 rx_byte 为文件级变量，main 启动与回调重挂共用一个，
 *         不再覆写 wifi_buf[0]，也不会丢首字节；
 *      b) 每收一字节在缓冲末尾显式补 '\0'，避免 strtok 越界/脏读；
 *      c) 判帧结束改为看终止行（OK/ERROR/FAIL，at_response_complete），
 *         不再依赖"换行前有 20ms 空闲"——连续到达的响应永远满足不了该条件。
 *
 * 接线：
 *   ESP8266 TX  -> PA10 (USART1_RX)
 *   ESP8266 RX  -> PA9  (USART1_TX)
 *   ESP8266 VCC -> 3.3V（建议独立供电，峰值电流 300mA+）
 *   ESP8266 GND -> GND
 *   ESP8266 CH_PD -> 3.3V（使能）
 *   调试输出：USART2（PA2/PA3）115200，接 USB-TTL 到 PC
 *
 * CubeMX 配置（见 wifi_scan_sim.ioc）：
 *   RCC: HSE 8MHz Crystal；SYS: Serial Wire（SWD）
 *   USART1: 115200 8N1，PA9/PA10，开全局中断
 *   USART2: 115200 8N1，PA2/PA3
 *   Clock: HCLK = 72MHz（PLL）
 */
#include "main.h"
#include <stdio.h>
#include <string.h>
#include "ap_parser.h"

UART_HandleTypeDef huart1;
UART_HandleTypeDef huart2;

#ifndef MAX_AP_T
#define MAX_AP_T 16           /* 单次扫描最多保存的 AP 数 */
#endif

/* ---------- ESP8266 串口接收（中断逐字节） ---------- */
#define WIFI_BUF_MAX  4096
uint8_t  wifi_buf[WIFI_BUF_MAX];
volatile uint16_t wifi_len = 0;
volatile uint8_t  wifi_done = 0;
static uint8_t rx_byte;       /* 逐字节接收缓冲：main 启动与回调重挂用同一个变量 */

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
    if (huart->Instance == USART1) {
        if (wifi_len < WIFI_BUF_MAX - 1) {
            wifi_buf[wifi_len++] = rx_byte;
            wifi_buf[wifi_len] = '\0';   /* 实时保持 NUL 结尾 */

            /* 判尾：收到换行，且缓冲末尾是独立成行的 OK / ERROR / FAIL */
            if (rx_byte == '\n' &&
                at_response_complete((const char *)wifi_buf, wifi_len)) {
                wifi_done = 1;
            }
        }
        HAL_UART_Receive_IT(&huart1, &rx_byte, 1);
    }
}

/* ---------- AT 指令发送 ---------- */
void esp_send(const char *cmd)
{
    HAL_UART_Transmit(&huart1, (uint8_t *)cmd, strlen(cmd), 100);
}

/* 发送指令并等待返回：响应以 OK 行收尾返回 1；ERROR / FAIL 收尾或超时返回 0。
 * 不能用 strstr(buf, "OK") 判成功——一个叫 "OK-Cafe" 的 AP 会让 FAIL 响应也含 "OK" */
int esp_wait(const char *cmd, uint32_t timeout_ms)
{
    wifi_len = 0;
    wifi_done = 0;
    esp_send(cmd);

    uint32_t start = HAL_GetTick();
    while (HAL_GetTick() - start < timeout_ms) {
        if (wifi_done) {
            wifi_done = 0;
            return at_response_ok((const char *)wifi_buf, wifi_len);
        }
    }
    return 0;
}

/* ---------- 打印结果到调试串口（USART2） ----------
 * 格式与 tools/serial_wifi_plot.py 解析器对齐：
 * [i] ch=<ch> rssi=<rssi> enc=<enc> ssid=<ssid>
 */
void print_aps(const ap_info_t *aps, int count)
{
    char line[96];
    for (int i = 0; i < count; i++) {
        snprintf(line, sizeof(line),
                 "[%02d] ch=%-2d rssi=%-4d enc=%d ssid=%s\r\n",
                 i, aps[i].channel, aps[i].rssi, aps[i].enc, aps[i].ssid);
        HAL_UART_Transmit(&huart2, (uint8_t *)line, strlen(line), 100);
    }
}

/* ---------- 主流程 ---------- */
int main(void)
{
    HAL_Init();
    SystemClock_Config();     /* CubeMX 生成 */
    MX_GPIO_Init();
    MX_USART1_UART_Init();    /* 115200, ESP8266 */
    MX_USART2_UART_Init();    /* 115200, 调试输出 */

    HAL_UART_Receive_IT(&huart1, &rx_byte, 1);   /* 首次启动中断接收 */

    /* 1. 基础握手 */
    while (!esp_wait("AT\r\n", 2000)) {
        HAL_Delay(500);
    }
    esp_wait("AT+CWMODE=1\r\n", 1000);   /* Station 模式 */

    ap_info_t aps[MAX_AP_T];
    uint8_t ap_count = 0;

    while (1) {
        HAL_UART_Transmit(&huart2, (uint8_t *)"\r\n--- scan ---\r\n", 15, 100);
        if (esp_wait("AT+CWLAP\r\n", 5000)) {
            ap_count = (uint8_t)parse_cwlap((const char *)wifi_buf, aps, MAX_AP_T);
            print_aps(aps, ap_count);
        } else {
            HAL_UART_Transmit(&huart2, (uint8_t *)"scan timeout\r\n", 14, 100);
        }
        HAL_Delay(10000);     /* 每 10 秒扫一次 */
    }
}

/* ---------- 以下由 CubeMX 生成的骨架（占位，实际以 .ioc 生成内容为准） ---------- */
void SystemClock_Config(void)
{
    /* 8MHz HSE -> PLL x9 -> 72MHz HCLK */
}

void MX_GPIO_Init(void)
{
    /* 由 CubeMX 生成：SWD 引脚保持 */
}

void MX_USART1_UART_Init(void)
{
    huart1.Instance = USART1;
    huart1.Init.BaudRate = 115200;
    huart1.Init.WordLength = UART_WORDLENGTH_8B;
    huart1.Init.StopBits = UART_STOPBITS_1;
    huart1.Init.Parity = UART_PARITY_NONE;
    huart1.Init.Mode = UART_MODE_TX_RX;
    huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart1.Init.OverSampling = UART_OVERSAMPLING_16;
    if (HAL_UART_Init(&huart1) != HAL_OK) {
        Error_Handler();
    }
}

void MX_USART2_UART_Init(void)
{
    huart2.Instance = USART2;
    huart2.Init.BaudRate = 115200;
    huart2.Init.WordLength = UART_WORDLENGTH_8B;
    huart2.Init.StopBits = UART_STOPBITS_1;
    huart2.Init.Parity = UART_PARITY_NONE;
    huart2.Init.Mode = UART_MODE_TX_RX;
    huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart2.Init.OverSampling = UART_OVERSAMPLING_16;
    if (HAL_UART_Init(&huart2) != HAL_OK) {
        Error_Handler();
    }
}

void Error_Handler(void)
{
    while (1) {
    }
}
