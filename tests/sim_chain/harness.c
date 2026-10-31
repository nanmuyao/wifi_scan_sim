/*
 * harness.c —— 在 PC 上跑真实的 stm32_project/Core/Src/main.c
 *
 * 做法：把 main.c 原样 #include 进来（main 改名为 fw_main），再实现一层 HAL 桩：
 *   - USART1 <-> argv[1] 指定的虚拟串口（esp8266_sim.py 的 pty slave 端）
 *   - USART2（调试输出）-> 标准输出，由 test_sim_chain.py 解析
 *   - 一个读线程扮演串口接收中断：每来 1 字节，若 Receive_IT 已挂起就调用
 *     固件的 HAL_UART_RxCpltCallback，没挂起则算一次溢出（overrun）
 *
 * 固件的接收回调、esp_wait、parse_cwlap 都是真实代码，没有重写。
 *
 * 编译（由 test_sim_chain.py 调用）：
 *   gcc -I tests/sim_chain/stub -I stm32_project/Core/Inc \
 *       -o harness tests/sim_chain/harness.c ap_parser.c -lpthread
 */
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "main.h"

#define SCAN_TARGET  3        /* 扫满这么多轮后正常退出 */
#define BYTE_US      87       /* 115200 8N1 约 87us/字节，模拟真实线速 */
#define WATCHDOG_S   20

#define main fw_main
#include "../../stm32_project/Core/Src/main.c"
#undef main

static int           serial_fd = -1;
static uint8_t      *rx_dst;               /* Receive_IT 挂起的目标地址 */
static _Atomic int   rx_armed;
static _Atomic long  overruns;
static volatile int  scans;

/* ---------- HAL 桩 ---------- */
int HAL_Init(void) { return 0; }

uint32_t HAL_GetTick(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

void HAL_Delay(uint32_t ms)
{
    if (scans >= SCAN_TARGET) {
        printf("HARNESS scans=%d overruns=%ld\n", scans, (long)overruns);
        fflush(stdout);
        exit(0);
    }
    usleep((ms > 20 ? 20 : ms) * 1000);   /* 压缩等待，不真的睡 10 秒 */
}

int HAL_UART_Init(UART_HandleTypeDef *huart) { (void)huart; return HAL_OK; }

int HAL_UART_Transmit(UART_HandleTypeDef *huart, uint8_t *data,
                      uint16_t len, uint32_t timeout)
{
    (void)timeout;
    if (huart == &huart1) {
        size_t off = 0;
        while (off < len) {
            ssize_t n = write(serial_fd, data + off, len - off);
            if (n <= 0) {
                perror("write serial");
                exit(3);
            }
            off += (size_t)n;
        }
    } else {
        char tmp[256];
        size_t n = len < sizeof(tmp) - 1 ? len : sizeof(tmp) - 1;
        memcpy(tmp, data, n);
        tmp[n] = '\0';
        if (strstr(tmp, "--- scan ---")) {
            scans++;
        }
        fwrite(data, 1, len, stdout);
        fflush(stdout);
    }
    return HAL_OK;
}

int HAL_UART_Receive_IT(UART_HandleTypeDef *huart, uint8_t *data, uint16_t len)
{
    (void)huart; (void)len;
    rx_dst = data;
    atomic_store(&rx_armed, 1);
    return HAL_OK;
}

/* ---------- 扮演串口接收中断 ---------- */
static void *rx_isr_thread(void *arg)
{
    (void)arg;
    uint8_t b;
    for (;;) {
        ssize_t n = read(serial_fd, &b, 1);
        if (n <= 0) {
            usleep(1000);
            continue;
        }
        if (atomic_exchange(&rx_armed, 0)) {
            *rx_dst = b;
            HAL_UART_RxCpltCallback(&huart1);   /* 回调内会重新挂起 */
        } else {
            atomic_fetch_add(&overruns, 1);     /* 没挂起 -> 真机上会丢字节 */
        }
        usleep(BYTE_US);
    }
    return NULL;
}

static void on_timeout(int sig)
{
    static const char msg[] = "HARNESS TIMEOUT\n";
    (void)sig;
    write(1, msg, sizeof(msg) - 1);
    _exit(2);
}

int main(int argc, char **argv)
{
    pthread_t th;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <serial-path>\n", argv[0]);
        return 64;
    }
    serial_fd = open(argv[1], O_RDWR | O_NOCTTY);
    if (serial_fd < 0) {
        perror("open serial");
        return 3;
    }
    signal(SIGALRM, on_timeout);
    alarm(WATCHDOG_S);
    pthread_create(&th, NULL, rx_isr_thread, NULL);
    fw_main();
    return 0;
}
