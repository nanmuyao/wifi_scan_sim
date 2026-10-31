/*
 * main.h —— 仅用于 PC 仿真的 HAL 桩头文件（真实工程里这个文件由 CubeMX 生成）
 *
 * 只声明 stm32_project/Core/Src/main.c 用到的 HAL 类型与函数，
 * 实现在 harness.c 里：把 UART1 接到 esp8266_sim.py 的虚拟串口。
 */
#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>

typedef struct {
    void *Instance;
    struct {
        uint32_t BaudRate, WordLength, StopBits, Parity;
        uint32_t Mode, HwFlowCtl, OverSampling;
    } Init;
} UART_HandleTypeDef;

#define USART1 ((void *)1)
#define USART2 ((void *)2)

#define UART_WORDLENGTH_8B   0
#define UART_STOPBITS_1      0
#define UART_PARITY_NONE     0
#define UART_MODE_TX_RX      0
#define UART_HWCONTROL_NONE  0
#define UART_OVERSAMPLING_16 0
#define HAL_OK               0

int      HAL_Init(void);
uint32_t HAL_GetTick(void);
void     HAL_Delay(uint32_t ms);
int      HAL_UART_Init(UART_HandleTypeDef *huart);
int      HAL_UART_Transmit(UART_HandleTypeDef *huart, uint8_t *data,
                           uint16_t len, uint32_t timeout);
int      HAL_UART_Receive_IT(UART_HandleTypeDef *huart, uint8_t *data,
                             uint16_t len);

void SystemClock_Config(void);
void MX_GPIO_Init(void);
void MX_USART1_UART_Init(void);
void MX_USART2_UART_Init(void);
void Error_Handler(void);

#endif /* MAIN_H */
