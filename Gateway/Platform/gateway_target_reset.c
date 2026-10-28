#include "gateway_target_reset.h"
#include "gateway_platform.h"
#include "gateway_log.h"
#include "main.h"
#include "cmsis_os2.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include <stdbool.h>
#include <string.h>

#define TRESET_PULSE_MS 100U
#define TRESET_HOLDOFF_MS 500U
#define TRESET_LINE_MAX 16U

extern UART_HandleTypeDef huart3;

static StackType_t treset_stack[512] __attribute__((section(".gateway_privileged")));
static StaticTask_t treset_tcb __attribute__((section(".gateway_privileged")));
static StaticQueue_t rx_queue_cb __attribute__((section(".gateway_privileged")));
static uint8_t rx_queue_storage[32] __attribute__((section(".gateway_privileged")));
static QueueHandle_t rx_queue __attribute__((section(".gateway_privileged")));
static uint8_t rx_byte __attribute__((section(".gateway_privileged")));
static volatile uint32_t rx_drops __attribute__((section(".gateway_privileged")));

static void rx_arm(void)
{
    (void)HAL_UART_Receive_IT(&huart3, &rx_byte, 1U);
}

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
    if (huart != &huart3) return;
    BaseType_t woken = pdFALSE;
    if (xQueueSendFromISR(rx_queue, &rx_byte, &woken) != pdPASS) rx_drops++;
    rx_arm();
    portYIELD_FROM_ISR(woken);
}

void HAL_UART_ErrorCallback(UART_HandleTypeDef *huart)
{
    /* HAL has already cleared ORE/FE/NE and aborted the reception. */
    if (huart == &huart3) rx_arm();
}

static void pulse(void)
{
    /* Open-drain: RESET sinks the line, SET only releases it (never drives high). */
    HAL_GPIO_WritePin(TGT_NRST_GPIO_Port, TGT_NRST_Pin, GPIO_PIN_RESET);
    (void)osDelay(TRESET_PULSE_MS);
    HAL_GPIO_WritePin(TGT_NRST_GPIO_Port, TGT_NRST_Pin, GPIO_PIN_SET);
}

static void run_target_reset(void *argument)
{
    (void)argument;
    char line[TRESET_LINE_MAX + 1U];
    size_t length = 0U;
    bool overlong = false;
    uint32_t last = osKernelGetTickCount() - TRESET_HOLDOFF_MS;
    rx_arm();
    for (;;) {
        uint8_t c;
        if (xQueueReceive(rx_queue, &c, portMAX_DELAY) != pdPASS) continue;
        if (c != '\r' && c != '\n') {
            if (length < TRESET_LINE_MAX) line[length++] = (char)c; else overlong = true;
            continue;
        }
        if (!length && !overlong) continue;
        line[length] = '\0';
        if (!overlong && !strcmp(line, "RESET")) {
            uint32_t now = osKernelGetTickCount();
            if (now - last < TRESET_HOLDOFF_MS) {
                gateway_log("[TRESET] busy\n");
            } else {
                pulse();
                last = osKernelGetTickCount();
                /* Drop bytes queued during the pulse; commands are not buffered. */
                (void)xQueueReset(rx_queue);
                gateway_log("[TRESET] pulse %lums\n", (unsigned long)TRESET_PULSE_MS);
            }
        } else if (!overlong && !strcmp(line, "STATUS")) {
            gateway_log("[TRESET] line=%s rx_drops=%lu\n",
                        HAL_GPIO_ReadPin(TGT_NRST_GPIO_Port, TGT_NRST_Pin) ? "released" : "low",
                        (unsigned long)rx_drops);
        } else {
            gateway_log("[TRESET] unknown command\n");
        }
        length = 0U;
        overlong = false;
    }
}

void gateway_target_reset_start(void)
{
    rx_queue = xQueueCreateStatic(sizeof(rx_queue_storage), 1U, rx_queue_storage, &rx_queue_cb);
    if (!rx_queue || !xTaskCreateStatic(run_target_reset, "gateway_treset",
            sizeof(treset_stack) / sizeof(StackType_t), NULL,
            (UBaseType_t)osPriorityLow | portPRIVILEGE_BIT, treset_stack, &treset_tcb))
        gateway_panic(GATEWAY_FAULT_STARTUP);
}
