#include "gateway_platform.h"
#include "gateway_network.h"
#include "gateway_log.h"
#include "gateway_tests.h"
#include "paper_experiment.h"
#include "main.h"
#include "cmsis_os2.h"
#include "FreeRTOS.h"
#include "task.h"
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define GATEWAY_STACK_BYTES 8192U
#if GATEWAY_PAPER_CONTROL
#define DIAGNOSTIC_STACK_BYTES 4096U
#else
#define DIAGNOSTIC_STACK_BYTES 2048U
#endif
#ifndef GATEWAY_FAULT_INJECT
#define GATEWAY_FAULT_INJECT 0
#endif
extern UART_HandleTypeDef huart3;
static _Alignas(8) StackType_t gateway_stack[GATEWAY_STACK_BYTES / sizeof(StackType_t)];
static _Alignas(8) StackType_t diagnostic_stack[DIAGNOSTIC_STACK_BYTES / sizeof(StackType_t)];
static StaticTask_t gateway_tcb, diagnostic_tcb;
static StaticSemaphore_t log_mutex_cb;
static osThreadId_t gateway_task, diagnostic_task;
#if GATEWAY_PAPER_CONTROL
TaskHandle_t gateway_paper_core_task(void) { return (TaskHandle_t)gateway_task; }
TaskHandle_t gateway_paper_diagnostics_task(void) { return (TaskHandle_t)diagnostic_task; }
#endif
static osMutexId_t log_mutex;
static volatile uint32_t log_drops;
static volatile uint32_t tests_complete;
static GatewayTestStats completed_stats;
volatile GatewayFaultRecord gateway_fault_record;

void gateway_panic(GatewayFault reason)
{
    __disable_irq();
    gateway_fault_record.reason = (uint32_t)reason;
    gateway_fault_record.cfsr = SCB->CFSR;
    gateway_fault_record.hfsr = SCB->HFSR;
    gateway_fault_record.msp = __get_MSP();
    gateway_fault_record.psp = __get_PSP();
    /* No allocation, mutexes, UART waits, or dependence on the scheduler/tick. */
    __HAL_RCC_GPIOB_CLK_ENABLE();
    GPIOB->MODER = (GPIOB->MODER & ~(3UL << 28)) | (1UL << 28);
    GPIOB->BSRR = LD3_Pin;
    __DSB();
    for (;;) __NOP();
}
void gateway_assert_failed(const char *file, unsigned line)
{
    gateway_fault_record.file = file;
    gateway_fault_record.line = line;
    gateway_panic(GATEWAY_FAULT_ASSERT);
}
void vApplicationMallocFailedHook(void) { gateway_panic(GATEWAY_FAULT_ALLOC); }
void vApplicationStackOverflowHook(TaskHandle_t task, signed char *name)
{
    (void)name;
    gateway_fault_record.task = task;
    gateway_panic(GATEWAY_FAULT_STACK);
}
static void dropped(void)
{
    uint32_t mask = __get_PRIMASK();
    __disable_irq(); ++log_drops; __set_PRIMASK(mask);
}
int gateway_log_write(const char *text, size_t length)
{
    if (__get_IPSR() != 0U || !text) return -1;
    char line[512];
    size_t n = 0;
    if (length > 256U) { length = 256U; dropped(); }
    for (size_t i = 0; i < length; ++i) {
        if (text[i] == '\n' && (i == 0 || text[i - 1] != '\r')) line[n++] = '\r';
        line[n++] = text[i];
    }
    bool running = osKernelGetState() == osKernelRunning;
    if (running && (!log_mutex || osMutexAcquire(log_mutex, 100U) != osOK)) {
        dropped(); return -1;
    }
    HAL_StatusTypeDef status = HAL_UART_Transmit(&huart3, (uint8_t *)line, (uint16_t)n, 100U);
    if (running && osMutexRelease(log_mutex) != osOK) gateway_panic(GATEWAY_FAULT_ASSERT);
    if (status != HAL_OK) { dropped(); return -1; }
    return (int)length;
}
int gateway_log_binary(const void *bytes, size_t length)
{
    if (__get_IPSR() != 0U || !bytes || length > UINT16_MAX ||
        osKernelGetState() != osKernelRunning || !log_mutex ||
        osMutexAcquire(log_mutex, 1000U) != osOK) return -1;
    HAL_StatusTypeDef result = HAL_UART_Transmit(&huart3, (uint8_t *)bytes,
                                                  (uint16_t)length, 15000U);
    if (osMutexRelease(log_mutex) != osOK) gateway_panic(GATEWAY_FAULT_ASSERT);
    if (result != HAL_OK) { dropped(); return -1; }
    return (int)length;
}
void gateway_log(const char *format, ...)
{
    char line[256];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (n < 0) { dropped(); return; }
    if ((size_t)n >= sizeof(line)) dropped();
    (void)gateway_log_write(line, (size_t)n < sizeof(line) ? (size_t)n : sizeof(line) - 1U);
}
/* Override CubeIDE's weak, per-character syscall without editing generated syscalls.c.
 * Application code uses gateway_log() for complete-message serialization. */
int _write(int file, char *data, int length)
{
    (void)file;
    if (length < 0) { errno = EINVAL; return -1; }
    int sent = gateway_log_write(data, (size_t)length);
    if (sent < 0) errno = EIO;
    return sent;
}
void gateway_boot_report(void)
{
    gateway_log("\n[BOOT] policy_gate core validation; STM32F767ZI\n");
    gateway_log("[BOOT] SYSCLK=%lu HCLK=%lu UART3=%lu FreeRTOS=%s\n",
                (unsigned long)HAL_RCC_GetSysClockFreq(), (unsigned long)HAL_RCC_GetHCLKFreq(),
                (unsigned long)huart3.Init.BaudRate, tskKERNEL_VERSION_NUMBER);
    gateway_log("[BOOT] lab Bearer HTTP transport; no TLS\n");
}
void gateway_test_yield(void) { (void)osDelay(1U); }
static void run_core(void *argument)
{
    (void)argument;
#if GATEWAY_FAULT_INJECT == 1
    vApplicationMallocFailedHook();
#elif GATEWAY_FAULT_INJECT == 2
    vApplicationStackOverflowHook(xTaskGetCurrentTaskHandle(), NULL);
#endif
    GatewayTestStats stats = gateway_tests_run();
#if GATEWAY_PAPER_TIMING
    extern void gateway_paper_timing_run(void);
    if (stats.passed == stats.total) gateway_paper_timing_run();
#endif
    taskENTER_CRITICAL();
    completed_stats = stats;
    tests_complete = 1U;
    taskEXIT_CRITICAL();
    if (stats.passed != stats.total) HAL_GPIO_WritePin(LD3_GPIO_Port, LD3_Pin, GPIO_PIN_SET);
    if (stats.total && stats.passed == stats.total) gateway_network_run();
    /* Failure leaves the listener disabled and preserves diagnostics. */
    for (;;) (void)osThreadFlagsWait(1U, osFlagsWaitAny, osWaitForever);
}
static void run_diagnostics(void *argument)
{
    (void)argument;
    uint32_t next = osKernelGetTickCount();
    for (;;) {
        GatewayTestStats stats;
        uint32_t complete;
        taskENTER_CRITICAL(); stats = completed_stats; complete = tests_complete; taskEXIT_CRITICAL();
        uint32_t core_free = (uint32_t)uxTaskGetStackHighWaterMark((TaskHandle_t)gateway_task) * sizeof(StackType_t);
        uint32_t diag_free = (uint32_t)uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t);
        bool margin = core_free >= GATEWAY_STACK_BYTES / 4U && diag_free >= DIAGNOSTIC_STACK_BYTES / 4U;
        const char *state = !complete ? "RUNNING" : stats.total && stats.passed == stats.total ? "PASS" : "FAIL";
        gateway_log("[HEARTBEAT] %s %lu/%lu stack_free_bytes=%lu/%lu margin=%s heap_free=%lu heap_min=%lu log_drops=%lu\n",
                    state, (unsigned long)stats.passed, (unsigned long)stats.total,
                    (unsigned long)core_free, (unsigned long)diag_free, margin ? "OK" : "LOW",
                    (unsigned long)xPortGetFreeHeapSize(), (unsigned long)xPortGetMinimumEverFreeHeapSize(),
                    (unsigned long)log_drops);
        if (!margin) HAL_GPIO_WritePin(LD3_GPIO_Port, LD3_Pin, GPIO_PIN_SET);
        HAL_GPIO_TogglePin(LD1_GPIO_Port, LD1_Pin);
        gateway_network_diagnostics();
#if GATEWAY_PAPER_CONTROL
        extern void gateway_paper_control_diagnostics(void);
        gateway_paper_control_diagnostics();
#endif
        next += osKernelGetTickFreq();
        (void)osDelayUntil(next);
    }
}
void gateway_platform_start(void)
{
    if (osKernelGetState() != osKernelReady) gateway_panic(GATEWAY_FAULT_STARTUP);
    /* heap_4 initializes lazily. Exercise and release a minimal allocation so
     * its free/minimum counters are meaningful even with all-static tasks. */
    void *heap_probe = pvPortMalloc(1U);
    if (!heap_probe) gateway_panic(GATEWAY_FAULT_ALLOC);
    vPortFree(heap_probe);
    const osMutexAttr_t mutex_attr = {.name = "gateway_log", .attr_bits = osMutexPrioInherit,
        .cb_mem = &log_mutex_cb, .cb_size = sizeof(log_mutex_cb)};
    log_mutex = osMutexNew(&mutex_attr);
    if (!log_mutex) gateway_panic(GATEWAY_FAULT_STARTUP);
    /* CMSIS osThreadNew rejects the MPU privilege bit. These two trusted
     * startup/diagnostic tasks call HAL and privileged heap probes directly. */
    gateway_task = (osThreadId_t)xTaskCreateStatic(run_core, "gateway_core",
        GATEWAY_STACK_BYTES / sizeof(StackType_t), NULL,
        (UBaseType_t)osPriorityNormal | portPRIVILEGE_BIT, gateway_stack, &gateway_tcb);
    diagnostic_task = (osThreadId_t)xTaskCreateStatic(run_diagnostics, "gateway_diag",
        DIAGNOSTIC_STACK_BYTES / sizeof(StackType_t), NULL,
        (UBaseType_t)(GATEWAY_PAPER_CONTROL ? osPriorityAboveNormal : osPriorityLow) |
        portPRIVILEGE_BIT, diagnostic_stack, &diagnostic_tcb);
    if (!gateway_task || !diagnostic_task) gateway_panic(GATEWAY_FAULT_STARTUP);
#if GATEWAY_PAPER_CONTROL
    extern void gateway_paper_control_start(void);
    gateway_paper_control_start();
#endif
#if GATEWAY_R4_CONTROL
    extern void gateway_r4_control_start(void);
    gateway_r4_control_start();
#endif
}
