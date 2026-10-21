#include "gateway_platform.h"
#include "gateway_d1_auth.h"
#include "gateway_d1_cleanup.h"
#include "gateway_network.h"
#include "gateway_log.h"
#include "gateway_tests.h"
#include "paper_experiment.h"
#include "main.h"
#include "cmsis_os2.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
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
static StackType_t gateway_stack[GATEWAY_STACK_BYTES / sizeof(StackType_t)] __attribute__((aligned(8192)));
static _Alignas(8) StackType_t diagnostic_stack[DIAGNOSTIC_STACK_BYTES / sizeof(StackType_t)] __attribute__((section(".gateway_privileged")));
static StaticTask_t gateway_tcb __attribute__((section(".gateway_privileged")));
static StaticTask_t diagnostic_tcb __attribute__((section(".gateway_privileged")));
static StaticSemaphore_t log_mutex_cb __attribute__((section(".gateway_privileged")));
typedef struct { uint16_t length; char bytes[512]; } LogMessage;
static StaticQueue_t log_queue_cb __attribute__((section(".gateway_privileged")));
static uint8_t log_queue_storage[4U*sizeof(LogMessage)] __attribute__((section(".gateway_privileged")));
static StackType_t log_stack[1024] __attribute__((section(".gateway_privileged"),aligned(4096)));
static StaticTask_t log_tcb __attribute__((section(".gateway_privileged")));
static StackType_t watchdog_stack[256] __attribute__((section(".gateway_privileged")));
static StaticTask_t watchdog_tcb __attribute__((section(".gateway_privileged")));
static QueueHandle_t log_queue __attribute__((section(".gateway_privileged")));
static QueueHandle_t unpriv_log_queue;
static osThreadId_t gateway_task, diagnostic_task;
void *gateway_platform_network_task_handle(void) { return (void *)gateway_task; }
#if GATEWAY_PAPER_CONTROL
TaskHandle_t gateway_paper_core_task(void) { return (TaskHandle_t)gateway_task; }
TaskHandle_t gateway_paper_diagnostics_task(void) { return (TaskHandle_t)diagnostic_task; }
#endif
static osMutexId_t log_mutex __attribute__((section(".gateway_privileged")));
void gateway_platform_grant_log_access(void *task)
{
    vGrantAccessToQueue((TaskHandle_t)task,log_queue);
}
static volatile uint32_t log_drops;
static volatile uint32_t tests_complete;
static GatewayTestStats completed_stats;
volatile GatewayFaultRecord gateway_fault_record;
typedef struct {
    uint32_t magic, reason, cfsr, hfsr, mmfar, task, psp, pc, checksum;
} GatewayResetRecord;
static volatile GatewayResetRecord reset_record
    __attribute__((section(".gateway_fault_noinit")));
volatile uint32_t gateway_d1_fault_was_reset;
#define GATEWAY_RESET_MAGIC 0xD1F017A5UL

static void watchdog_start(void)
{
    IWDG->KR=0x5555U;
    IWDG->PR=6U;       /* LSI/256; about eight seconds at nominal 32 kHz. */
    IWDG->RLR=1000U;
    IWDG->KR=0xAAAAU;
    IWDG->KR=0xCCCCU;
}
static void watchdog_feed(void) { IWDG->KR=0xAAAAU; }
static void watchdog_task(void *argument)
{
    (void)argument;
    for(;;) {
        watchdog_feed();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void gateway_panic(GatewayFault reason)
{
    __disable_irq();
    gateway_fault_record.reason = (uint32_t)reason;
    gateway_fault_record.cfsr = SCB->CFSR;
    gateway_fault_record.hfsr = SCB->HFSR;
    gateway_fault_record.msp = __get_MSP();
    gateway_fault_record.psp = __get_PSP();
    uint32_t psp=__get_PSP();
    uint32_t pc=0U;
    /* Exception frames from unprivileged tasks live on PSP. Fault handlers
     * call here before any stack switch; a basic frame has PC at word six. */
    if(psp>=0x20020000UL && psp<=0x2006ffe0UL) pc=((const uint32_t *)psp)[6];
    uint32_t mmfar=SCB->MMFAR;
    /* A fault handler cannot enter an MPU syscall/SVC. Read the kernel's
     * current TCB pointer directly while already privileged in handler mode. */
    extern void * volatile pxCurrentTCB;
    uint32_t task=(uint32_t)pxCurrentTCB;
    reset_record.magic=0U;
    reset_record.reason=(uint32_t)reason;
    reset_record.cfsr=SCB->CFSR;
    reset_record.hfsr=SCB->HFSR;
    reset_record.mmfar=mmfar;
    reset_record.task=task;
    reset_record.psp=psp;
    reset_record.pc=pc;
    reset_record.checksum=GATEWAY_RESET_MAGIC ^ reset_record.reason ^
        reset_record.cfsr ^ reset_record.hfsr ^ reset_record.mmfar ^
        reset_record.task ^ reset_record.psp ^ reset_record.pc;
    __DMB();
    reset_record.magic=GATEWAY_RESET_MAGIC;
    __DSB();
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
void vApplicationStackOverflowHook(TaskHandle_t task, char *name)
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
static void run_logger(void *argument)
{
    (void)argument;
    for(;;) {
        LogMessage message;
        if(xQueueReceive(log_queue,&message,portMAX_DELAY)!=pdPASS) continue;
        if(message.length>sizeof(message.bytes)) gateway_panic(GATEWAY_FAULT_ASSERT);
        if(osMutexAcquire(log_mutex,100U)!=osOK) { dropped(); continue; }
        if(HAL_UART_Transmit(&huart3,(uint8_t *)message.bytes,message.length,1000U)!=HAL_OK)
            dropped();
        (void)osMutexRelease(log_mutex);
    }
}
__attribute__((noinline)) static int enqueue_log(const char *line, size_t n)
{
    LogMessage message={.length=(uint16_t)n};
    memcpy(message.bytes,line,n);
    if(!unpriv_log_queue || xQueueSend(unpriv_log_queue,&message,pdMS_TO_TICKS(100))!=pdPASS) {
        dropped(); return -1;
    }
    return 0;
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
    if(running && (__get_CONTROL() & 1U)) {
        if(enqueue_log(line,n)!=0) return -1;
        return (int)length;
    }
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
    if ((__get_CONTROL() & 1U) || __get_IPSR() != 0U || !bytes || length > UINT16_MAX ||
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
    if(reset_record.magic==GATEWAY_RESET_MAGIC &&
       reset_record.checksum==(GATEWAY_RESET_MAGIC ^ reset_record.reason ^
       reset_record.cfsr ^ reset_record.hfsr ^ reset_record.mmfar ^
       reset_record.task ^ reset_record.psp ^ reset_record.pc)) {
        gateway_d1_fault_was_reset=1U;
        gateway_log("[RESET] previous_fault=%lu cfsr=0x%08lx mmfar=0x%08lx task=0x%08lx pc=0x%08lx\n",
            (unsigned long)reset_record.reason,(unsigned long)reset_record.cfsr,
            (unsigned long)reset_record.mmfar,(unsigned long)reset_record.task,
            (unsigned long)reset_record.pc);
    }
    reset_record.magic=0U;
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
#if GATEWAY_PAPER_GATE_N32
    extern void gateway_paper_gate_n32_run(void);
    if (stats.passed == stats.total) gateway_paper_gate_n32_run();
#endif
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
    watchdog_start();
    /* heap_4 initializes lazily. Exercise and release a minimal allocation so
     * its free/minimum counters are meaningful even with all-static tasks. */
    void *heap_probe = pvPortMalloc(1U);
    if (!heap_probe) gateway_panic(GATEWAY_FAULT_ALLOC);
    vPortFree(heap_probe);
    const osMutexAttr_t mutex_attr = {.name = "gateway_log", .attr_bits = osMutexPrioInherit,
        .cb_mem = &log_mutex_cb, .cb_size = sizeof(log_mutex_cb)};
    log_mutex = osMutexNew(&mutex_attr);
    if (!log_mutex) gateway_panic(GATEWAY_FAULT_STARTUP);
    log_queue=xQueueCreateStatic(4U,sizeof(LogMessage),log_queue_storage,&log_queue_cb);
    unpriv_log_queue=log_queue;
    if(!log_queue || !xTaskCreateStatic(run_logger,"gateway_log",1024U,NULL,
        (UBaseType_t)osPriorityLow|portPRIVILEGE_BIT,log_stack,&log_tcb))
        gateway_panic(GATEWAY_FAULT_STARTUP);
    if(!xTaskCreateStatic(watchdog_task,"gateway_watchdog",256U,NULL,
        (UBaseType_t)osPriorityHigh4|portPRIVILEGE_BIT,
        watchdog_stack,&watchdog_tcb)) gateway_panic(GATEWAY_FAULT_STARTUP);
    gateway_d1_auth_secrets_init();
    gateway_d1_auth_start();
    gateway_d1_cleanup_start();
    /* CMSIS osThreadNew rejects the MPU privilege bit. These two trusted
     * startup/diagnostic tasks call HAL and privileged heap probes directly. */
    const TaskParameters_t network_params = {
        .pvTaskCode=run_core, .pcName="gateway_core",
        .usStackDepth=GATEWAY_STACK_BYTES / sizeof(StackType_t),
        .pvParameters=NULL,
        .uxPriority=(UBaseType_t)osPriorityNormal | portPRIVILEGE_BIT,
        .puxStackBuffer=gateway_stack,
        .xRegions={
            {(void *)0x20000000UL,512U*1024U,
                portMPU_REGION_READ_WRITE|portMPU_REGION_EXECUTE_NEVER|
                /* The Ethernet input path copies DMA frames into lwIP pool
                 * buffers before NET sees them. Deny the whole DMA bank. */
                portMPU_REGION_CACHEABLE_BUFFERABLE|(0xE0UL<<8)},
            GATEWAY_ITCM_SHARED_REGION, /* drops privilege at runtime */
            {(void *)0x20020000UL,16U*1024U,
                portMPU_REGION_PRIVILEGED_READ_WRITE|portMPU_REGION_EXECUTE_NEVER|
                portMPU_REGION_CACHEABLE_BUFFERABLE}},
        .pxTaskBuffer=&gateway_tcb};
    TaskHandle_t network_task=NULL;
    if(xTaskCreateRestrictedStatic(&network_params,&network_task)!=pdPASS)
        gateway_panic(GATEWAY_FAULT_STARTUP);
    gateway_task=(osThreadId_t)network_task;
    diagnostic_task = (osThreadId_t)xTaskCreateStatic(run_diagnostics, "gateway_diag",
        DIAGNOSTIC_STACK_BYTES / sizeof(StackType_t), NULL,
        (UBaseType_t)(GATEWAY_PAPER_CONTROL ? osPriorityAboveNormal : osPriorityLow) |
        portPRIVILEGE_BIT, diagnostic_stack, &diagnostic_tcb);
    if (!gateway_task || !diagnostic_task) gateway_panic(GATEWAY_FAULT_STARTUP);
    extern void gateway_target_reset_start(void);
    gateway_target_reset_start();
#if GATEWAY_PAPER_CONTROL
    extern void gateway_paper_control_start(void);
    gateway_paper_control_start();
#endif
#if GATEWAY_R4_CONTROL
    extern void gateway_r4_control_start(void);
    gateway_r4_control_start();
#endif
}
