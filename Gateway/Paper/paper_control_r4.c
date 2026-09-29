/* Timer-released R4 control observer. The exact 10,000 release-to-run samples
 * are sent as one binary UART record, then retained by the host collector. */
#include "paper_experiment.h"
#if GATEWAY_R4_CONTROL
#include "gateway_log.h"
#include "gateway_platform.h"
#include "main.h"
#include "FreeRTOS.h"
#include "task.h"
#include "cmsis_os2.h"
#include <stdint.h>

#if GATEWAY_R4_CONTROL_HZ != 1000 && GATEWAY_R4_CONTROL_HZ != 4000 && GATEWAY_R4_CONTROL_HZ != 10000
#error R4 control frequency must be 1, 4 or 10 kHz
#endif
#define R4_SAMPLES 10000U
#define R4_STACK_WORDS 1024U
static StackType_t control_stack[R4_STACK_WORDS] __attribute__((aligned(4096)));
static StaticTask_t control_tcb;
static TaskHandle_t control_handle;
static volatile uint32_t release_count;
static volatile uint32_t release_cycles[R4_SAMPLES];
static TaskStatus_t runtime_before[16], runtime_after[16];
static UBaseType_t runtime_before_count;
static uint32_t runtime_before_total;
extern void gateway_r4_critical_reset(void);
extern uint32_t gateway_r4_critical_max(void);
static struct {
    uint8_t magic[4];
    uint16_t hz;
    uint8_t high;
    uint8_t reserved;
    uint32_t cycles[R4_SAMPLES];
} capture;

void gateway_runtime_init(void)
{
    CoreDebug->DEMCR|=CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT=0U;
    DWT->CTRL|=DWT_CTRL_CYCCNTENA_Msk;
}
uint32_t gateway_runtime_counter(void) { return DWT->CYCCNT; }

void TIM7_IRQHandler(void)
{
    if((TIM7->SR & TIM_SR_UIF)==0U) return;
    TIM7->SR=0U;
    uint32_t n=release_count;
    if(n<R4_SAMPLES) {
        release_cycles[n]=DWT->CYCCNT;
        release_count=n+1U;
        BaseType_t wake=pdFALSE;
        vTaskNotifyGiveFromISR(control_handle,&wake);
        portYIELD_FROM_ISR(wake);
    }
    if(n+1U>=R4_SAMPLES) {
        TIM7->DIER=0U;
        TIM7->CR1=0U;
    }
}

static void control_task(void *unused)
{
    (void)unused;
    capture.magic[0]='P';capture.magic[1]='G';
    capture.magic[2]='C';capture.magic[3]='1';
    capture.hz=GATEWAY_R4_CONTROL_HZ;
    capture.high=GATEWAY_R4_CONTROL_HIGH;
    /* The network listener and host load are active by the start of this window. */
    vTaskDelay(pdMS_TO_TICKS(3000));
    __HAL_RCC_TIM7_CLK_ENABLE();
    uint32_t bus=HAL_RCC_GetPCLK1Freq();
    uint32_t ppre=(RCC->CFGR & RCC_CFGR_PPRE1)>>RCC_CFGR_PPRE1_Pos;
    uint32_t timer_clock=ppre>=4U ? bus*2U : bus;
    uint32_t period_cycles=HAL_RCC_GetHCLKFreq()/GATEWAY_R4_CONTROL_HZ;
    TIM7->CR1=0U;
    TIM7->PSC=timer_clock/1000000U-1U;
    TIM7->ARR=1000000U/GATEWAY_R4_CONTROL_HZ-1U;
    TIM7->EGR=TIM_EGR_UG;
    TIM7->SR=0U;
    TIM7->DIER=TIM_DIER_UIE;
    NVIC_SetPriority(TIM7_IRQn,configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY);
    NVIC_EnableIRQ(TIM7_IRQn);
    runtime_before_count=uxTaskGetSystemState(runtime_before,16U,&runtime_before_total);
    gateway_log("[CTRL R4] START hz=%u high=%u\n",
                GATEWAY_R4_CONTROL_HZ,GATEWAY_R4_CONTROL_HIGH);
    gateway_r4_critical_reset();
    TIM7->CR1=TIM_CR1_CEN;
    uint32_t processed=0U, misses=0U, max_cycles=0U;
    while(processed<R4_SAMPLES) {
        (void)ulTaskNotifyTake(pdTRUE,portMAX_DELAY);
        uint32_t available=release_count;
        while(processed<available) {
            uint32_t now=DWT->CYCCNT;
            uint32_t late=now-release_cycles[processed];
            capture.cycles[processed]=late;
            if(late>=period_cycles) ++misses;
            if(late>max_cycles) max_cycles=late;
            ++processed;
        }
    }
    gateway_log("[CTRL R4] hz=%u high=%u samples=%lu misses=%lu max_cycles=%lu critical_max_cycles=%lu stack_free=%lu\n",
                GATEWAY_R4_CONTROL_HZ,GATEWAY_R4_CONTROL_HIGH,
                (unsigned long)processed,(unsigned long)misses,(unsigned long)max_cycles,
                (unsigned long)gateway_r4_critical_max(),
                (unsigned long)uxTaskGetStackHighWaterMark(NULL)*sizeof(StackType_t));
    /* This observer suspends scheduling and scans stacks, so run it only after
     * the 10,000-sample deadline window has closed, but before the long UART
     * transfer used to export the exact samples. */
    uint32_t total=0U;
    UBaseType_t tasks=uxTaskGetSystemState(runtime_after,16U,&total);
    if(gateway_log_binary(&capture,sizeof(capture))!=(int)sizeof(capture))
        gateway_panic(GATEWAY_FAULT_ASSERT);
    gateway_log("[RUNTIME R4] total_cycles=%lu tasks=%lu\n",
                (unsigned long)(total-runtime_before_total),(unsigned long)tasks);
    for(UBaseType_t i=0;i<tasks;++i) {
        uint32_t before=0U;
        for(UBaseType_t j=0;j<runtime_before_count;++j)
            if(runtime_before[j].xHandle==runtime_after[i].xHandle) {
                before=runtime_before[j].ulRunTimeCounter;
                break;
            }
        gateway_log("[RUNTIME R4] task=%s cycles=%lu\n",runtime_after[i].pcTaskName,
                    (unsigned long)(runtime_after[i].ulRunTimeCounter-before));
    }
    gateway_log("[RUNTIME R4] end\n");
    for(;;) vTaskDelay(portMAX_DELAY);
}

void gateway_r4_control_start(void)
{
    control_handle=xTaskCreateStatic(control_task,"r4_control",R4_STACK_WORDS,NULL,
        (UBaseType_t)(GATEWAY_R4_CONTROL_HIGH ? osPriorityHigh : osPriorityNormal) |
        portPRIVILEGE_BIT,control_stack,&control_tcb);
    if(!control_handle) gateway_panic(GATEWAY_FAULT_STARTUP);
}
#endif
