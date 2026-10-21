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
static StackType_t control_stack[R4_STACK_WORDS]
    __attribute__((section(".gateway_rt.stack"),aligned(4096)));
static StaticTask_t control_tcb __attribute__((section(".gateway_privileged")));
static TaskHandle_t control_handle __attribute__((section(".gateway_privileged")));
static volatile uint32_t release_count __attribute__((section(".gateway_privileged")));
static volatile uint32_t isr_max_cycles __attribute__((section(".gateway_privileged")));
static volatile uint32_t release_lost __attribute__((section(".gateway_privileged")));
static volatile uint32_t release_gap_anomalies __attribute__((section(".gateway_privileged")));
static volatile uint32_t last_release_cycles __attribute__((section(".gateway_privileged")));
static volatile uint32_t timer_period_cycles __attribute__((section(".gateway_privileged")));
static volatile uint32_t core_cycles_per_us __attribute__((section(".gateway_privileged")));
static TaskStatus_t runtime_before[16] __attribute__((section(".gateway_privileged")));
static TaskStatus_t runtime_after[16] __attribute__((section(".gateway_privileged")));
static UBaseType_t runtime_before_count __attribute__((section(".gateway_privileged")));
static uint32_t runtime_before_total __attribute__((section(".gateway_privileged")));
extern void gateway_r4_critical_reset(void);
extern uint32_t gateway_r4_critical_max(void);
extern uint32_t gateway_r4_critical_anomalies(void);
extern void gateway_r4_critical_window(uint32_t active);
extern void gateway_r4_critical_rank(unsigned i, uint32_t *caller, uint32_t *task, uint32_t *max, uint32_t *count);
extern void gateway_d1_eth_isr_reset(void);
extern uint32_t gateway_d1_eth_isr_max(void);
extern uint32_t gateway_d1_eth_isr_count(void);
static volatile struct {
    uint8_t magic[4];
    uint16_t hz;
    uint8_t high;
    uint8_t reserved;
    uint32_t cycles[R4_SAMPLES];
} capture __attribute__((section(".gateway_rt.capture")));

void gateway_runtime_init(void)
{
    CoreDebug->DEMCR|=CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT=0U;
    DWT->CTRL|=DWT_CTRL_CYCCNTENA_Msk;
}
uint32_t gateway_runtime_counter(void) { return DWT->CYCCNT; }

#if GATEWAY_R4_BLOCKER_PC
/* What was running when each release arrived: the interrupted context's PC
 * (from its exception frame), task and exception number (0 = thread mode).
 * Indexed by release number mod 16; the task reads it within a few releases. */
#define BLOCK_RING 16U
#define BLOCK_TOP 16U
#define BLOCK_LATE_CYCLES 6000U
static volatile uint32_t release_pc[BLOCK_RING], release_task[BLOCK_RING], release_exc[BLOCK_RING];
static struct { uint32_t pc, task, exc, max_late, count; } block_top[BLOCK_TOP];
extern TaskHandle_t pxCurrentTCB;
void gateway_r4_tim7_irq(const uint32_t *frame) __attribute__((used));
__attribute__((naked)) void TIM7_IRQHandler(void)
{
    __asm volatile("tst lr, #4      \n"
                   "ite eq          \n"
                   "mrseq r0, msp   \n"
                   "mrsne r0, psp   \n"
                   "b gateway_r4_tim7_irq \n");
}
static void block_note(uint32_t n, uint32_t late)
{
    uint32_t pc=release_pc[n%BLOCK_RING], task=release_task[n%BLOCK_RING], exc=release_exc[n%BLOCK_RING];
    unsigned slot=BLOCK_TOP;
    for(unsigned i=0;i<BLOCK_TOP;i++)
        if(block_top[i].count && block_top[i].pc==pc && block_top[i].exc==exc) { slot=i; break; }
    if(slot==BLOCK_TOP)
        for(unsigned i=0;i<BLOCK_TOP;i++) if(!block_top[i].count) { slot=i; break; }
    if(slot==BLOCK_TOP) return;
    block_top[slot].pc=pc; block_top[slot].task=task; block_top[slot].exc=exc;
    if(late>block_top[slot].max_late) block_top[slot].max_late=late;
    block_top[slot].count++;
}
void gateway_r4_tim7_irq(const uint32_t *frame)
#else
void TIM7_IRQHandler(void)
#endif
{
    uint32_t entered=DWT->CYCCNT;
    if((TIM7->SR & TIM_SR_UIF)==0U) return;
    TIM7->SR=0U;
    /* CNT reports time since the most recent hardware update. A single UIF
     * can represent several updates while BASEPRI masks this IRQ, so count
     * those releases from the DWT gap between reconstructed update times. */
    uint32_t released=entered-(uint32_t)TIM7->CNT*core_cycles_per_us;
    uint32_t n=release_count;
    if(n<R4_SAMPLES) {
        if(n) {
            uint32_t gap=released-last_release_cycles;
            uint32_t intervals=(gap+timer_period_cycles/2U)/timer_period_cycles;
            if(intervals==0U) ++release_gap_anomalies;
            else if(intervals>1U) release_lost+=intervals-1U;
        }
        last_release_cycles=released;
        /* The ISR writes the release timestamp into the final sample slot.
         * The task replaces it with latency only after release_count advances. */
        capture.cycles[n]=released;
#if GATEWAY_R4_BLOCKER_PC
        release_pc[n%BLOCK_RING]=frame[6];
        release_exc[n%BLOCK_RING]=frame[7]&0x1FFU;
        release_task[n%BLOCK_RING]=(uint32_t)pxCurrentTCB;
#endif
        release_count=n+1U;
        BaseType_t wake=pdFALSE;
        vTaskNotifyGiveFromISR(control_handle,&wake);
        uint32_t spent=DWT->CYCCNT-entered;
        if(spent>isr_max_cycles) isr_max_cycles=spent;
        portYIELD_FROM_ISR(wake);
    }
    if(n+1U>=R4_SAMPLES) {
        gateway_r4_critical_window(0U);
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
    capture.reserved=0U;
    /* Boot self-tests and the host's admin policy install finish before this
     * window; the collector also verifies READY precedes START. */
    vTaskDelay(pdMS_TO_TICKS(10000));
    __HAL_RCC_TIM7_CLK_ENABLE();
    uint32_t bus=HAL_RCC_GetPCLK1Freq();
    uint32_t ppre=(RCC->CFGR & RCC_CFGR_PPRE1)>>RCC_CFGR_PPRE1_Pos;
    uint32_t timer_clock=ppre>=4U ? bus*2U : bus;
    uint32_t period_cycles=HAL_RCC_GetHCLKFreq()/GATEWAY_R4_CONTROL_HZ;
    timer_period_cycles=period_cycles;
    core_cycles_per_us=HAL_RCC_GetHCLKFreq()/1000000U;
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
    gateway_d1_eth_isr_reset();
    release_count=0U;
    isr_max_cycles=0U;
    release_lost=0U;
    release_gap_anomalies=0U;
    gateway_r4_critical_window(1U);
    TIM7->CR1=TIM_CR1_CEN;
    uint32_t processed=0U, misses=0U, max_cycles=0U;
    while(processed<R4_SAMPLES) {
        (void)ulTaskNotifyTake(pdTRUE,portMAX_DELAY);
        uint32_t available=release_count;
        while(processed<available) {
            uint32_t now=DWT->CYCCNT;
            uint32_t late=now-capture.cycles[processed];
            capture.cycles[processed]=late;
            if(late>=period_cycles) ++misses;
#if GATEWAY_R4_BLOCKER_PC
            if(late>=BLOCK_LATE_CYCLES) block_note(processed,late);
#endif
            if(late>max_cycles) max_cycles=late;
            ++processed;
        }
    }
    /* Freeze measurements before stack scans, logging or runtime diagnostics
     * can add unrelated critical sections and Ethernet interrupts. */
    uint32_t critical_max=gateway_r4_critical_max();
    uint32_t critical_anomalies=gateway_r4_critical_anomalies();
    uint32_t tim_isr_max=isr_max_cycles;
    uint32_t lost=release_lost;
    uint32_t gap_anomalies=release_gap_anomalies;
    uint32_t eth_isr_max=gateway_d1_eth_isr_max();
    uint32_t eth_irqs=gateway_d1_eth_isr_count();
    uint32_t stack_free=uxTaskGetStackHighWaterMark(NULL)*sizeof(StackType_t);
    gateway_log("[CTRL R4] hz=%u high=%u samples=%lu misses=%lu lost_releases=%lu gap_anomalies=%lu max_cycles=%lu critical_max_cycles=%lu critical_anomalies=%lu isr_max_cycles=%lu eth_isr_max_cycles=%lu eth_isr_count=%lu stack_free=%lu\n",
                GATEWAY_R4_CONTROL_HZ,GATEWAY_R4_CONTROL_HIGH,
                (unsigned long)processed,(unsigned long)misses,
                (unsigned long)lost,(unsigned long)gap_anomalies,
                (unsigned long)max_cycles,
                (unsigned long)critical_max,(unsigned long)critical_anomalies,
                (unsigned long)tim_isr_max,(unsigned long)eth_isr_max,
                (unsigned long)eth_irqs,(unsigned long)stack_free);
    for(unsigned i=0;i<8U;i++) {
        uint32_t caller,task,cmax,count;
        gateway_r4_critical_rank(i,&caller,&task,&cmax,&count);
        if(count) gateway_log("[CRIT] rank=%u caller=0x%08lx task=0x%08lx max_cycles=%lu count=%lu task_name=%s\n",
                              i,(unsigned long)caller,(unsigned long)task,(unsigned long)cmax,(unsigned long)count,
                              task ? pcTaskGetName((TaskHandle_t)task) : "-");
    }
#if GATEWAY_R4_BLOCKER_PC
    for(unsigned i=0;i<BLOCK_TOP;i++)
        if(block_top[i].count) gateway_log("[BLOCK] pc=0x%08lx exc=%lu task=0x%08lx count=%lu max_late=%lu\n",
            (unsigned long)block_top[i].pc,(unsigned long)block_top[i].exc,(unsigned long)block_top[i].task,
            (unsigned long)block_top[i].count,(unsigned long)block_top[i].max_late);
#endif
    /* This observer suspends scheduling and scans stacks, so run it only after
     * the 10,000-sample deadline window has closed, but before the long UART
     * transfer used to export the exact samples. */
    uint32_t total=0U;
    UBaseType_t tasks=uxTaskGetSystemState(runtime_after,16U,&total);
    if(gateway_log_binary((const void *)&capture,sizeof(capture))!=(int)sizeof(capture))
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
        (UBaseType_t)(GATEWAY_R4_CONTROL_HIGH ? osPriorityRealtime4 : osPriorityNormal) |
        portPRIVILEGE_BIT,control_stack,&control_tcb);
    if(!control_handle) gateway_panic(GATEWAY_FAULT_STARTUP);
}
#endif
