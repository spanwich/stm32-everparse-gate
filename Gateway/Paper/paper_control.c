/* Optional 1 kHz control-task load experiment; primary firmware excludes it. */
#include "paper_experiment.h"
#if GATEWAY_PAPER_CONTROL
#include "gateway_log.h"
#include "gateway_platform.h"
#include "main.h"
#include "cmsis_os2.h"
#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"
#include <string.h>

enum { CONTROL_STACK_BYTES=2048, RUNTIME_TASKS=12, HIST_BUCKETS=256 };
static _Alignas(8) StackType_t stack[CONTROL_STACK_BYTES/sizeof(StackType_t)];
static StaticTask_t tcb;
static osThreadId_t control_task;
static volatile uint32_t samples, misses, max_lateness_cycles, workload_sink;
static volatile uint32_t histogram[HIST_BUCKETS];
static uint32_t histogram_copy[HIST_BUCKETS];
static TaskStatus_t tasks[RUNTIME_TASKS];
static struct { TaskHandle_t handle; uint32_t previous; } old[RUNTIME_TASKS];
static struct { TaskHandle_t handle; uint32_t previous; } next[RUNTIME_TASKS];
static uint32_t old_total;
extern TaskHandle_t gateway_paper_core_task(void);
extern TaskHandle_t gateway_paper_diagnostics_task(void);
extern osThreadId_t gateway_tcpip_task, gateway_eth_task, gateway_link_task;

void gateway_runtime_init(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT=0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}
uint32_t gateway_runtime_counter(void) { return DWT->CYCCNT; }

static void run_control(void *unused)
{
    (void)unused;
    uint32_t tick=osKernelGetTickCount();
    tick+=1U;
    (void)osDelayUntil(tick);
    uint32_t expected=DWT->CYCCNT;
    for(;;) {
        uint32_t work=workload_sink;
        for(unsigned i=0;i<64;++i) work=(work*1664525u+1013904223u)^i;
        workload_sink=work;
        uint32_t late=DWT->CYCCNT-expected;
        unsigned bucket=late/384U;
        if(bucket>=HIST_BUCKETS) bucket=HIST_BUCKETS-1;
        ++histogram[bucket];
        ++samples;
        if(late>96000U) ++misses;
        if(late>max_lateness_cycles) max_lateness_cycles=late;
        expected+=96000U;
        tick+=1U;
        (void)osDelayUntil(tick);
    }
}

void gateway_paper_control_start(void)
{
    const osThreadAttr_t attr={.name="paper_control",.priority=osPriorityHigh,
        .cb_mem=&tcb,.cb_size=sizeof(tcb),.stack_mem=stack,.stack_size=sizeof(stack)};
    control_task=osThreadNew(run_control,NULL,&attr);
    if(!control_task) gateway_panic(GATEWAY_FAULT_STARTUP);
}

void gateway_paper_control_diagnostics(void)
{
    uint32_t count,failed,max;
    taskENTER_CRITICAL();
    count=samples;failed=misses;max=max_lateness_cycles;
    for(unsigned i=0;i<HIST_BUCKETS;++i) histogram_copy[i]=histogram[i];
    taskEXIT_CRITICAL();
    uint32_t cumulative=0;unsigned p99=HIST_BUCKETS-1;
    for(unsigned i=0;i<HIST_BUCKETS;++i) {
        cumulative+=histogram_copy[i];
        if(cumulative*100U>=count*99U) { p99=i;break; }
    }
    gateway_log("[CTRL] samples=%lu misses=%lu max_cycles=%lu p99_bucket_us=%lu stack_free=%lu\n",
        (unsigned long)count,(unsigned long)failed,(unsigned long)max,
        (unsigned long)(p99*4U),(unsigned long)(uxTaskGetStackHighWaterMark((TaskHandle_t)control_task)*sizeof(StackType_t)));
    /* uxTaskGetSystemState scans every unused stack byte while scheduling is
     * suspended. That observer alone missed deadlines in the first idle run.
     * Read the same per-task runtime counters without the stack scans. */
    TaskHandle_t handles[]={xTaskGetIdleTaskHandle(),gateway_paper_core_task(),
        gateway_paper_diagnostics_task(),(TaskHandle_t)gateway_tcpip_task,
        (TaskHandle_t)gateway_eth_task,(TaskHandle_t)gateway_link_task,
        (TaskHandle_t)control_task,xTimerGetTimerDaemonTaskHandle()};
    uint32_t total=DWT->CYCCNT;
    UBaseType_t n=sizeof(handles)/sizeof(handles[0]);
    for(UBaseType_t i=0;i<n;++i) {
        if(handles[i]) vTaskGetInfo(handles[i],&tasks[i],pdFALSE,eInvalid);
        else memset(&tasks[i],0,sizeof(tasks[i]));
    }
    uint32_t elapsed=total-old_total;old_total=total;
    for(UBaseType_t i=0;i<n;++i) {
        if(!handles[i]) continue;
        uint32_t prior=0;
        for(UBaseType_t j=0;j<RUNTIME_TASKS;++j)
            if(old[j].handle==tasks[i].xHandle) { prior=old[j].previous;break; }
        uint32_t delta=tasks[i].ulRunTimeCounter-prior;
        next[i].handle=tasks[i].xHandle;next[i].previous=tasks[i].ulRunTimeCounter;
        gateway_log("[RUNTIME] task=%s cycles=%lu total_cycles=%lu\n",
                    tasks[i].pcTaskName,(unsigned long)delta,(unsigned long)elapsed);
    }
    memcpy(old,next,sizeof(old));
}
#endif
