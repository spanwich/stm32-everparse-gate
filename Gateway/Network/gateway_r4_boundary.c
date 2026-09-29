/* R4 transport/gate/app task boundary. Queue items copy bytes; no request,
 * response or app pointer crosses ownership. The gate re-parses every request
 * and owns the only live policy and validator input in privileged SRAM. */
#include "gateway_r4_boundary.h"
#include "gateway_platform.h"
#include "gateway_log.h"
#include "paper_experiment.h"
#include "main.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "cmsis_os2.h"
#include <string.h>

#if GATEWAY_R4_FAULT_INJECT == 8
extern BaseType_t xPortRaisePrivilege(void) __attribute__((weak));
#endif
#if GATEWAY_R4_FAULT_INJECT == 9
extern TickType_t MPU_xTaskGetTickCount(void);
#endif

#define PRIVATE __attribute__((section(".gateway_privileged")))
#define APP_PRIVATE __attribute__((section(".gateway_app")))
#define GATE_STACK_WORDS 2048U
#define APP_STACK_WORDS 1024U
typedef struct { uint32_t used; uint8_t raw[GATEWAY_REQUEST_CAPACITY]; } Ingress;
typedef struct { uint32_t length; Policy policy; uint8_t app[GATEWAY_WIRE_CAPACITY]; } AppJob;
typedef struct { uint32_t length; uint8_t gate[GATEWAY_WIRE_CAPACITY]; bool ok; } AppResult;

static GatewayContext live_gate PRIVATE;
static GatewayHttp gate_http PRIVATE;
static Ingress gate_input PRIVATE;
static AppJob app_job APP_PRIVATE;
static AppResult app_result APP_PRIVATE;
static StackType_t gate_stack[GATE_STACK_WORDS] PRIVATE __attribute__((aligned(8192)));
static StackType_t app_stack[APP_STACK_WORDS] APP_PRIVATE __attribute__((aligned(4096)));
static StaticTask_t gate_tcb PRIVATE, app_tcb PRIVATE;
static StaticQueue_t ingress_cb PRIVATE, reply_cb PRIVATE, app_cb PRIVATE, app_reply_cb PRIVATE;
static uint8_t ingress_storage[sizeof(Ingress)] PRIVATE;
static uint8_t reply_storage[sizeof(GatewayR4Reply)] PRIVATE;
static uint8_t app_storage[sizeof(AppJob)] PRIVATE;
static uint8_t app_reply_storage[sizeof(AppResult)] PRIVATE;
static QueueHandle_t ingress_queue, reply_queue, app_queue, app_reply_queue;
static bool app_started PRIVATE;
static Ingress outbound;
static GatewayR4Reply inbound;
#if GATEWAY_R4_FAULT_INJECT == 2
static volatile uint8_t *volatile validator_probe_target;
static StackType_t probe_stack[512] __attribute__((aligned(2048)));
static StaticTask_t probe_tcb;
static void validator_probe(void *arg)
{
    (void)arg;
    while (!validator_probe_target) vTaskDelay(1);
    gateway_fault_record.line=2;
    *validator_probe_target=0;
    gateway_panic(GATEWAY_FAULT_ASSERT); /* Reaching here fails the experiment. */
}
#endif

static void app_task(void *arg)
{
    (void)arg;
    gateway_log("[MPU] app_unprivileged=%u\n",(unsigned)(__get_CONTROL() & 1U));
#if GATEWAY_R4_FAULT_INJECT == 6
    gateway_fault_record.line=6;
    live_gate.policy.num_rules=0;
    gateway_panic(GATEWAY_FAULT_ASSERT); /* An app write into gate state must fault. */
#endif
    for (;;) {
        if (xQueueReceive(app_queue,&app_job,portMAX_DELAY)!=pdPASS)
            gateway_panic(GATEWAY_FAULT_ASSERT);
        app_result.ok=gateway_render_app(app_job.app,app_job.length,&app_job.policy,
                                         app_result.gate,&app_result.length);
        if(!app_result.ok) app_result.length=0;
        if (xQueueSend(app_reply_queue,&app_result,pdMS_TO_TICKS(2000))!=pdPASS)
            gateway_panic(GATEWAY_FAULT_ASSERT);
    }
}

bool gateway_r4_app_dispatch(GatewayContext *gate)
{
    /* Self-tests run before task/queue startup and retain their old fixture path. */
    if (!app_started) return gateway_dispatch(gate);
    if (!gate || gate->app_len>sizeof(app_job.app) ||
        gate->app_len<APP_REQUEST_HEADER_SIZE) return false;
    app_job.length=gate->app_len;
    app_job.policy=gate->policy;
    memcpy(app_job.app,gate->app,gate->app_len);
    if (xQueueSend(app_queue,&app_job,pdMS_TO_TICKS(2000))!=pdPASS ||
        xQueueReceive(app_reply_queue,&app_result,pdMS_TO_TICKS(2000))!=pdPASS ||
        !app_result.ok || app_result.length>sizeof(gate->gate)) return false;
    memcpy(gate->gate,app_result.gate,app_result.length);
    gate->gate_len=app_result.length;
    gate->result=GATEWAY_DISPATCHED;
    ++gate->dispatch_count;
    return true;
}

static void gate_task(void *arg)
{
    (void)arg;
    gateway_init(&live_gate);
    for (;;) {
        if (xQueueReceive(ingress_queue,&gate_input,portMAX_DELAY)!=pdPASS)
            gateway_panic(GATEWAY_FAULT_ASSERT);
        GatewayR4Reply answer={0};
        gateway_begin_request(&live_gate);
        gateway_http_init(&gate_http);
        gateway_audit_begin(&live_gate);
        int status=gate_input.used<=sizeof(gate_input.raw)?
            gateway_http_feed(&gate_http,&live_gate,gate_input.raw,gate_input.used):413;
        if (status==1) status=gateway_http_process(&gate_http,&live_gate);
        else if(status==0) status=400;
        answer.status=status;
        answer.audit=gateway_audit_finish();
        if(live_gate.gate_len<=sizeof(answer.gate)) {
            answer.gate_len=live_gate.gate_len;
            memcpy(answer.gate,live_gate.gate,answer.gate_len);
        }
        if(status==200) {
            answer.dashboard=gate_http.dashboard;
            answer.script=gate_http.script;
            answer.demo=gate_http.demo;
        }
        if(xQueueSend(reply_queue,&answer,pdMS_TO_TICKS(2000))!=pdPASS)
            gateway_panic(GATEWAY_FAULT_ASSERT);
    }
}

void gateway_r4_boundary_start(void)
{
    ingress_queue=xQueueCreateStatic(1,sizeof(Ingress),ingress_storage,&ingress_cb);
    reply_queue=xQueueCreateStatic(1,sizeof(GatewayR4Reply),reply_storage,&reply_cb);
    app_queue=xQueueCreateStatic(1,sizeof(AppJob),app_storage,&app_cb);
    app_reply_queue=xQueueCreateStatic(1,sizeof(AppResult),app_reply_storage,&app_reply_cb);
    if(!ingress_queue || !reply_queue || !app_queue || !app_reply_queue)
        gateway_panic(GATEWAY_FAULT_ALLOC);
    const TaskParameters_t app_params={
        .pvTaskCode=app_task,.pcName="gateway_app",.usStackDepth=APP_STACK_WORDS,
        .pvParameters=NULL,.uxPriority=(UBaseType_t)osPriorityBelowNormal,
        .puxStackBuffer=app_stack,
        .xRegions={
            {(void *)0x20000000UL,512U*1024U,
                portMPU_REGION_READ_WRITE|portMPU_REGION_EXECUTE_NEVER|
                portMPU_REGION_CACHEABLE_BUFFERABLE|(0x80UL<<8)},
            {(void *)0x20000000UL,128U*1024U,
                portMPU_REGION_PRIVILEGED_READ_WRITE|portMPU_REGION_EXECUTE_NEVER|
                portMPU_REGION_CACHEABLE_BUFFERABLE},
            {(void *)0x20020000UL,16U*1024U,
                portMPU_REGION_READ_WRITE|portMPU_REGION_EXECUTE_NEVER|
                portMPU_REGION_CACHEABLE_BUFFERABLE}},
        .pxTaskBuffer=&app_tcb};
    TaskHandle_t app=NULL;
    if(xTaskCreateRestrictedStatic(&app_params,&app)!=pdPASS) app=NULL;
    TaskHandle_t gate=xTaskCreateStatic(gate_task,"gateway_gate",GATE_STACK_WORDS,NULL,
        (UBaseType_t)osPriorityAboveNormal|portPRIVILEGE_BIT,gate_stack,&gate_tcb);
    if(!app || !gate) gateway_panic(GATEWAY_FAULT_STARTUP);
    /* V11 wrappers v2 default to no kernel-object access for unprivileged
     * tasks. Give each endpoint only the R4 queues it actually uses. */
    vGrantAccessToQueue(xTaskGetCurrentTaskHandle(), ingress_queue);
    vGrantAccessToQueue(xTaskGetCurrentTaskHandle(), reply_queue);
    vGrantAccessToQueue(app, app_queue);
    vGrantAccessToQueue(app, app_reply_queue);
    gateway_platform_grant_log_access(xTaskGetCurrentTaskHandle());
    gateway_platform_grant_log_access(app);
#if GATEWAY_R4_FAULT_INJECT == 2
    if(!xTaskCreateStatic(validator_probe,"mpu_probe",512,NULL,
        (UBaseType_t)osPriorityHigh,probe_stack,&probe_tcb))
        gateway_panic(GATEWAY_FAULT_STARTUP);
#endif
    app_started=true;
}

void gateway_r4_network_drop_privilege(void)
{
    vPortSwitchToUserMode();
    gateway_log("[MPU] network_unprivileged=%u gate_privileged=1\n",
                (unsigned)(__get_CONTROL() & 1U));
#if GATEWAY_R4_FAULT_INJECT == 1
    gateway_fault_record.line=1;
    live_gate.policy.num_rules=0;
#elif GATEWAY_R4_FAULT_INJECT == 3
    gateway_fault_record.line=3;
    app_job.app[0]=0;
#elif GATEWAY_R4_FAULT_INJECT == 4
    gateway_fault_record.line=4;
    (void)xPortStartScheduler();
#elif GATEWAY_R4_FAULT_INJECT == 5
    gateway_fault_record.line=5;
    __set_CONTROL(0);
    __ISB();
    if((__get_CONTROL() & 1U)==0) gateway_panic(GATEWAY_FAULT_ASSERT);
    live_gate.policy.num_rules=0;
#elif GATEWAY_R4_FAULT_INJECT == 7
    /* D1 pre-port control: the V10.2 SVC handler does not check its caller. */
    gateway_fault_record.line=7;
    __asm volatile("svc %0" :: "i" (portSVC_RAISE_PRIVILEGE) : "memory");
    __ISB();
    gateway_fault_record.line=70U+(__get_CONTROL() & 1U);
    live_gate.policy.num_rules=0xA7U;
#elif GATEWAY_R4_FAULT_INJECT == 8
    /* V10 exposes this v1 helper. V11 removes it; a null weak reference
     * records the absence of that direct entry point on the live image. */
    gateway_fault_record.line=8;
    if(xPortRaisePrivilege) (void)xPortRaisePrivilege();
    __ISB();
    gateway_fault_record.line=80U+(__get_CONTROL() & 1U);
    if((__get_CONTROL() & 1U)==0U) live_gate.policy.num_rules=0xA8U;
#elif GATEWAY_R4_FAULT_INJECT == 9
    /* Enter the v2 wrapper at its SVC instruction, bypassing its prologue.
     * This exact offset is checked against the staged ELF disassembly. */
    gateway_fault_record.line=9;
    TickType_t (*jump)(void)=(TickType_t (*)(void))
        (((uintptr_t)MPU_xTaskGetTickCount+0x12U)|1U);
    (void)jump();
    __ISB();
    gateway_fault_record.line=90U+(__get_CONTROL() & 1U);
    if((__get_CONTROL() & 1U)==0U) live_gate.policy.num_rules=0xA9U;
#endif
#if GATEWAY_R4_FAULT_INJECT != 0 && GATEWAY_R4_FAULT_INJECT != 2 && GATEWAY_R4_FAULT_INJECT != 6
    gateway_panic(GATEWAY_FAULT_ASSERT); /* A protected effect escaped the MPU. */
#endif
}

void gateway_r4_fault_before_validator(uint8_t *validator_input)
{
#if GATEWAY_R4_FAULT_INJECT == 2
    if(app_started) {
        validator_probe_target=validator_input;
        vTaskDelay(10); /* Force the probe to attempt the write before checking. */
    }
#else
    (void)validator_input;
#endif
}

const GatewayR4Reply *gateway_r4_submit(const GatewayHttp *assembled)
{
    if(!assembled || assembled->used>sizeof(outbound.raw)) return NULL;
    outbound.used=assembled->used;
    memcpy(outbound.raw,assembled->raw,outbound.used);
    if(xQueueSend(ingress_queue,&outbound,pdMS_TO_TICKS(2000))!=pdPASS ||
       xQueueReceive(reply_queue,&inbound,pdMS_TO_TICKS(2000))!=pdPASS) return NULL;
    return &inbound;
}
