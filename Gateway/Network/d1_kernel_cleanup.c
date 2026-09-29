/* Interim privileged kernel-object reclamation for the R4 netconn adapter.
 * V11 deliberately does not expose vQueueDelete to unprivileged tasks.
 * D1.7 step 4 will replace this broad registration with NET/SHIM-owned
 * lifetime rules and exact ACLs. */
#include "gateway_d1_cleanup.h"
#include "gateway_platform.h"
#include "cmsis_os2.h"
#include "task.h"

#define PRIVATE __attribute__((section(".gateway_privileged")))
#define TRUSTED __attribute__((section("privileged_functions")))
#define REGISTERED_MAX 128U
static QueueHandle_t registered[REGISTERED_MAX] PRIVATE;
static StackType_t cleanup_stack[256] PRIVATE __attribute__((aligned(1024)));
static StaticTask_t cleanup_tcb PRIVATE;
static StaticQueue_t cleanup_cb PRIVATE;
static QueueHandle_t cleanup_priv PRIVATE;
static QueueHandle_t cleanup_user;
static uint8_t cleanup_storage[8U*sizeof(QueueHandle_t)] PRIVATE;

void TRUSTED gateway_d1_cleanup_register(QueueHandle_t handle)
{
    if(!handle) return;
    taskENTER_CRITICAL();
    for(unsigned i=0;i<REGISTERED_MAX;++i) {
        if(registered[i]==handle) { taskEXIT_CRITICAL(); return; }
        if(!registered[i]) { registered[i]=handle; taskEXIT_CRITICAL(); return; }
    }
    taskEXIT_CRITICAL();
    gateway_panic(GATEWAY_FAULT_ALLOC);
}

void TRUSTED gateway_d1_cleanup_forget(QueueHandle_t handle)
{
    taskENTER_CRITICAL();
    for(unsigned i=0;i<REGISTERED_MAX;++i)
        if(registered[i]==handle) { registered[i]=NULL; break; }
    taskEXIT_CRITICAL();
}

static void cleanup_task(void *arg)
{
    (void)arg;
    for(;;) {
        QueueHandle_t handle=NULL;
        if(xQueueReceive(cleanup_priv,&handle,portMAX_DELAY)!=pdPASS) continue;
        bool found=false;
        taskENTER_CRITICAL();
        for(unsigned i=0;i<REGISTERED_MAX;++i)
            if(registered[i]==handle) { registered[i]=NULL; found=true; break; }
        taskEXIT_CRITICAL();
        if(found) vQueueDelete(handle);
    }
}

void TRUSTED gateway_d1_cleanup_start(void)
{
    cleanup_priv=xQueueCreateStatic(8,sizeof(QueueHandle_t),cleanup_storage,&cleanup_cb);
    if(!cleanup_priv) gateway_panic(GATEWAY_FAULT_ALLOC);
    cleanup_user=cleanup_priv;
    if(!xTaskCreateStatic(cleanup_task,"kernel_cleanup",256,NULL,
        (UBaseType_t)osPriorityAboveNormal|portPRIVILEGE_BIT,
        cleanup_stack,&cleanup_tcb)) gateway_panic(GATEWAY_FAULT_STARTUP);
}

void TRUSTED gateway_d1_cleanup_grant(void *task)
{
    vGrantAccessToQueue((TaskHandle_t)task,cleanup_priv);
}

bool gateway_d1_cleanup_enqueue(QueueHandle_t handle)
{
    return handle && xQueueSend(cleanup_user,&handle,pdMS_TO_TICKS(2000))==pdPASS;
}
