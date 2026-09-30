/* Bounded NET kernel-object lifecycle service. V11 wrappers v2 keep dynamic
 * creation/deletion privileged; this worker creates only lwIP queues and
 * semaphores, grants them to NET, and reclaims registered handles. */
#include "gateway_d1_cleanup.h"
#include "gateway_platform.h"
#include "cmsis_os2.h"
#include "task.h"
#include "semphr.h"

#define PRIVATE __attribute__((section(".gateway_privileged")))
#define TRUSTED __attribute__((section("privileged_functions")))
#define REGISTERED_MAX 128U
enum { DELETE_OBJECT=1, CREATE_MBOX=2, CREATE_SEM=3 };
typedef struct {
    uint8_t action;
    uint16_t count;
    uint16_t initial;
    QueueHandle_t handle;
} KernelRequest;

static QueueHandle_t registered[REGISTERED_MAX] PRIVATE;
static TaskHandle_t network_owner PRIVATE, tcpip_owner PRIVATE;
static StackType_t cleanup_stack[384] PRIVATE __attribute__((aligned(2048)));
static StaticTask_t cleanup_tcb PRIVATE;
static StaticQueue_t request_cb PRIVATE, reply_cb PRIVATE;
static StaticSemaphore_t creation_cb PRIVATE;
static QueueHandle_t request_priv PRIVATE, reply_priv PRIVATE;
static QueueHandle_t request_user, reply_user;
static SemaphoreHandle_t creation_priv PRIVATE, creation_user;
static uint8_t request_storage[8U*sizeof(KernelRequest)] PRIVATE;
static uint8_t reply_storage[sizeof(QueueHandle_t)] PRIVATE;

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
        KernelRequest request={0};
        if(xQueueReceive(request_priv,&request,portMAX_DELAY)!=pdPASS) continue;
        if(request.action==DELETE_OBJECT) {
            bool found=false;
            taskENTER_CRITICAL();
            for(unsigned i=0;i<REGISTERED_MAX;++i)
                if(registered[i]==request.handle) {
                    registered[i]=NULL; found=true; break;
                }
            taskEXIT_CRITICAL();
            if(found) vQueueDelete(request.handle);
            continue;
        }
        QueueHandle_t made=NULL;
        if(request.action==CREATE_MBOX && request.count>0U && request.count<=64U)
            made=xQueueCreate(request.count,sizeof(void *));
        else if(request.action==CREATE_SEM && request.count>0U &&
                request.initial<=request.count)
            made=xSemaphoreCreateCounting(request.count,request.initial);
        if(made) {
            gateway_d1_cleanup_register(made);
            if(network_owner) vGrantAccessToQueue(network_owner,made);
            if(tcpip_owner) vGrantAccessToQueue(tcpip_owner,made);
        }
        if(xQueueSend(reply_priv,&made,pdMS_TO_TICKS(2000))!=pdPASS)
            gateway_panic(GATEWAY_FAULT_ASSERT);
    }
}

void TRUSTED gateway_d1_cleanup_start(void)
{
    request_priv=xQueueCreateStatic(8,sizeof(KernelRequest),request_storage,&request_cb);
    reply_priv=xQueueCreateStatic(1,sizeof(QueueHandle_t),reply_storage,&reply_cb);
    creation_priv=xSemaphoreCreateMutexStatic(&creation_cb);
    if(!request_priv || !reply_priv || !creation_priv) gateway_panic(GATEWAY_FAULT_ALLOC);
    request_user=request_priv; reply_user=reply_priv; creation_user=creation_priv;
    if(!xTaskCreateStatic(cleanup_task,"kernel_cleanup",384,NULL,
        (UBaseType_t)osPriorityAboveNormal|portPRIVILEGE_BIT,
        cleanup_stack,&cleanup_tcb)) gateway_panic(GATEWAY_FAULT_STARTUP);
}

void TRUSTED gateway_d1_cleanup_grant(void *task)
{
    TaskHandle_t owner=(TaskHandle_t)task;
    if(!network_owner) network_owner=owner;
    else if(!tcpip_owner && owner!=network_owner) tcpip_owner=owner;
    vGrantAccessToQueue(owner,request_priv);
    vGrantAccessToQueue(owner,reply_priv);
    vGrantAccessToQueue(owner,creation_priv);
}

static QueueHandle_t create_object(uint8_t action,unsigned count,unsigned initial)
{
    if(count==0U || count>UINT16_MAX || initial>count || !creation_user)
        return NULL;
    if(action==CREATE_MBOX && count>64U) return NULL;
    if(xSemaphoreTake(creation_user,pdMS_TO_TICKS(2000))!=pdPASS) return NULL;
    KernelRequest request={.action=action,.count=(uint16_t)count,
                           .initial=(uint16_t)initial};
    QueueHandle_t result=NULL;
    if(xQueueSend(request_user,&request,pdMS_TO_TICKS(2000))==pdPASS)
        (void)xQueueReceive(reply_user,&result,pdMS_TO_TICKS(2000));
    (void)xSemaphoreGive(creation_user);
    return result;
}

QueueHandle_t gateway_d1_cleanup_create_mbox(unsigned count)
{
    return create_object(CREATE_MBOX,count,0U);
}

QueueHandle_t gateway_d1_cleanup_create_sem(unsigned maximum,unsigned initial)
{
    return create_object(CREATE_SEM,maximum,initial);
}

bool gateway_d1_cleanup_enqueue(QueueHandle_t handle)
{
    KernelRequest request={.action=DELETE_OBJECT,.handle=handle};
    return handle && xQueueSend(request_user,&request,pdMS_TO_TICKS(2000))==pdPASS;
}
