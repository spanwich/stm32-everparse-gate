/* D1 AUTH identity oracle. No request, policy, or APP pointer crosses this
 * channel: the kernel copies bounded token/credential bytes and replies. */
#include "gateway_d1_auth.h"
#include "gateway_platform.h"
#include "gateway_clear.h"
#include "token_validate.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "cmsis_os2.h"
#include <string.h>

#define AUTH_PRIVATE __attribute__((section(".gateway_auth")))
#define KERNEL_PRIVATE __attribute__((section(".gateway_privileged")))
#define GATE_PRIVATE __attribute__((section(".gateway_gate")))
#define BOOT_SECRET __attribute__((section("privileged_functions")))
#define AUTH_STACK_WORDS 1024U
#define AUTH_LOGIN_MAX 256U

typedef struct {
    char token[16];
    uint8_t token_len, role, rate;
    uint16_t scope;
    char subject[16];
    uint8_t subject_len;
} Fixture;
static const struct {
    uint8_t key[32];
    Fixture fixture[3];
} boot_secrets BOOT_SECRET = {
    {0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
     0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
     0xF0,0xE1,0xD2,0xC3,0xB4,0xA5,0x96,0x87,
     0x78,0x69,0x5A,0x4B,0x3C,0x2D,0x1E,0x0F},
    {
        {"pg-lab-operator",15,ROLE_OPERATOR,0,1,"lab-operator",12},
        {"pg-lab-admin",12,ROLE_ADMIN,0,7,"lab-admin",9},
        {"pg-lab-limited",14,ROLE_OPERATOR,50,1,"lab-limited",11},
    }
};
static uint8_t auth_key[32] AUTH_PRIVATE;
static Fixture auth_fixture[3] AUTH_PRIVATE;
static StackType_t auth_stack[AUTH_STACK_WORDS] AUTH_PRIVATE
    __attribute__((aligned(4096)));
static StaticTask_t auth_tcb KERNEL_PRIVATE;

typedef enum { AUTH_IDENTIFY=1, AUTH_LOGIN=2 } AuthKind;
typedef struct {
    uint32_t sequence;
    uint16_t length;
    uint8_t kind;
    uint8_t bytes[AUTH_LOGIN_MAX];
} AuthRequest;
typedef struct {
    uint32_t sequence;
    int32_t status;
    GatewayIdentity identity;
    uint8_t rate, token_length;
    char token[128];
} AuthReply;

static StaticQueue_t request_cb KERNEL_PRIVATE, reply_cb KERNEL_PRIVATE;
static uint8_t request_storage[sizeof(AuthRequest)] KERNEL_PRIVATE;
static uint8_t reply_storage[sizeof(AuthReply)] KERNEL_PRIVATE;
static QueueHandle_t gate_request GATE_PRIVATE, gate_reply GATE_PRIVATE;
static QueueHandle_t auth_request AUTH_PRIVATE, auth_reply AUTH_PRIVATE;
static uint32_t gate_sequence GATE_PRIVATE;

const uint8_t *gateway_d1_auth_key(void) { return auth_key; }

void gateway_d1_auth_secrets_init(void)
{
    memcpy(auth_key,boot_secrets.key,sizeof(auth_key));
    memcpy(auth_fixture,boot_secrets.fixture,sizeof(auth_fixture));
    gateway_auth_credential_init();
}

static bool identify_local(const uint8_t *token, size_t length,
                           GatewayIdentity *identity, uint8_t *rate)
{
    memset(identity,0,sizeof(*identity)); *rate=0;
    for(size_t i=0;i<3;++i) {
        const Fixture *f=&auth_fixture[i];
        if(length!=f->token_len) continue;
        unsigned diff=0;
        for(size_t j=0;j<length;++j) diff|=token[j]^(uint8_t)f->token[j];
        if(diff) continue;
        identity->valid=true; identity->role=f->role; identity->scope=f->scope;
        identity->subject_len=f->subject_len;
        memcpy(identity->subject,f->subject,f->subject_len);
        *rate=f->rate;
        return true;
    }
    if(length==0 || length>127) return false;
    identity->valid=validate_token((const char *)token,(uint8_t)length,
        &identity->role,&identity->scope,(char *)identity->subject,
        &identity->subject_len)!=0;
    return identity->valid;
}

static void auth_task(void *arg)
{
    (void)arg;
    for(;;) {
        AuthRequest request;
        AuthReply reply={0};
        if(xQueueReceive(auth_request,&request,portMAX_DELAY)!=pdPASS)
            continue;
        reply.sequence=request.sequence;
        if(request.kind==AUTH_IDENTIFY && request.length<=127U) {
            reply.status=identify_local(request.bytes,request.length,
                                        &reply.identity,&reply.rate)?200:401;
        } else if(request.kind==AUTH_LOGIN && request.length<=AUTH_LOGIN_MAX) {
            reply.status=gateway_auth_issue_token(request.bytes,request.length,
                                                   reply.token,&reply.token_length);
        } else reply.status=400;
        gateway_clear(&request,sizeof(request));
        (void)xQueueSend(auth_reply,&reply,pdMS_TO_TICKS(2000));
        gateway_clear(&reply,sizeof(reply));
    }
}

void gateway_d1_auth_start(void)
{
    gate_request=xQueueCreateStatic(1,sizeof(AuthRequest),request_storage,&request_cb);
    gate_reply=xQueueCreateStatic(1,sizeof(AuthReply),reply_storage,&reply_cb);
    if(!gate_request || !gate_reply) gateway_panic(GATEWAY_FAULT_ALLOC);
    auth_request=gate_request; auth_reply=gate_reply;
    const TaskParameters_t parameters={
        .pvTaskCode=auth_task,.pcName="gateway_auth",
        .usStackDepth=AUTH_STACK_WORDS,.pvParameters=NULL,
        .uxPriority=(UBaseType_t)osPriorityHigh4,.puxStackBuffer=auth_stack,
        .xRegions={{(void *)0x20060000UL,16U*1024U,
            portMPU_REGION_READ_WRITE|portMPU_REGION_EXECUTE_NEVER|
            portMPU_REGION_CACHEABLE_BUFFERABLE},{NULL,0,0},{NULL,0,0}},
        .pxTaskBuffer=&auth_tcb};
    TaskHandle_t task=NULL;
    if(xTaskCreateRestrictedStatic(&parameters,&task)!=pdPASS || !task)
        gateway_panic(GATEWAY_FAULT_STARTUP);
    vGrantAccessToQueue(task,gate_request);
    vGrantAccessToQueue(task,gate_reply);
}

void gateway_d1_auth_grant_gate(void *task)
{
    vGrantAccessToQueue((TaskHandle_t)task,gate_request);
    vGrantAccessToQueue((TaskHandle_t)task,gate_reply);
}

static bool exchange(AuthRequest *request, AuthReply *reply)
{
    request->sequence=++gate_sequence;
    if(xQueueSend(gate_request,request,pdMS_TO_TICKS(2000))!=pdPASS)
        return false;
    /* A timed-out prior call may leave one stale reply. A mismatched sequence
     * always fails closed; only the matching reply can supply identity. */
    if(xQueueReceive(gate_reply,reply,pdMS_TO_TICKS(2000))!=pdPASS)
        return false;
    return reply->sequence==request->sequence;
}

bool gateway_d1_auth_identify(const uint8_t *token, size_t length,
                              GatewayIdentity *identity, uint8_t *rate)
{
    memset(identity,0,sizeof(*identity)); *rate=0;
    if(!token || length==0 || length>127) return false;
    AuthRequest request={.length=(uint16_t)length,.kind=AUTH_IDENTIFY};
    AuthReply reply={0};
    memcpy(request.bytes,token,length);
    bool ok=exchange(&request,&reply) && reply.status==200 && reply.identity.valid;
    if(ok) { *identity=reply.identity; *rate=reply.rate; }
    gateway_clear(&request,sizeof(request)); gateway_clear(&reply,sizeof(reply));
    return ok;
}

int gateway_d1_auth_login(const uint8_t *body, size_t length,
                          char *token, uint8_t *token_length)
{
    *token_length=0;
    if(!body || !token || length==0 || length>AUTH_LOGIN_MAX) return 400;
    AuthRequest request={.length=(uint16_t)length,.kind=AUTH_LOGIN};
    AuthReply reply={0};
    memcpy(request.bytes,body,length);
    int status=exchange(&request,&reply)?reply.status:500;
    if(status==200 && reply.token_length<=127U) {
        *token_length=reply.token_length;
        memcpy(token,reply.token,*token_length);
        token[*token_length]=0;
    } else if(status==200) status=500;
    gateway_clear(&request,sizeof(request)); gateway_clear(&reply,sizeof(reply));
    return status;
}
