/* Optional R1 DWT experiment. Binary records are decoded by paper_timing_capture.py.
 * Interrupts stay enabled; this is an observed distribution, not WCET. */
#include "paper_experiment.h"
#if GATEWAY_PAPER_TIMING
#include "gateway_core.h"
#include "gateway_http.h"
#include "gateway_log.h"
#include "path_hashes.h"
#include "HTTP_Extract_Complete.h"
#include "../Generated/Mediation/Mediation_Format.h"
#include "../Generated/Mediation/Mediation_Field.h"
#include "main.h"
#include <stdio.h>
#include <string.h>

enum { SAMPLES=10000, STAGES=8, CASES=7 };
static uint8_t record[8+4*SAMPLES];
static GatewayContext context;
static GatewayHttp http;
static uint8_t security[1536], policy[65], login[106], envelope[106];
static uint8_t extracted[1536];
static uint32_t extracted_len;
static char http_request[160];
static size_t http_length;
static volatile uint32_t result_sink;
extern bool paper_timing_validate(uint8_t *bytes);
static uint32_t path;
static uint8_t method, role, rate;
static uint16_t scope;

static void put16(uint8_t *p,uint16_t value)
{ p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8); }
static void put32(uint8_t *p,uint32_t value)
{ for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(value>>(8*i)); }

static bool handwritten(void)
{
    if(rate>=50) return false;
    for(unsigned i=0;i<8;++i) {
        const PolicyRule *r=&context.policy.rules[i];
        if(r->path_hash==path && (r->method&method)==method &&
           role>=r->min_role && (scope&r->req_scope)==r->req_scope) return true;
    }
    return false;
}

static void setup(unsigned which)
{
    gateway_init(&context);
    context.policy.num_rules=3;
    for(unsigned i=0;i<8;++i)
        context.policy.rules[i]=(PolicyRule){INACTIVE_PATH_ID,0,ROLE_NONE,0};
    path=PATH_STATUS;method=METHOD_GET;role=ROLE_OPERATOR;scope=3;rate=0;
    unsigned slot=which==1?2:0;
    context.policy.rules[slot]=(PolicyRule){PATH_STATUS,METHOD_GET,ROLE_OPERATOR,1};
    if(which==2) path=0xFEEDBEEFu;
    if(which==3) method=METHOD_POST;
    if(which==4) {
        path=PATH_POLICY;
        context.policy.rules[0]=(PolicyRule){PATH_POLICY,METHOD_GET,ROLE_ADMIN,1};
    }
    if(which==5) context.policy.rules[0].req_scope=4;
    if(which==6) rate=50;
    memset(security,0,sizeof(security));
    security[0]=rate;put32(security+1,path);security[5]=method;
    security[6]=role;put16(security+7,scope);
    memset(policy,0,sizeof(policy));policy[0]=context.policy.num_rules;
    for(unsigned i=0;i<8;++i) {
        const PolicyRule *r=&context.policy.rules[i];uint8_t *p=policy+1+8*i;
        put32(p,r->path_hash);p[4]=r->method;p[5]=r->min_role;put16(p+6,r->req_scope);
    }
    const char *target=which==2?"/unknown":which==4?"/api/policy":"/api/status";
    const char *verb=which==3?"POST":"GET";
    const char *token=which==6?"pg-lab-limited":"pg-lab-operator";
    int n=snprintf(http_request,sizeof(http_request),
        "%s %s HTTP/1.1\r\nHost: board\r\nAuthorization: Bearer %s\r\nContent-Length: 0\r\n\r\n",
        verb,target,token);
    http_length=n>0?(size_t)n:0;
}

static uint32_t run_one(unsigned stage)
{
    switch(stage) {
    case 0: return DWT->CYCCNT;
    case 1: return paper_timing_validate(envelope);
    case 2:
        Mediation_Format_build(security,policy,login,2,envelope);
        return paper_timing_validate(envelope);
    case 3:
        extracted_len=0;
        return extract_security_params((uint8_t *)http_request,(uint32_t)http_length,
                                       extracted,&extracted_len);
    case 4: return handwritten();
    case 5:
        gateway_begin_request(&context);gateway_http_init(&http);
        {
            int status=gateway_http_feed(&http,&context,http_request,http_length);
            return status==1?(uint32_t)gateway_http_process(&http,&context):(uint32_t)status;
        }
    case 6:
        Mediation_Format_build(security,policy,login,2,envelope);
        return envelope[0];
    default:
        Mediation_Field_build_access(security,policy,login,envelope);
        return envelope[0];
    }
}

void gateway_paper_timing_run(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT=0;DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
    gateway_log("[PAPER TIMING] begin samples=%u stages=%u cases=%u interrupts=%s\n",
                SAMPLES,STAGES,CASES,GATEWAY_R4_TIMING_MASK_IRQ?"masked":"enabled");
    for(unsigned stage=0;stage<STAGES;++stage) {
        unsigned count=stage==0?1:CASES;
        for(unsigned which=0;which<count;++which) {
            setup(which);
            Mediation_Format_build(security,policy,login,2,envelope);
            if (stage==7) {
                uint8_t reference[sizeof(envelope)];
                memcpy(reference,envelope,sizeof(reference));
                Mediation_Field_build_access(security,policy,login,envelope);
                if(memcmp(reference,envelope,sizeof(reference))!=0) {
                    gateway_log("[PAPER TIMING] field mismatch case=%u\n",which);
                    return;
                }
            }
            if(stage==1 || stage==2 || stage==4) {
                bool oracle=handwritten();
                bool generated=paper_timing_validate(envelope);
                if(oracle!=generated) {
                    gateway_log("[PAPER TIMING] oracle mismatch stage=%u case=%u\n",stage,which);
                    return;
                }
            }
            memcpy(record,"PGB1",4);record[4]=(uint8_t)stage;record[5]=(uint8_t)which;
            put16(record+6,SAMPLES);
            for(unsigned sample=0;sample<SAMPLES;++sample) {
#if GATEWAY_R4_TIMING_MASK_IRQ
                uint32_t primask=__get_PRIMASK();
                __disable_irq();
#endif
                uint32_t start=DWT->CYCCNT;
                result_sink=run_one(stage);
                uint32_t delta=DWT->CYCCNT-start;
#if GATEWAY_R4_TIMING_MASK_IRQ
                __set_PRIMASK(primask);
#endif
                put32(record+8+4*sample,delta);
            }
            if(gateway_log_binary(record,sizeof(record))!=(int)sizeof(record)) {
                gateway_log("[PAPER TIMING] UART record failed stage=%u case=%u\n",stage,which);
                return;
            }
        }
    }
    gateway_log("[PAPER TIMING] done samples=%u\n",SAMPLES);
}
#endif
