/* Research integration: only the generated wrapper calls the effect bridge.
 * Single gateway-task ownership and immutable snapshots are caller obligations.
 * See Verification/README.md for the exact proof and trusted C boundary. */
#include "gateway_mediation.h"
#include "gateway_login.h"
#include "gateway_clear.h"
#include "gateway_audit.h"
#include "gateway_routes.h"
#ifdef STM32F767xx
#include "gateway_r4_boundary.h"
#endif
#include "paper_experiment.h"
#if GATEWAY_PAPER_CONTROL
#include "paper_control.h"
#include "main.h"
#include "FreeRTOS.h"
#include "task.h"
#endif
#include "../Generated/Mediation/Mediation_Wrapper.h"
#include "../Generated/Mediation/Mediation_Extern.h"
#include <string.h>
#include <stdio.h>

_Static_assert(sizeof(GatewayContext)==8860 || sizeof(GatewayContext)==8864,
               "update the Low* context size contract for this ABI");
#if GATEWAY_PAPER_CONTROL
static volatile uint32_t decision_start, decision_end, decision_end_valid;
static volatile uint32_t decision_cycles, decision_calls;
PaperGateCycles gateway_paper_gate_take(void)
{
    taskENTER_CRITICAL();
    PaperGateCycles result={decision_cycles,decision_calls};
    decision_cycles=0;decision_calls=0;
    taskEXIT_CRITICAL();
    return result;
}
#endif

bool gateway_mediation_check(uint8_t kind, uint8_t *bytes, uint32_t length);

bool Mediation_Extern_check(uint8_t kind, uint32_t length, uint8_t *request,
                          uint8_t *policy, uint8_t *login, uint8_t *envelope)
{
#if defined(STM32F767xx) && GATEWAY_R4_FAULT_INJECT == 2
    gateway_r4_fault_before_validator(envelope);
#endif
    bool accepted=gateway_mediation_check(kind,envelope,length);
    if(accepted) gateway_audit_accept(kind,length,request,policy,login);
    return accepted;
}

uint8_t gateway_policy_update(uint8_t role, uint8_t count, uint8_t *body,
                              uint32_t paths[8], uint8_t masks[8],
                              uint8_t min_roles[8], uint16_t scopes[8],
                              uint8_t *num_rules);
static void pack_policy(uint8_t out[65], const Policy *in)
{
    memset(out,0,65); out[0]=in->num_rules;
    for(unsigned i=0;i<MAX_RULES;++i) {
        const PolicyRule *r=&in->rules[i]; uint8_t *b=out+1+8*i;
        b[0]=(uint8_t)r->path_hash; b[1]=(uint8_t)(r->path_hash>>8);
        b[2]=(uint8_t)(r->path_hash>>16); b[3]=(uint8_t)(r->path_hash>>24);
        b[4]=r->method; b[5]=r->min_role; b[6]=(uint8_t)r->req_scope;
        b[7]=(uint8_t)(r->req_scope>>8);
    }
}
static int message(GatewayContext *c, unsigned status, const char *text)
{
    GateResponse *out=(GateResponse *)c->gate;
    out->conn_id=0; out->status=(uint8_t)status;
    out->body_len=(uint32_t)strlen(text);
    memcpy(out->body,text,out->body_len);
    c->gate_len=GATE_RESPONSE_HEADER_SIZE+out->body_len;
    return status==GATE_STATUS_OK?200:403;
}

/* Trusted leaf semantics: this function acts on the exact snapshots supplied
 * to check, never on a second parsed request. No callback or snapshot escapes. */
uint32_t Mediation_Extern_invoke(uint8_t kind, uint32_t length, uint8_t *request,
                               uint8_t *policy, uint8_t *login, uint8_t *context)
{
#if GATEWAY_PAPER_CONTROL
    decision_end=DWT->CYCCNT;decision_end_valid=1;
#endif
    GatewayContext *c=(GatewayContext *)context;
    gateway_audit_effect(kind,length,request,policy,login,c);
    const SecurityParamsWire *p=(const SecurityParamsWire *)request;
    if(kind==GATEWAY_PUBLIC) {
        c->dispatch_count++; c->result=GATEWAY_DISPATCHED;
        return 200;
    }
    if(kind==GATEWAY_LOGIN) {
        GateResponse *out=(GateResponse *)c->gate;
        int status=gateway_login(p->body,p->body_len,(char *)out->body,
                                 sizeof(c->gate)-GATE_RESPONSE_HEADER_SIZE);
        out->conn_id=0; out->status=status==200?GATE_STATUS_OK:GATE_STATUS_NO_AUTH;
        out->body_len=(uint32_t)strlen((const char *)out->body);
        c->gate_len=GATE_RESPONSE_HEADER_SIZE+out->body_len;
        c->dispatch_count++; c->result=GATEWAY_DISPATCHED;
        return (uint32_t)status;
    }
    if(kind==GATEWAY_UPDATE) {
        /* Commit through the verified update gate: the rules are exactly those
         * the validated bytes encode. A disagreement with the check above
         * fails closed and leaves the live policy unchanged. */
        uint32_t paths[MAX_RULES]; uint8_t masks[MAX_RULES], roles[MAX_RULES], nr=0;
        uint16_t scopes[MAX_RULES];
        if(gateway_policy_update(p->role,p->rate_count,(uint8_t *)p->body,
                                 paths,masks,roles,scopes,&nr)!=1) {
            c->result=GATEWAY_DENIED;
            return (uint32_t)message(c,GATE_STATUS_DENIED,"{\"status\":\"denied\"}");
        }
        memset(&c->policy,0,sizeof(c->policy)); c->policy.num_rules=nr;
        for(unsigned i=0;i<MAX_RULES;++i)
            c->policy.rules[i]=(PolicyRule){paths[i],masks[i],roles[i],scopes[i]};
        c->result=GATEWAY_POLICY_UPDATED;
        return (uint32_t)message(c,GATE_STATUS_OK,"{\"status\":\"ok\",\"message\":\"policy updated\"}");
    }
    /* Single-owner execution preserves the policy snapshot during this call.
     * Access never writes policy; only the update branch commits a candidate. */
    AppRequest *app=(AppRequest *)c->app;
    app->conn_id=0; app->path_hash=p->path_hash; app->method=p->method;
    app->role=p->role; app->scope=p->scope; app->subject_id_len=p->subject_id_len;
    memcpy(app->subject_id,p->subject_id,SUBJECT_ID_MAX_APP);
    app->body_len=p->body_len; memcpy(app->body,p->body,p->body_len);
    c->app_len=APP_REQUEST_HEADER_SIZE+p->body_len; c->result=GATEWAY_FORWARD;
#ifdef STM32F767xx
    return gateway_r4_app_dispatch(c)?200:500;
#else
    return gateway_dispatch(c)?200:500;
#endif
}

int gateway_mediate(GatewayContext *c, unsigned kind)
{
    if(!gateway_guards_ok(c) || kind>GATEWAY_UPDATE ||
       c->security_len<SECPARAMS_HEADER_SIZE || c->security_len>sizeof(c->security)) return 500;
    const SecurityParamsWire *p=(const SecurityParamsWire *)c->security;
    if(p->body_len>MAX_INLINE_BODY || c->security_len!=SECPARAMS_HEADER_SIZE+p->body_len ||
       p->role>ROLE_ADMIN || p->subject_id_len>SUBJECT_ID_MAX || p->token_len>AUTH_TOKEN_MAX ||
       p->method<METHOD_GET || p->method>METHOD_HEAD ||
       (p->method & (p->method-1U))!=0U ||
       c->policy.num_rules<1 || c->policy.num_rules>8)
        return 400;
    bool public_route=(p->path_hash==GATEWAY_PATH_DASHBOARD || p->path_hash==GATEWAY_PATH_SCRIPT) && p->method==METHOD_GET;
    bool login_route=p->path_hash==PATH_LOGIN && p->method==METHOD_POST;
    bool update_route=p->path_hash==PATH_POLICY && p->method==METHOD_PUT;
    if((kind==GATEWAY_PUBLIC)!=public_route || (kind==GATEWAY_LOGIN)!=login_route ||
       (kind==GATEWAY_UPDATE)!=update_route) return 400;
    if(kind==GATEWAY_UPDATE && p->body_len!=65) return 403;
    if((kind==GATEWAY_ACCESS || kind==GATEWAY_UPDATE) && c->result!=GATEWAY_IDENTIFIED) return 500;
    if((kind==GATEWAY_PUBLIC || kind==GATEWAY_LOGIN) && c->result!=GATEWAY_EXTRACTED) return 500;
    /* No pointers in these snapshots. Their lifetime spans the synchronous call.
     * Scratch storage is explicit in the Low* contract and disjoint from ctx. */
    uint8_t request[1536], policy[65], login[106]={0}, envelope[106]={0};
    memcpy(request,c->security,sizeof(request)); pack_policy(policy,&c->policy);
    uint32_t length=kind==GATEWAY_UPDATE?70:75;
    if(kind==GATEWAY_LOGIN && !gateway_login_prepare(p->body,p->body_len,login,&length)) {
        gateway_clear(request,sizeof(request)); gateway_clear(login,sizeof(login));
        return 400;
    }
#if GATEWAY_PAPER_CONTROL
    decision_end_valid=0;decision_start=DWT->CYCCNT;
#endif
    Mediation_Wrapper_result result=Mediation_Wrapper_run((uint8_t)kind,length,request,policy,login,(uint8_t *)c,envelope);
#if GATEWAY_PAPER_CONTROL
    decision_cycles+=(decision_end_valid?decision_end:DWT->CYCCNT)-decision_start;
    ++decision_calls;
#endif
    gateway_clear(request,sizeof(request)); gateway_clear(login,sizeof(login)); gateway_clear(envelope,sizeof(envelope));
    if(!result.invoked) {
        c->result=GATEWAY_DENIED;
        bool limited=p->rate_count>=MAX_RATE;
        message(c,limited?GATE_STATUS_RATE_LIMITED:GATE_STATUS_DENIED,
                limited?"{\"status\":\"rate_limited\"}":"{\"status\":\"denied\"}");
        return limited?429:403;
    }
    return (int)result.status;
}
