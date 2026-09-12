#include "gateway_http.h"
#include "gateway_routes.h"
#include "gateway_tests.h"
#include <stdio.h>
#include <string.h>
extern GatewayContext gateway_test_context;
extern GatewayHttp gateway_http_fixture;
static int request(const char *method,const char *path,const char *token,const uint8_t *body,size_t length)
{
    GatewayContext *c=&gateway_test_context;GatewayHttp *h=&gateway_http_fixture;
    char head[256];gateway_begin_request(c);gateway_http_init(h);
    int n=snprintf(head,sizeof(head),"%s %s HTTP/1.1\r\nHost: board\r\n%s%s%sContent-Length: %lu\r\n\r\n",
        method,path,token?"Authorization: Bearer ":"",token?token:"",token?"\r\n":"",(unsigned long)length);
    if(n<0 || (size_t)n>=sizeof(head))return 500;
    int r=0;
    for(int i=0;i<n && r<=1;++i) r=gateway_http_feed(h,c,head+i,1);
    if(r>1)return r;
    if(length)r=gateway_http_feed(h,c,body,length);
    return r==1?gateway_http_process(h,c):r;
}
static void encode(const Policy *p,uint8_t out[65])
{
    memset(out,0,65);out[0]=p->num_rules;
    for(unsigned i=0;i<p->num_rules;++i) {
        const PolicyRule *r=&p->rules[i];unsigned n=1+8*i;
        for(unsigned j=0;j<4;++j)out[n+j]=(uint8_t)(r->path_hash>>(8*j));
        out[n+4]=r->method;out[n+5]=r->min_role;out[n+6]=(uint8_t)r->req_scope;out[n+7]=(uint8_t)(r->req_scope>>8);
    }
}
void gateway_test_live_policy(GatewayTestStats *s)
{
#define CHECK(n,x) gateway_test_check(s,n,(x))
    GatewayContext *c=&gateway_test_context;gateway_init(c);
    CHECK("Public JavaScript with fragmented headers",request("GET","/dashboard.js",NULL,NULL,0)==200 && gateway_http_fixture.script);
    CHECK("Demo GET requires authentication",request("GET","/demo",NULL,NULL,0)==401);
    CHECK("Demo rejects non-GET",request("POST","/demo",NULL,NULL,0)==400);
    CHECK("Demo alias is exact",request("GET","/demo?other",NULL,NULL,0)==400);
#if !GATEWAY_LAB_AUTH
    CHECK("Disabled auth denies demo",request("GET","/demo","pg-lab-admin",NULL,0)==401);
    return;
#endif
    CHECK("Operator demo denied by default",request("GET","/demo","pg-lab-operator",NULL,0)==403 && c->app_len==0);
    CHECK("Admin demo allowed",request("GET","/demo","pg-lab-admin",NULL,0)==200 && strstr((char *)c->gate+GATE_RESPONSE_HEADER_SIZE,"Policy gate demo"));
    CHECK("Demo has distinct integration route ID",((SecurityParamsWire *)c->security)->path_hash==GATEWAY_PATH_DEMO);
    CHECK("Status remains allowed independently",request("GET","/api/status","pg-lab-operator",NULL,0)==200 && ((SecurityParamsWire *)c->security)->path_hash==PATH_STATUS);
    CHECK("Operator cannot inspect policy",request("GET","/api/policy","pg-lab-operator",NULL,0)==403);
    CHECK("Admin reads actual rules",request("GET","/api/policy","pg-lab-admin",NULL,0)==200 && strstr((char *)c->gate+GATE_RESPONSE_HEADER_SIZE,"1431655765"));
    uint8_t body[65];Policy desired=c->policy, before=c->policy;desired.rules[3].min_role=ROLE_OPERATOR;encode(&desired,body);
    CHECK("Operator cannot change live policy",request("PUT","/api/policy","pg-lab-operator",body,65)==403 && !memcmp(&before,&c->policy,sizeof(before)));
    CHECK("Admin enables operator demo",request("PUT","/api/policy","pg-lab-admin",body,65)==200);
    CHECK("Operator demo succeeds immediately",request("GET","/demo","pg-lab-operator",NULL,0)==200 && c->result==GATEWAY_DISPATCHED);
    CHECK("Demo still enforces rate predicate",request("GET","/demo","pg-lab-limited",NULL,0)==429 && c->app_len==0);
    body[1+3*8+5]=ROLE_ADMIN;
    CHECK("Admin disables operator demo",request("PUT","/api/policy","pg-lab-admin",body,65)==200);
    CHECK("Operator demo denied immediately",request("GET","/demo","pg-lab-operator",NULL,0)==403 && c->app_len==0);
    CHECK("Admin retains demo access",request("GET","/demo","pg-lab-admin",NULL,0)==200);
    body[1+0*8+5]=ROLE_ADMIN;
    CHECK("Admin disables operator status",request("PUT","/api/policy","pg-lab-admin",body,65)==200);
    CHECK("Operator status denied",request("GET","/api/status","pg-lab-operator",NULL,0)==403);
    CHECK("Admin status remains allowed",request("GET","/api/status","pg-lab-admin",NULL,0)==200);
    CHECK("Policy readback reflects edited role",request("GET","/api/policy","pg-lab-admin",NULL,0)==200 && strstr((char *)c->gate+GATE_RESPONSE_HEADER_SIZE,"\"id\":858993459,\"method\":1,\"min_role\":2"));
    CHECK("Live policy integration guards",gateway_guards_ok(c));
    gateway_init(c);
#undef CHECK
}
