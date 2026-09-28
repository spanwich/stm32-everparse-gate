#include "gateway_mediation.h"
#include "gateway_tests.h"
#include "gateway_routes.h"
#include <string.h>
extern GatewayContext gateway_test_context;
static SecurityParamsWire *prepare(uint32_t path,uint8_t method,uint8_t role)
{
    GatewayContext *c=&gateway_test_context;
    gateway_init(c);c->security_len=SECPARAMS_HEADER_SIZE;
    c->result=role?GATEWAY_IDENTIFIED:GATEWAY_EXTRACTED;
    SecurityParamsWire *p=(SecurityParamsWire *)c->security;
    p->path_hash=path;p->method=method;p->role=role;p->scope=7;
    return p;
}
void gateway_test_mediation(GatewayTestStats *s)
{
#define CHECK(n,x) gateway_test_check(s,n,(x))
    GatewayContext *c=&gateway_test_context;
    prepare(GATEWAY_PATH_DASHBOARD,METHOD_GET,0);
    CHECK("Mediation public handler explicitly admitted",gateway_mediate(c,GATEWAY_PUBLIC)==200 && c->dispatch_count==1);
    CHECK("Mediation public invocation consumed",gateway_mediate(c,GATEWAY_PUBLIC)==500 && c->dispatch_count==1);
    prepare(PATH_STATUS,METHOD_GET,0);
    CHECK("Mediation public class cannot select API",gateway_mediate(c,GATEWAY_PUBLIC)==400 && c->dispatch_count==0);
    prepare(GATEWAY_PATH_SCRIPT,METHOD_POST,0);
    CHECK("Mediation public method restricted",gateway_mediate(c,GATEWAY_PUBLIC)==400 && c->dispatch_count==0);
    prepare(PATH_STATUS,METHOD_GET,ROLE_OPERATOR);
    c->policy.num_rules=1;c->policy.rules[0]=(PolicyRule){PATH_LOGOUT,METHOD_POST,ROLE_OPERATOR,0};
    c->policy.rules[1]=(PolicyRule){PATH_STATUS,METHOD_GET,ROLE_OPERATOR,0};
    Policy old=c->policy;
    CHECK("Mediation inactive matching rule denied",gateway_mediate(c,GATEWAY_ACCESS)==403 && c->dispatch_count==0 && !memcmp(&old,&c->policy,sizeof(old)));
    CHECK("Mediation denied decision cannot dispatch",!gateway_dispatch(c));
    SecurityParamsWire *p=prepare(PATH_POLICY,METHOD_PUT,ROLE_OPERATOR);
    p->body_len=65;c->security_len+=65;memset(p->body,0,65);p->body[0]=1;
    old=c->policy;
    CHECK("Mediation operator cannot commit candidate",gateway_mediate(c,GATEWAY_UPDATE)==403 && !memcmp(&old,&c->policy,sizeof(old)));
    p=prepare(PATH_POLICY,METHOD_PUT,ROLE_ADMIN);
    p->body_len=65;c->security_len+=65;memset(p->body,0,65);p->body[0]=1;
    memset(p->body+1,0x55,4);p->body[5]=METHOD_GET;p->body[6]=ROLE_OPERATOR;
    CHECK("Mediation commits exact active candidate",gateway_mediate(c,GATEWAY_UPDATE)==200 && c->policy.num_rules==1 &&
          c->policy.rules[0].path_hash==GATEWAY_PATH_DEMO && c->policy.rules[0].min_role==ROLE_OPERATOR);
    CHECK("Mediation policy transaction consumed",gateway_mediate(c,GATEWAY_UPDATE)==500);
    prepare(PATH_LOGIN,METHOD_POST,0);
    CHECK("Mediation malformed login has no effect",gateway_mediate(c,GATEWAY_LOGIN)==400 && c->dispatch_count==0);
#undef CHECK
}
