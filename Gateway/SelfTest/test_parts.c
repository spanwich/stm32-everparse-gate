/* Partition-indexed policy API on the 64-partition live store: PUT/GET /api/policy
 * with the ?part=J selector. The range check 1 <= J <= N for updates is the verified
 * GlueLowMediate's; readback range-checks in the adapter; malformed or duplicated
 * selectors are rejected by the handwritten HTTP adapter before the gate. */
#include "gateway_http.h"
#include "gateway_glue.h"
#include "gateway_routes.h"
#include "gateway_tests.h"
#include <stdio.h>
#include <string.h>
extern GatewayContext gateway_test_context;
extern GatewayHttp gateway_http_fixture;

static int part_request(const char *method,const char *target,const char *token,const uint8_t *body,size_t length)
{
    GatewayContext *c=&gateway_test_context;GatewayHttp *h=&gateway_http_fixture;
    char head[320];gateway_begin_request(c);gateway_http_init(h);
    gateway_rate_state_init();   /* the windowed limit is exercised by gateway_test_rate */
    int n=snprintf(head,sizeof(head),"%s %s HTTP/1.1\r\nHost: board\r\n%s%s%sContent-Length: %lu\r\n\r\n",
        method,target,token?"Authorization: Bearer ":"",token?token:"",token?"\r\n":"",(unsigned long)length);
    if(n<0 || (size_t)n>=sizeof(head))return 500;
    int r=0;
    for(int i=0;i<n && r<=1;++i) r=gateway_http_feed(h,c,head+i,1);
    if(r>1)return r;
    if(length)r=gateway_http_feed(h,c,body,length);
    return r==1?gateway_http_process(h,c):r;
}
/* One-rule partition body; the other seven slots are the inactive sentinel. */
static void one_rule(uint8_t out[65],uint32_t path,uint8_t method,uint8_t role,uint16_t scope)
{
    memset(out,0,65);out[0]=1;
    for(unsigned i=0;i<8;++i) {
        uint8_t *b=out+1+8*i;uint32_t p=i?0xDEADDEADu:path;
        for(unsigned j=0;j<4;++j)b[j]=(uint8_t)(p>>(8*j));
        if(!i){b[4]=method;b[5]=role;b[6]=(uint8_t)scope;b[7]=(uint8_t)(scope>>8);}
    }
}
static bool same_part(uint32_t part,const Policy *want)
{
    Policy got;
    return gateway_glue_store_to_policy(&got,part,0) && !memcmp(got.rules,want->rules,sizeof(got.rules));
}
void gateway_test_parts(GatewayTestStats *s)
{
#define CHECK(n,x) gateway_test_check(s,n,(x))
    GatewayContext *c=&gateway_test_context;gateway_init(c);
    gateway_policy_store_load(&c->policy);
#if !GATEWAY_LAB_AUTH
    return;
#endif
    const char *body_of=(const char *)c->gate+GATE_RESPONSE_HEADER_SIZE;
    uint8_t body[65];Policy before1,before64,empty;
    CHECK("Geometry: 64 partitions of 8 slots",GATEWAY_LIVE_PARTS==64U && GATEWAY_LIVE_SLOTS==512U);
    CHECK("Default part=1 readback has the gateway routes",part_request("GET","/api/policy","pg-lab-admin",NULL,0)==200 && strstr(body_of,"1431655765"));
    CHECK("Explicit part=1 equals default",part_request("GET","/api/policy?part=1","pg-lab-admin",NULL,0)==200 && strstr(body_of,"1431655765"));
    CHECK("Partition 2..64 start inactive",part_request("GET","/api/policy?part=64","pg-lab-admin",NULL,0)==200 && strstr(body_of,"3735936685"));
    (void)gateway_glue_store_to_policy(&before1,1,0);(void)gateway_glue_store_to_policy(&before64,64,0);
    (void)gateway_glue_store_to_policy(&empty,2,0);
    /* Install into an interior and the last partition through the verified update gate. */
    one_rule(body,0x12345678u,METHOD_GET,ROLE_OPERATOR,1);
    CHECK("Admin installs partition 5",part_request("PUT","/api/policy?part=5","pg-lab-admin",body,65)==200);
    CHECK("Partition 5 readback shows the rule",part_request("GET","/api/policy?part=5","pg-lab-admin",NULL,0)==200 && strstr(body_of,"305419896"));
    CHECK("Partition 1 untouched by the partition 5 write",same_part(1,&before1) && part_request("GET","/api/policy","pg-lab-admin",NULL,0)==200 && !strstr(body_of,"305419896"));
    one_rule(body,GATEWAY_PATH_DEMO,METHOD_GET,ROLE_OPERATOR,0);
    CHECK("Operator /demo denied before the last-partition rule",part_request("GET","/demo","pg-lab-operator",NULL,0)==403);
    CHECK("Admin installs partition 64 (last)",part_request("PUT","/api/policy?part=64","pg-lab-admin",body,65)==200);
    CHECK("Decision scans to partition 64: operator /demo now allowed",part_request("GET","/demo","pg-lab-operator",NULL,0)==200);
    CHECK("Zero-padded part number accepted",part_request("GET","/api/policy?part=005","pg-lab-admin",NULL,0)==200 && strstr(body_of,"305419896"));
    CHECK("Other query params are ignored",part_request("GET","/api/policy?q=1&part=5&next=/x","pg-lab-admin",NULL,0)==200 && strstr(body_of,"305419896"));
    CHECK("part is ignored on other routes",part_request("GET","/api/status?part=zzz","pg-lab-operator",NULL,0)==200);
    /* Negative selectors. Update range check is the verified glue's. */
    Policy before5,after64;(void)gateway_glue_store_to_policy(&before5,5,0);(void)gateway_glue_store_to_policy(&after64,64,0);
    one_rule(body,0x0BADF00Du,METHOD_GET,ROLE_OPERATOR,1);
    CHECK("PUT part=0 rejected, store unchanged",part_request("PUT","/api/policy?part=0","pg-lab-admin",body,65)==403 && same_part(1,&before1) && same_part(5,&before5));
    CHECK("PUT part=65 (N+1) rejected, store unchanged",part_request("PUT","/api/policy?part=65","pg-lab-admin",body,65)==403 && same_part(1,&before1) && same_part(64,&after64) && same_part(5,&before5));
    CHECK("PUT part=4294967296 rejected",part_request("PUT","/api/policy?part=4294967296","pg-lab-admin",body,65)==400);
    CHECK("PUT part=abc rejected (400)",part_request("PUT","/api/policy?part=abc","pg-lab-admin",body,65)==400 && same_part(1,&before1));
    CHECK("PUT part= (empty) rejected (400)",part_request("PUT","/api/policy?part=","pg-lab-admin",body,65)==400);
    CHECK("PUT part (no value) rejected (400)",part_request("PUT","/api/policy?part","pg-lab-admin",body,65)==400);
    CHECK("PUT part=-1 rejected (400)",part_request("PUT","/api/policy?part=-1","pg-lab-admin",body,65)==400);
    CHECK("PUT part=2x rejected (400)",part_request("PUT","/api/policy?part=2x","pg-lab-admin",body,65)==400);
    CHECK("PUT duplicate part rejected (400), store unchanged",part_request("PUT","/api/policy?part=2&part=3","pg-lab-admin",body,65)==400 && same_part(2,&empty));
    CHECK("PUT duplicate identical part rejected (400)",part_request("PUT","/api/policy?part=2&part=2","pg-lab-admin",body,65)==400);
    CHECK("Operator cannot write any partition",part_request("PUT","/api/policy?part=6","pg-lab-operator",body,65)==403 && same_part(6,&empty));
    CHECK("GET part=0 denied",part_request("GET","/api/policy?part=0","pg-lab-admin",NULL,0)==403);
    CHECK("GET part=65 denied",part_request("GET","/api/policy?part=65","pg-lab-admin",NULL,0)==403);
    CHECK("GET part=abc rejected (400)",part_request("GET","/api/policy?part=abc","pg-lab-admin",NULL,0)==400);
    CHECK("Operator cannot read a partition",part_request("GET","/api/policy?part=5","pg-lab-operator",NULL,0)==403);
    /* Provisioning: all 64 partitions through the verified update gate. */
    bool all=true;
    for(uint32_t j=2;j<=64;++j) {
        char t[40];snprintf(t,sizeof(t),"/api/policy?part=%lu",(unsigned long)j);
        one_rule(body,0x20000000u+j,METHOD_GET,ROLE_ADMIN,0);
        all &= part_request("PUT",t,"pg-lab-admin",body,65)==200;
    }
    CHECK("All 63 non-gateway partitions provisioned",all);
    CHECK("Provisioned partition 33 reads back",part_request("GET","/api/policy?part=33","pg-lab-admin",NULL,0)==200 && strstr(body_of,"536870945"));
    CHECK("Gateway routes (partition 1) still reachable after provisioning",part_request("GET","/api/policy","pg-lab-admin",NULL,0)==200);
    gateway_init(c);
    gateway_policy_store_load(&c->policy);   /* leave the default store for later suites */
#undef CHECK
}
