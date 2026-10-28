#include "gateway_http.h"
#include "gateway_glue.h"
#include "gateway_tests.h"
#include <string.h>
#include <stdio.h>
extern GatewayContext gateway_test_context;
GatewayHttp gateway_http_fixture;
static uint8_t request[4096];
static int execute(const void *p,size_t n,size_t split)
{
    GatewayContext *c=&gateway_test_context; GatewayHttp *h=&gateway_http_fixture;
    gateway_init(c); gateway_http_init(h);
    /* The access/update decision reads the live store; load it from this
     * request's default policy so each request starts from the default. */
    gateway_policy_store_load(&c->policy);
    int r=gateway_http_feed(h,c,p,split);
    if(!r) r=gateway_http_feed(h,c,(const uint8_t *)p+split,n-split);
    return r==1?gateway_http_process(h,c):r;
}
void gateway_test_http(GatewayTestStats *s)
{
#define CHECK(n,x) gateway_test_check(s,n,(x))
    const char *get="GET /api/status HTTP/1.1\r\nHost: board\r\nAuthorization: Bearer pg-lab-operator\r\n\r\n";
#if !GATEWAY_LAB_AUTH
    GatewayIdentity disabled_identity; uint8_t disabled_rate;
    CHECK("Lab authentication disabled rejects known token",!gateway_bearer_check((const uint8_t *)"pg-lab-admin",12,&disabled_identity,&disabled_rate) && !disabled_identity.valid);
    CHECK("Lab authentication disabled returns HTTP 401",execute(get,strlen(get),0)==401);
    return;
#endif
    size_t n=strlen(get); int ok=1;
    for(size_t i=0;i<=n;++i) ok &= execute(get,n,i)==200;
    CHECK("HTTP every two-fragment split",ok);
    gateway_init(&gateway_test_context); gateway_http_init(&gateway_http_fixture);
    ok=1;
    for(size_t i=0;i<n;++i) ok &= gateway_http_feed(&gateway_http_fixture,&gateway_test_context,get+i,1)==(i+1==n?1:0);
    CHECK("HTTP byte fragments",ok && gateway_http_process(&gateway_http_fixture,&gateway_test_context)==200);
    CHECK("HTTP processing cannot replay",gateway_http_process(&gateway_http_fixture,&gateway_test_context)==400);
    const struct {const char *text; int status;} cases[]={
      {"GET /api/status HTTP/1.1\r\nHost: b\r\naUtHoRiZaTiOn:\t bEaReR   pg-lab-operator \t\r\n\r\n",200},
      {"GET /api/status HTTP/1.0\r\nAuthorization: Bearer pg-lab-admin\r\n\r\n",200},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\n\r\n",401},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer invalid\r\n\r\n",401},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer pg-lab-operatorX\r\n\r\n",401},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer PG-LAB-OPERATOR\r\n\r\n",401},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer pg-lab-limited\r\n\r\n",429},
      {"GET /api/policy HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer pg-lab-operator\r\n\r\n",403},
      {"GET /api/policy HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer pg-lab-admin\r\n\r\n",200},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer pg-lab-admin\r\nAuthorization: Bearer pg-lab-operator\r\n\r\n",400},
      {"GET /api/status?api/policy HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer pg-lab-operator\r\n\r\n",200},
      {"GET /api/login?next=/api/policy HTTP/1.1\r\nHost: b\r\n\r\n",401},
      {"GET /api/status#policy HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer pg-lab-operator\r\n\r\n",400},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",400},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\nTransfer-Encoding: chunked\r\n\r\n",400},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\nExpect: 100-continue\r\n\r\n",417},
      {"POST /api/logout HTTP/1.1\r\nHost: b\r\n\r\n",400},
      {"POST /api/logout HTTP/1.1\r\nHost: b\r\nContent-Length: -1\r\n\r\n",400},
      {"POST /api/logout HTTP/1.1\r\nHost: b\r\nContent-Length: 1362\r\n\r\n",413},
      {"POST /api/logout HTTP/1.1\r\nHost: b\r\nContent-Length: 999999999999999\r\n\r\n",413},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\nContent-Length: 1\r\n\r\nx",400},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\n Folded: invalid\r\n\r\n",400},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\nAuthorization : Bearer pg-lab-admin\r\n\r\n",400},
      {"GET /api/status HTTP/1.1\r\n\r\n",400},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\nHost: b\r\n\r\n",400},
      {"GET /api/status HTTP/1.1\r\nHost: b\r\n\r\nextra",400},
      {"GET /api/status HTTP/2.0\r\nHost: b\r\n\r\n",400}
    };
    for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
        char name[48]; snprintf(name,sizeof(name),"HTTP framing/auth case %u",i+1);
        CHECK(name,execute(cases[i].text,strlen(cases[i].text),0)==cases[i].status);
    }
    int z=snprintf((char *)request,sizeof(request),"POST /api/logout HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer pg-lab-operator\r\ncOnTeNt-LeNgTh:\t1361 \r\n\r\n");
    memset(request+z,0,1361);
    CHECK("HTTP maximum binary body",execute(request,(size_t)z+1361,(size_t)z+100)==200 && gateway_guards_ok(&gateway_test_context));
    gateway_init(&gateway_test_context); gateway_http_init(&gateway_http_fixture);
    CHECK("HTTP incomplete body waits",gateway_http_feed(&gateway_http_fixture,&gateway_test_context,request,(size_t)z+1360)==0);
    memset(request,'A',sizeof(request));
    CHECK("HTTP 4096 unterminated header",execute(request,sizeof(request),2000)==413);
    z=snprintf((char *)request,sizeof(request),"GET /api/status HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer ");
    memset(request+z,'A',129); memcpy(request+z+129,"\r\n\r\n",4);
    CHECK("HTTP overlong bearer rejected",execute(request,(size_t)z+133,0)==401);
    z=snprintf((char *)request,sizeof(request),"PUT /api/policy HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer pg-lab-admin\r\nContent-Length: 65\r\n\r\n");
    memset(request+z,0,65); request[z]=1;
    uint32_t path=PATH_STATUS;
    for(unsigned i=0;i<4;++i) request[z+1+i]=(uint8_t)(path>>(8*i));
    request[z+5]=METHOD_GET; request[z+6]=ROLE_OPERATOR; request[z+7]=1;
    CHECK("HTTP binary admin policy update",execute(request,(size_t)z+65,(size_t)z+3)==200 && gateway_test_context.policy.num_rules==1);
    GatewayIdentity id; uint8_t rate;
    CHECK("Bearer failed lookup clears identity",!gateway_bearer_check((const uint8_t *)"bad",3,&id,&rate) && !id.valid && id.role==0 && rate==0);
    char response[256]; int len=gateway_http_response_header(response,sizeof(response),401,2);
    CHECK("HTTP response framing and challenge",len>0 && strstr(response,"Content-Length: 2\r\n") && strstr(response,"WWW-Authenticate: Bearer"));
    CHECK("HTTP response small buffer fails",gateway_http_response_header(response,8,200,2)==-1);
#undef CHECK
}
