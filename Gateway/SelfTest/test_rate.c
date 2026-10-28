/* Windowed rate-limit self-test. Drives the full gateway_http_process path with a
 * synthetic interface clock (gateway_clock_synthetic), so the verified windowed
 * counter (GlueRate, N_max = 50, 49 ms window) is exercised deterministically on
 * both the host and the real build. It carries the attack suite's rate-limit class
 * (20 distinct over-limit cases: the 50th..69th request inside one window) plus an
 * over-limit policy update that must be refused with the policy unchanged, so the
 * network attack suites keep only their nine ~60 req/s classes. Requests here must
 * NOT reset the counter per request (unlike the other suites); the synthetic clock
 * is restored to the real tick at the end. */
#include "gateway_http.h"
#include "gateway_glue.h"
#include "gateway_core.h"
#include "gateway_tests.h"
#include <string.h>
#include <stdio.h>
extern GatewayContext gateway_test_context;
extern GatewayHttp gateway_http_fixture;

/* One authenticated GET /api/status through the real path, WITHOUT resetting the
 * rate counter (so the window accumulates). The caller holds the synthetic clock. */
static int rate_request(void)
{
    GatewayContext *c=&gateway_test_context; GatewayHttp *h=&gateway_http_fixture;
    gateway_init(c); gateway_http_init(h);
    gateway_policy_store_load(&c->policy);
    static const char get[]="GET /api/status HTTP/1.1\r\nHost: b\r\nAuthorization: Bearer pg-lab-operator\r\n\r\n";
    int r=gateway_http_feed(h,c,get,sizeof(get)-1);
    return r==1?gateway_http_process(h,c):r;
}

/* A well-formed admin policy update issued WHILE over the window limit: the gate's
 * rate predicate (count<50) rejects it before any commit, so it must not return 200
 * and must leave the live policy unchanged. Does not reset the counter. */
static int rate_update_refused(void)
{
    GatewayContext *c=&gateway_test_context; GatewayHttp *h=&gateway_http_fixture;
    gateway_init(c); gateway_http_init(h);
    gateway_policy_store_load(&c->policy);
    Policy before=c->policy;
    uint8_t body[65]={0}; body[0]=1;           /* one well-formed rule */
    body[1]=0x11;body[2]=0x11;body[3]=0x11;body[4]=0x11;
    body[5]=1; body[6]=1; body[7]=1;           /* GET, min_role operator, scope 1 */
    char head[160];
    int n=snprintf(head,sizeof(head),"PUT /api/policy HTTP/1.1\r\nHost: b\r\n"
                   "Authorization: Bearer pg-lab-admin\r\nContent-Length: 65\r\n\r\n");
    int r=gateway_http_feed(h,c,head,(size_t)n);
    if(r<=0) r=gateway_http_feed(h,c,body,sizeof(body));
    int status=r==1?gateway_http_process(h,c):r;
    return status!=200 && memcmp(&before,&c->policy,sizeof(before))==0;
}

void gateway_test_rate(GatewayTestStats *s)
{
#define CHECK(n,x) gateway_test_check(s,n,(x))
#if !GATEWAY_LAB_AUTH
    (void)s; (void)rate_request; (void)rate_update_refused;
    return;   /* no bearer identity without lab auth */
#else
    gateway_clock_synthetic(100000U);   /* hold time inside one window */
    gateway_rate_state_init();          /* start a fresh window */
    int admitted=1;
    for(int i=1;i<=49;++i) admitted &= (rate_request()==200);
    CHECK("Rate: 49 requests in one window admitted",admitted);
    /* The attack suite's rate-limit class: 20 distinct over-limit cases, the
     * 50th..69th request inside the same window, each refused (HTTP 429). */
    for(int i=50;i<=69;++i) {
        char name[52]; snprintf(name,sizeof(name),"Rate: over-limit request %d refused (429)",i);
        CHECK(name, rate_request()==429);
    }
    /* A policy update while over the limit is refused and leaves the policy. */
    CHECK("Rate: over-limit policy update refused, policy unchanged", rate_update_refused());
    gateway_clock_synthetic(100000U+49U); /* exactly one 49 ms window later */
    CHECK("Rate: first request in the next window admitted",rate_request()==200);
    gateway_clock_real();               /* restore the live tick for real serving */
#endif
#undef CHECK
}
