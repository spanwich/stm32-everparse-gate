/* Windowed rate-limit self-test. Drives the full gateway_http_process path with a
 * synthetic interface clock (gateway_clock_synthetic), so the verified windowed
 * counter (GlueRate, N_max = 50, 49 ms window) is exercised deterministically on
 * both the host and the real build: 49 requests in one window are admitted, the
 * 50th (and later ones in the same window) are refused, and the first request in
 * the next window is admitted again. The counter is one interface-wide state, so
 * these requests must NOT reset it per request (unlike the other suites); the
 * synthetic clock is restored to the real tick at the end. */
#include "gateway_http.h"
#include "gateway_glue.h"
#include "gateway_core.h"
#include "gateway_tests.h"
#include <string.h>
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

void gateway_test_rate(GatewayTestStats *s)
{
#define CHECK(n,x) gateway_test_check(s,n,(x))
#if !GATEWAY_LAB_AUTH
    (void)s; (void)rate_request;
    return;   /* no bearer identity without lab auth */
#else
    gateway_clock_synthetic(100000U);   /* hold time inside one window */
    gateway_rate_state_init();          /* start a fresh window */
    int admitted=1;
    for(int i=1;i<=49;++i) admitted &= (rate_request()==200);
    CHECK("Rate: 49 requests in one window admitted",admitted);
    CHECK("Rate: 50th request in the window refused",rate_request()==429);
    CHECK("Rate: still refused later in the same window",rate_request()==429);
    gateway_clock_synthetic(100000U+49U); /* exactly one 49 ms window later */
    CHECK("Rate: first request in the next window admitted",rate_request()==200);
    gateway_clock_real();               /* restore the live tick for real serving */
#endif
#undef CHECK
}
