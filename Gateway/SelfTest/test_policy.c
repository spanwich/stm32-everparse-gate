/* Separate translation unit: EverParse runtime never shares an extractor TU. */
#include "gateway_core.h"
#include "gateway_tests.h"
#include "../Generated/Policy/RbacPolicyWrapper.h"
#include <stdio.h>
#include <string.h>
extern GatewayContext gateway_test_context;
#define ctx gateway_test_context
#define CHECK(name, condition) gateway_test_check(s, name, (condition))
static void put32(uint8_t *p, uint32_t n)
{ p[0] = (uint8_t)n; p[1] = (uint8_t)(n >> 8); p[2] = (uint8_t)(n >> 16); p[3] = (uint8_t)(n >> 24); }
static void identify(uint8_t role, uint16_t scope, uint8_t rate)
{
    GatewayIdentity id = {.valid = true, .role = role, .scope = scope, .subject_len = 1, .subject = {'t'}};
    (void)gateway_set_identity(&ctx, &id, rate);
}
static void start(const char *method, const char *path, uint8_t role, uint16_t scope, uint8_t rate)
{
    gateway_begin_request(&ctx);
    ctx.request_len = (uint32_t)snprintf((char *)ctx.request, sizeof(ctx.request), "%s %s HTTP/1.1\r\n\r\n", method, path);
    (void)gateway_extract(&ctx); identify(role, scope, rate);
}
static void update(uint8_t role, uint8_t rate, uint8_t count, uint8_t method, uint8_t min_role, uint32_t body_len)
{
    gateway_begin_request(&ctx);
    int head = snprintf((char *)ctx.request, sizeof(ctx.request), "PUT /api/policy HTTP/1.1\r\nContent-Length: %lu\r\n\r\n", (unsigned long)body_len);
    uint8_t *body = ctx.request + head;
    memset(body, 0, body_len);
    body[0] = count;
    put32(body + 1, PATH_STATUS); body[5] = method; body[6] = min_role; body[7] = 1;
    /* The reference engine evaluates all eight stored slots, regardless of num_rules. */
    put32(body + 9, PATH_POLICY); body[13] = METHOD_GET; body[14] = ROLE_NONE;
    ctx.request_len = (uint32_t)head + body_len;
    (void)gateway_extract(&ctx); identify(role, 0xFFFF, rate);
}
void gateway_test_policy(GatewayTestStats *s)
{
    gateway_test_printf("=== Policy and dispatch boundaries ===\n");
    gateway_init(&ctx);
    start("GET", "/api/status", ROLE_OPERATOR, 1, 49);
    CHECK("operator sensor read allowed at 49", gateway_evaluate(&ctx) == GATEWAY_FORWARD && ctx.app_len == APP_REQUEST_HEADER_SIZE && ctx.gate_len == 0);
    CHECK("authorized dispatch occurs once", gateway_dispatch(&ctx) && ctx.dispatch_count == 1 && ctx.result == GATEWAY_DISPATCHED);
    CHECK("status response matches reference", strstr((char *)ctx.gate + GATE_RESPONSE_HEADER_SIZE, "OPERATOR") != NULL);
    CHECK("forward result cannot be replayed", !gateway_dispatch(&ctx) && ctx.dispatch_count == 1);
    start("GET", "/api/status", ROLE_OPERATOR, 1, 50);
    CHECK("rate 50 denied", gateway_evaluate(&ctx) == GATEWAY_DENIED && ctx.gate[1] == GATE_STATUS_RATE_LIMITED);
    CHECK("rate denial cannot dispatch", !gateway_dispatch(&ctx) && ctx.dispatch_count == 1 && ctx.app_len == 0);
    start("GET", "/api/status", ROLE_NONE, 1, 1);
    CHECK("insufficient role denied", gateway_evaluate(&ctx) == GATEWAY_DENIED);
    start("GET", "/api/status", ROLE_ADMIN, 0, 1);
    CHECK("admin still requires scope", gateway_evaluate(&ctx) == GATEWAY_DENIED);
    start("POST", "/api/status", ROLE_ADMIN, 0xFFFF, 1);
    CHECK("wrong method denied", gateway_evaluate(&ctx) == GATEWAY_DENIED);
    start("GET", "/api/login", ROLE_ADMIN, 0xFFFF, 1);
    CHECK("unmatched path denied by policy", gateway_evaluate(&ctx) == GATEWAY_DENIED);
    start("GET", "/api/policy", ROLE_OPERATOR, 4, 1);
    CHECK("policy read requires admin", gateway_evaluate(&ctx) == GATEWAY_DENIED);
    start("GET", "/api/policy", ROLE_ADMIN, 4, 1);
    CHECK("admin policy read allowed", gateway_evaluate(&ctx) == GATEWAY_FORWARD);
    CHECK("policy read response", gateway_dispatch(&ctx) && strstr((char *)ctx.gate + GATE_RESPONSE_HEADER_SIZE, "policy read ok") != NULL);
    start("POST", "/api/logout", ROLE_OPERATOR, 0, 1);
    CHECK("zero-scope rule allowed", gateway_evaluate(&ctx) == GATEWAY_FORWARD);
    start("GET", "/api/status", ROLE_ADMIN, 0xFFFF, 1);
    ctx.policy.rules[0].req_scope = 3;
    CHECK("all requested scope bits allowed", gateway_evaluate(&ctx) == GATEWAY_FORWARD);
    start("GET", "/api/status", ROLE_ADMIN, 1, 1);
    CHECK("partial scope mask denied", gateway_evaluate(&ctx) == GATEWAY_DENIED);
    gateway_init(&ctx);
    Policy before = ctx.policy;
    update(ROLE_OPERATOR, 1, 1, METHOD_GET, ROLE_OPERATOR, 65);
    CHECK("non-admin policy update denied", gateway_evaluate(&ctx) == GATEWAY_DENIED && memcmp(&before, &ctx.policy, sizeof(before)) == 0);
    update(ROLE_ADMIN, 50, 1, METHOD_GET, ROLE_OPERATOR, 65);
    CHECK("rate-limited policy update unchanged", gateway_evaluate(&ctx) == GATEWAY_DENIED && memcmp(&before, &ctx.policy, sizeof(before)) == 0);
    update(ROLE_ADMIN, 1, 0, METHOD_GET, ROLE_OPERATOR, 65);
    CHECK("zero rules rejected unchanged", gateway_evaluate(&ctx) == GATEWAY_DENIED && memcmp(&before, &ctx.policy, sizeof(before)) == 0);
    update(ROLE_ADMIN, 1, 9, METHOD_GET, ROLE_OPERATOR, 65);
    CHECK("nine rules rejected unchanged", gateway_evaluate(&ctx) == GATEWAY_DENIED && memcmp(&before, &ctx.policy, sizeof(before)) == 0);
    update(ROLE_ADMIN, 1, 1, 0x40, ROLE_OPERATOR, 65);
    CHECK("invalid rule method rejected unchanged", gateway_evaluate(&ctx) == GATEWAY_DENIED && memcmp(&before, &ctx.policy, sizeof(before)) == 0);
    update(ROLE_ADMIN, 1, 1, METHOD_GET, 3, 65);
    CHECK("invalid rule role rejected unchanged", gateway_evaluate(&ctx) == GATEWAY_DENIED && memcmp(&before, &ctx.policy, sizeof(before)) == 0);
    update(ROLE_ADMIN, 1, 1, METHOD_GET, ROLE_OPERATOR, 64);
    CHECK("short policy body rejected unchanged", gateway_evaluate(&ctx) == GATEWAY_DENIED && memcmp(&before, &ctx.policy, sizeof(before)) == 0);
    update(ROLE_ADMIN, 1, 1, METHOD_GET, ROLE_OPERATOR, 66);
    CHECK("trailing policy bytes rejected unchanged", gateway_evaluate(&ctx) == GATEWAY_DENIED && memcmp(&before, &ctx.policy, sizeof(before)) == 0);
    update(ROLE_ADMIN, 49, 1, METHOD_GET, ROLE_OPERATOR, 65);
    CHECK("valid policy update commits", gateway_evaluate(&ctx) == GATEWAY_POLICY_UPDATED && ctx.policy.num_rules == 1 && ctx.gate[1] == GATE_STATUS_OK);
    CHECK("policy update does not dispatch", !gateway_dispatch(&ctx) && ctx.dispatch_count == 0 && ctx.app_len == 0);
    CHECK("stored policy slot preserved", ctx.policy.rules[1].path_hash == PATH_POLICY && ctx.policy.rules[1].method == METHOD_GET);
    start("GET", "/api/status", ROLE_OPERATOR, 1, 1);
    CHECK("updated active rule works", gateway_evaluate(&ctx) == GATEWAY_FORWARD);
    start("GET", "/api/policy", ROLE_ADMIN, 0xFFFF, 1);
    CHECK("stored slot matches despite count one", gateway_evaluate(&ctx) == GATEWAY_FORWARD);
    CHECK("policy tests retain buffer guards", gateway_guards_ok(&ctx));

    /* Direct generated validators, independent of handwritten rate prechecks. */
    uint8_t access[75] = {0};
    access[0] = ROLE_OPERATOR; access[1] = 49; access[2] = 1;
    put32(access + 4, PATH_STATUS); access[8] = METHOD_GET; access[9] = ROLE_OPERATOR; access[10] = 1;
    put32(access + 68, PATH_STATUS); access[72] = METHOD_GET;
    CHECK("EverParse access allow directly", RbacPolicyCheckAccessRequest(access, sizeof(access)));
    int truncated = 1;
    for (uint32_t n = 0; n < sizeof(access); ++n) if (RbacPolicyCheckAccessRequest(access, n)) truncated = 0;
    CHECK("EverParse rejects every truncated access length", truncated);
    access[1] = 50;
    CHECK("EverParse rate predicate independently denies", !RbacPolicyCheckAccessRequest(access, sizeof(access)));
    access[1] = 0; access[2] = 0;
    CHECK("EverParse scope predicate independently denies", !RbacPolicyCheckAccessRequest(access, sizeof(access)));
    uint8_t policy[70] = {0}; policy[0] = ROLE_ADMIN; policy[1] = 49; policy[2] = 1;
    put32(policy + 3, PATH_STATUS); policy[7] = METHOD_GET; policy[8] = ROLE_OPERATOR; policy[9] = 1;
    CHECK("EverParse policy allow directly", RbacPolicyCheckPolicyBlob(policy, sizeof(policy)));
    truncated = 1;
    for (uint32_t n = 0; n < sizeof(policy); ++n) if (RbacPolicyCheckPolicyBlob(policy, n)) truncated = 0;
    CHECK("EverParse rejects every truncated policy length", truncated);
    policy[0] = ROLE_OPERATOR;
    CHECK("EverParse policy admin predicate", !RbacPolicyCheckPolicyBlob(policy, sizeof(policy)));
    policy[0] = ROLE_ADMIN; policy[1] = 50;
    CHECK("EverParse policy rate predicate", !RbacPolicyCheckPolicyBlob(policy, sizeof(policy)));
}
