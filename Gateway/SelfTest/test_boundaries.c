#include "gateway_core.h"
#include "gateway_tests.h"
#include <string.h>
#include <stdio.h>
/* Test-owned contexts and snapshots are static: never placed on the task stack. */
extern GatewayContext gateway_test_context;
#define ctx gateway_test_context
static uint8_t snapshot[GATEWAY_REQUEST_CAPACITY];
#define CHECK(name, condition) gateway_test_check(s, name, (condition))
static void request(const char *text)
{
    gateway_begin_request(&ctx);
    ctx.request_len = (uint32_t)strlen(text);
    memcpy(ctx.request, text, ctx.request_len);
}
void gateway_test_boundaries(GatewayTestStats *s)
{
    gateway_test_printf("=== Adapter and buffer boundaries ===\n");
    gateway_init(&ctx);
    CHECK("initial guards", gateway_guards_ok(&ctx));
    CHECK("empty input incomplete", gateway_extract(&ctx) == GATEWAY_REJECTED && ctx.extraction_code == EXTRACT_INCOMPLETE && ctx.security_len == 0);
    CHECK("no policy call before extraction", gateway_evaluate(&ctx) == GATEWAY_REJECTED);
    CHECK("no dispatch before authorization", !gateway_dispatch(&ctx) && ctx.dispatch_count == 0);
    gateway_begin_request(&ctx);
    memset(ctx.request, 'A', sizeof(ctx.request));
    memcpy(snapshot, ctx.request, sizeof(snapshot));
    ctx.request_len = sizeof(ctx.request);
    CHECK("4096-byte unterminated header", gateway_extract(&ctx) == GATEWAY_REJECTED && ctx.extraction_code == EXTRACT_INCOMPLETE);
    CHECK("unterminated input unchanged", memcmp(snapshot, ctx.request, sizeof(snapshot)) == 0);
    CHECK("unterminated buffers intact", gateway_guards_ok(&ctx) && ctx.security_len == 0);
    ctx.request_len++;
    CHECK("4097 bytes rejected before extractor", gateway_extract(&ctx) == GATEWAY_REJECTED && ctx.security_len == 0);
    CHECK("oversized buffers intact", gateway_guards_ok(&ctx));

    gateway_begin_request(&ctx);
    const char *prefix = "GET /api/status HTTP/1.1\r\nX-Pad: ";
    size_t n = strlen(prefix);
    memcpy(ctx.request, prefix, n);
    memset(ctx.request + n, 'a', sizeof(ctx.request) - n - 4);
    memcpy(ctx.request + sizeof(ctx.request) - 4, "\r\n\r\n", 4);
    ctx.request_len = sizeof(ctx.request);
    memcpy(snapshot, ctx.request, sizeof(snapshot));
    CHECK("4096-byte complete request", gateway_extract(&ctx) == GATEWAY_EXTRACTED && ctx.security_len == SECPARAMS_HEADER_SIZE);
    CHECK("maximum request unchanged", memcmp(snapshot, ctx.request, sizeof(snapshot)) == 0 && gateway_guards_ok(&ctx));

    gateway_begin_request(&ctx);
    int header = snprintf((char *)ctx.request, sizeof(ctx.request), "PUT /api/policy HTTP/1.1\r\nContent-Length: 1361\r\n\r\n");
    memset(ctx.request + header, 0xA5, MAX_INLINE_BODY);
    ctx.request_len = (uint32_t)header + MAX_INLINE_BODY;
    memcpy(snapshot, ctx.request, sizeof(snapshot));
    CHECK("1361-byte body fills output", gateway_extract(&ctx) == GATEWAY_EXTRACTED && ctx.security_len == GATEWAY_WIRE_CAPACITY);
    CHECK("maximum body copied", memcmp(ctx.security + SECPARAMS_HEADER_SIZE, ctx.request + header, MAX_INLINE_BODY) == 0);
    CHECK("maximum body input stable", memcmp(snapshot, ctx.request, sizeof(snapshot)) == 0 && gateway_guards_ok(&ctx));
    request("PUT /api/policy HTTP/1.1\r\nContent-Length: 1362\r\n\r\n");
    CHECK("1362-byte body rejected", gateway_extract(&ctx) == GATEWAY_REJECTED && ctx.extraction_code == EXTRACT_BODY_TOO_LARGE && ctx.security_len == 0);
    request("PUT /api/policy HTTP/1.1\r\nContent-Length: 9999999999999999999999\r\n\r\n");
    CHECK("huge body length rejected", gateway_extract(&ctx) == GATEWAY_REJECTED && ctx.extraction_code == EXTRACT_BODY_TOO_LARGE);

    const char *fragmented = "POST /api/login HTTP/1.1\r\nContent-Length: 4\r\n\r\ndata";
    int incomplete = 1;
    for (uint32_t cut = 0; cut < strlen(fragmented); ++cut) {
        gateway_begin_request(&ctx);
        memcpy(ctx.request, fragmented, cut); ctx.request_len = cut;
        if (gateway_extract(&ctx) != GATEWAY_REJECTED || ctx.extraction_code != EXTRACT_INCOMPLETE || ctx.security_len != 0 || !gateway_guards_ok(&ctx)) incomplete = 0;
    }
    CHECK("every fragmented prefix incomplete", incomplete);
    request(fragmented);
    CHECK("complete fragmented request accepted", gateway_extract(&ctx) == GATEWAY_EXTRACTED && ctx.security_len == SECPARAMS_HEADER_SIZE + 4);

    const char *bad[] = {"DELETE /api/status HTTP/1.1\r\n\r\n", "GET /api/../status HTTP/1.1\r\n\r\n", "GET /unknown HTTP/1.1\r\n\r\n"};
    const uint8_t expected[] = {EXTRACT_METHOD_UNKNOWN, EXTRACT_PATH_TRAVERSAL, EXTRACT_MALFORMED};
    for (unsigned i = 0; i < 3; ++i) {
        request(bad[i]);
        CHECK("malformed request classification", gateway_extract(&ctx) == GATEWAY_REJECTED && ctx.extraction_code == expected[i] && ctx.security_len == 0);
        CHECK("malformed request cannot dispatch", !gateway_dispatch(&ctx) && gateway_guards_ok(&ctx));
    }
    request("GET /api/status HTTP/1.1\r\n\r\n");
    (void)gateway_extract(&ctx);
    GatewayIdentity identity = {.valid = true, .role = ROLE_ADMIN, .scope = 0xFFFF, .subject_len = 32};
    memset(identity.subject, 's', sizeof(identity.subject));
    CHECK("32-byte trusted identity", gateway_set_identity(&ctx, &identity, 49) == GATEWAY_IDENTIFIED);
    CHECK("identity fields and separate auth storage", ctx.security[6] == ROLE_ADMIN && ctx.security[9] == 32 && memcmp(ctx.security + 10, identity.subject, 32) == 0 && gateway_guards_ok(&ctx));
    identity.valid = false;
    CHECK("invalid identity revokes prior identity", gateway_set_identity(&ctx, &identity, 0) == GATEWAY_REJECTED && ctx.security[6] == 0 && ctx.security[9] == 0 && ctx.security[0] == 0);
    CHECK("invalid identity cannot evaluate", gateway_evaluate(&ctx) == GATEWAY_REJECTED && !gateway_dispatch(&ctx));
    (void)gateway_extract(&ctx); identity.valid = true; identity.role = 99;
    CHECK("adapter rejects invalid role", gateway_set_identity(&ctx, &identity, 0) == GATEWAY_REJECTED);
    (void)gateway_extract(&ctx); identity.role = ROLE_ADMIN; identity.subject_len = 33;
    CHECK("adapter rejects oversized subject", gateway_set_identity(&ctx, &identity, 0) == GATEWAY_REJECTED);
    (void)gateway_extract(&ctx);
    CHECK("adapter rejects missing identity", gateway_set_identity(&ctx, NULL, 0) == GATEWAY_REJECTED);
    (void)gateway_extract(&ctx); identity.subject_len = 1;
    (void)gateway_set_identity(&ctx, &identity, 0);
    ctx.security_len = SECPARAMS_HEADER_SIZE - 1;
    CHECK("short security header rejected", gateway_evaluate(&ctx) == GATEWAY_REJECTED && ctx.app_len == 0);
    (void)gateway_extract(&ctx); (void)gateway_set_identity(&ctx, &identity, 0);
    memset(ctx.security + 171, 0xFF, 4);
    CHECK("corrupt body length rejected before copy", gateway_evaluate(&ctx) == GATEWAY_REJECTED && ctx.app_len == 0 && gateway_guards_ok(&ctx));
    (void)gateway_extract(&ctx); (void)gateway_set_identity(&ctx, &identity, 0);
    ctx.guard_security = 0;
    CHECK("guard corruption stops processing", gateway_evaluate(&ctx) == GATEWAY_REJECTED && !gateway_dispatch(&ctx));
    gateway_init(&ctx);
}
