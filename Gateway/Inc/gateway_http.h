#ifndef GATEWAY_HTTP_H
#define GATEWAY_HTTP_H
#include "gateway_core.h"
#ifndef GATEWAY_LAB_AUTH
#define GATEWAY_LAB_AUTH 1
#endif
/* One owner; no retained references to incoming network buffers. */
typedef struct {
    uint8_t raw[GATEWAY_REQUEST_CAPACITY];
    uint32_t used, header_end, body_len, canonical_header;
    bool script, demo;
    bool dashboard; /* Set only after complete, validated GET /. */
    int status; /* 0: need more, 1: complete, otherwise HTTP error status */
} GatewayHttp;
void gateway_http_init(GatewayHttp *h);
int gateway_http_feed(GatewayHttp *h, GatewayContext *c, const void *data, size_t length);
/* Consumes a complete request, authenticates, evaluates and dispatches once. */
int gateway_http_process(GatewayHttp *h, GatewayContext *c);
/* Token bytes are compared exactly; no strings or prefix matching. */
bool gateway_bearer_check(const uint8_t *token, size_t length, GatewayIdentity *identity, uint8_t *rate);
int gateway_http_typed_header(char *out, size_t capacity, int status, size_t body_length, const char *content_type);
int gateway_http_html_header(char *out, size_t capacity, size_t body_length);
int gateway_http_response_header(char *out, size_t capacity, int status, size_t body_length);
#endif
