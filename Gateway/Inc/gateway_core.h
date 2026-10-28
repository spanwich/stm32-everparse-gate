/* Handwritten STM32 integration. Not covered by the generated core's proofs. */
#ifndef GATEWAY_CORE_H
#define GATEWAY_CORE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "control_pipeline.h"
#include "extract.h"
#define GATEWAY_REQUEST_CAPACITY 4096U
#define GATEWAY_WIRE_CAPACITY 1536U
#define GATEWAY_AUTH_CAPACITY 37U
#define GATEWAY_GUARD 0x47575459U

typedef enum {
    GATEWAY_IDLE, GATEWAY_EXTRACTED, GATEWAY_IDENTIFIED,
    GATEWAY_FORWARD, GATEWAY_DENIED, GATEWAY_POLICY_UPDATED,
    GATEWAY_REJECTED, GATEWAY_DISPATCHED
} GatewayResult;

/* A trusted in-process result, never a network input or proof of authentication.
 * Milestone one supplies this ONLY from synthetic self-test fixtures. */
typedef struct {
    bool valid;
    uint8_t role;
    uint16_t scope;
    uint8_t subject_len;
    uint8_t subject[SUBJECT_ID_MAX];
} GatewayIdentity;

/* Exactly one task owns this context. No fields may change during a core call.
 * request_len counts initialized bytes; request and generated output never alias.
 * Guard words are diagnostic sentinels, not an isolation mechanism. */
typedef struct {
    uint32_t guard_start;
    uint8_t request[GATEWAY_REQUEST_CAPACITY];
    uint32_t guard_request;
    uint8_t security[GATEWAY_WIRE_CAPACITY];
    uint32_t guard_security;
    uint8_t auth[GATEWAY_AUTH_CAPACITY];
    uint32_t guard_auth;
    uint8_t app[GATEWAY_WIRE_CAPACITY];
    uint32_t guard_app;
    uint8_t gate[GATEWAY_WIRE_CAPACITY];
    uint32_t guard_gate;
    uint32_t request_len, security_len, app_len, gate_len;
    Policy policy;
    GatewayResult result;
    uint8_t extraction_code;
    uint32_t dispatch_count;
} GatewayContext;

void gateway_init(GatewayContext *ctx);
/* Clears request-local state and buffers, preserving policy and dispatch count. */
void gateway_begin_request(GatewayContext *ctx);
/* Caller fills request[0..request_len) before calling. Rejects lengths >4096. */
GatewayResult gateway_extract(GatewayContext *ctx);
/* On failure clears previously populated identity and pending outputs. */
/* `now` is the interface time in ms (gateway_tick_ms); it drives the verified
 * windowed rate counter, which supplies the gate's count byte. */
GatewayResult gateway_set_identity(GatewayContext *ctx,
                                  const GatewayIdentity *identity, uint64_t now);
/* Interface time source (ms) for the windowed rate counter. gateway_platform_tick_ms
 * is the real tick (osKernelGetTickCount on target, a fixed value on the host);
 * gateway_tick_ms returns it unless a self-test set a synthetic value. The
 * synthetic hooks let the rate self-test drive the window deterministically on
 * both the host and the real build; gateway_clock_real restores the live tick. */
uint64_t gateway_platform_tick_ms(void);
uint64_t gateway_tick_ms(void);
void gateway_clock_synthetic(uint64_t now_ms);
void gateway_clock_real(void);
GatewayResult gateway_evaluate(GatewayContext *ctx);
/* Consumes a forwarding result once; never dispatches denied/updated requests. */
bool gateway_dispatch(GatewayContext *ctx);
/* App task's bounded effect implementation, with a copied policy snapshot. */
bool gateway_render_app(const uint8_t *app, uint32_t app_len,
                        const Policy *policy, uint8_t *gate, uint32_t *gate_len);
bool gateway_guards_ok(const GatewayContext *ctx);
#endif
