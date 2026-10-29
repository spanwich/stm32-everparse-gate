#ifndef GATEWAY_GLUE_H
#define GATEWAY_GLUE_H
#include <stdint.h>
#include <stdbool.h>
#include "control_pipeline.h"   /* Policy */

/* Plain-typed shims over the verified glue (Gateway/Generated/Glue). The glue
 * headers pull the Gate/Policy EverParse runtime, whose KRML_CHECK_SIZE clashes
 * with the extractor's krml runtime if both are in one translation unit (see
 * AGENTS.md). These shims and the live policy store live in the separate
 * gateway_glue_adapter.c, which includes only the EverParse family, so callers
 * that use the extractor runtime (gateway_mediation.c, extractor_adapter.c)
 * never include the glue headers directly. */

/* Step the one interface rate counter at `now` (ms) and place its resulting count
 * (byte 0) plus role/scope/subject (bytes 6-41) into the frame, via the verified
 * GlueRateCountAndIdentify. The gate then reads the real per-window request count.
 * subject is a 32-byte buffer; subject_len of it is copied and the rest zero-filled. */
void gateway_glue_set_identity(uint8_t *frame, uint64_t now, uint8_t role,
                               uint16_t scope, uint8_t subject_len, uint8_t *subject);
/* Initialise the one interface-wide windowed rate counter (empty window). Called
 * once at gate start, alongside gateway_policy_store_init. */
void gateway_rate_state_init(void);

/* Decide one access/update request (GlueLowMediate over the live store, n=1,
 * j=1). Returns 0 malformed, 1 forward (app holds the AppRequest, *app_len set),
 * 2 deny, 3 rate limited, 4 updated (the store now holds the decoded rules,
 * *num_rules set), 5 update rejected, 6 fail closed. */
uint8_t gateway_glue_mediate(uint8_t *frame, uint32_t len, uint8_t *num_rules,
                             uint8_t *app, uint32_t *app_len, uint32_t part);

/* Refresh a display Policy (8 slots) from partition `part` (1-based) of the live
 * store. num_rules is the committed rule count after an update, or 0 to derive it
 * (through the last active slot, min 1) on a readback. Returns false, leaving *out untouched, when `part` is outside 1..N. */
bool gateway_glue_store_to_policy(Policy *out, uint32_t part, uint8_t num_rules);

/* The /api/policy partition selector of the request being processed (1-based,
 * default 1). Request-scoped: set by the HTTP adapter after parsing ?part=J, reset
 * by gateway_begin_request. Kept out of GatewayContext so its ABI contract is
 * unchanged. Not range-checked here; see gateway_glue_mediate / store_to_policy. */
void gateway_glue_set_part(uint32_t part);
uint32_t gateway_glue_part(void);

/* Rate window in ms (tick units of gateway_tick_ms). 500 ms: with N_max = 50 at most
 * 49 requests are admitted per window (~98 req/s sustained). The verified GlueRate
 * takes the window length as a runtime parameter, so this is a constant only. */
#ifndef GATEWAY_RATE_WINDOW_MS
#define GATEWAY_RATE_WINDOW_MS 500ULL
#endif

/* Live store geometry: GATEWAY_LIVE_PARTS partitions of 8 slots (OPNsense-size
 * policy: partition 1 = the gateway's own routes / restrictive default). */
#define GATEWAY_LIVE_PARTS 64U
#define GATEWAY_LIVE_SLOTS (8U * GATEWAY_LIVE_PARTS)
/* gateway_glue_live_store() (GATE_SPEC_RULE *) is declared by the one labelled
 * variant that includes Glue.h (paper_runtime53.c). */

/* The single authoritative live policy store for the composed gate (one
 * partition, eight slots), used by gateway_glue_mediate. store_init loads the
 * restrictive default (first-boot policy); store_load replaces it from a Policy.
 * These two and the verified GlueLowMediate update branch are its only writers;
 * a display Policy is refreshed from it, never the reverse. */
void gateway_policy_store_init(void);
void gateway_policy_store_load(const Policy *policy);
#endif
