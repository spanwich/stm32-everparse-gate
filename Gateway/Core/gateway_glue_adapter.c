/* Separate adapter translation unit for the verified glue. It includes only the
 * Gate/Policy EverParse runtime (via Glue.h/GlueFront.h), never the extractor's
 * krml runtime, so the KRML_CHECK_SIZE macro does not clash (AGENTS.md). It owns
 * the single live policy store and exposes plain-typed shims (gateway_glue.h). */
#include <stdint.h>
#include <string.h>
#include "control_pipeline.h"             /* Policy, PolicyRule, MAX_RULES, DEAD_HASH, policy_init_restrictive */
#include "gateway_glue.h"
#include "../Generated/Glue/Glue.h"       /* GlueLowMediate, GATE_SPEC_RULE */
#include "../Generated/Glue/GlueFront.h"  /* GlueFrontSetIdentity */
#include "../Generated/Glue/GlueRate.h"   /* GlueRateRateInit, GlueRateCountAndIdentify */

/* One windowed rate counter for the whole interface (not per role/subject).
 * N_max = 50 is fixed in the verified gate (GlueLowMediate: count >= 50 -> rate);
 * the window is chosen so a ~1 kHz interface stays under the limit. */
#define GATEWAY_RATE_WINDOW_MS 49ULL

/* Authoritative live store. Trusted writers: the two store functions below and
 * the verified GlueLowMediate update branch (CopyPart). */
static GATE_SPEC_RULE gateway_live_pi[MAX_RULES] __attribute__((section(".gateway_gate")));

/* The one interface-wide rate state. Trusted writers: gateway_rate_state_init and
 * the verified GlueRateCountAndIdentify (via gateway_glue_set_identity). */
static GLUE_RATESPEC_RSTATE gateway_rate_state __attribute__((section(".gateway_gate")));

void gateway_rate_state_init(void)
{
    GlueRateRateInit(&gateway_rate_state);
}

void gateway_policy_store_load(const Policy *policy)
{
    for (unsigned i = 0; i < MAX_RULES; ++i)
        gateway_live_pi[i] = (GATE_SPEC_RULE){ policy->rules[i].path_hash, policy->rules[i].method,
                                               policy->rules[i].min_role, policy->rules[i].req_scope };
}

void gateway_policy_store_init(void)
{
    Policy p;
    policy_init_restrictive(&p);
    gateway_policy_store_load(&p);
}

void gateway_glue_set_identity(uint8_t *frame, uint64_t now, uint8_t role,
                               uint16_t scope, uint8_t subject_len, uint8_t *subject)
{
    /* Step the one interface rate counter at `now` and place its count (byte 0)
     * plus role/scope/subject (bytes 6-41) into the frame, in one verified call.
     * The gate then reads the real per-window request count, not a fixture. */
    GlueRateCountAndIdentify(&gateway_rate_state, now, GATEWAY_RATE_WINDOW_MS,
                             frame, role, scope, subject_len, subject);
}

uint8_t gateway_glue_mediate(uint8_t *frame, uint32_t len, uint8_t *num_rules,
                             uint8_t *app, uint32_t *app_len)
{
    uint8_t ctxt = 0;
    return GlueLowMediate(1, gateway_live_pi, 1, frame, len, num_rules, app, app_len, &ctxt);
}

void gateway_glue_store_to_policy(Policy *out, uint8_t num_rules)
{
    memset(out, 0, sizeof(*out));
    out->num_rules = num_rules;
    for (unsigned i = 0; i < MAX_RULES; ++i)
        out->rules[i] = (PolicyRule){ gateway_live_pi[i].path, gateway_live_pi[i].mask,
                                      gateway_live_pi[i].min_role, gateway_live_pi[i].rscope };
}
