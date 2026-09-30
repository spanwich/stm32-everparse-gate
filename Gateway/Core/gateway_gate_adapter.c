/* Platform glue for the verified composed gate (papers repo,
 * experiments/verified-combiner; PAPER_EVIDENCE_REQUIREMENTS.md section 14).
 *
 * The decision is GateLowGateDecide, extracted from Low* and proved to accept
 * exactly when D_accept holds. This file only decodes the 75-byte access
 * envelope, which the proved Mediation.Field serializer builds from the request
 * and policy snapshots, into the gate's structs:
 *   e[0] role, e[1] rate count, e[2..3] scope (LE),
 *   e[4+8i..11+8i] rule i: path (LE32), method mask, min role, scope (LE16),
 *   e[68..71] request path (LE32), e[72] request method.
 * The policy is one partition (n = 1) of eight slots; inactive slots carry the
 * 0xDEADDEAD sentinel, as for the monolithic validator. */
#include <stdbool.h>
#include <stdint.h>
#include "../Generated/Gate/Gate.h"

static uint16_t le16(const uint8_t *b) { return (uint16_t)(b[0] | (b[1] << 8)); }
static uint32_t le32(const uint8_t *b)
{ return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24); }

bool gateway_gate_decide_envelope(const uint8_t *e, uint32_t length)
{
    if (length != 75) return false;
    GATE_SPEC_RULE rules[8];
    for (unsigned i = 0; i < 8; i++) {
        const uint8_t *r = e + 4 + 8 * i;
        rules[i] = (GATE_SPEC_RULE){ .path = le32(r), .mask = r[4], .min_role = r[5], .rscope = le16(r + 6) };
    }
    GATE_SPEC_REQUEST q = { .rpath = le32(e + 68), .meth = e[72] };
    GATE_SPEC_SESSION s = { .role = e[0], .sscope = le16(e + 2), .count = e[1] };
    uint8_t ctxt = 0;
    /* 1 = accept; 0 = deny; 2 = fail-closed deny. */
    return GateLowGateDecide(1U, rules, q, s, &ctxt) == 1U;
}
