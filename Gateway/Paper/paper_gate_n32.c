/* Section 14 experiment (labelled variant, GATEWAY_PAPER_GATE_N32 = 1).
 *
 * 1. Switch-model policy as data: the SCALANCE XB-200 policy (254 rules,
 *    n = 32) is copied from flash data into a RAM rule table and decided by the
 *    unchanged extracted GateLowGateDecide against 17,760 oracle vectors.
 * 2. Cost: DWT cycles of the decision for first match, last rule and absent
 *    path at n = 1 and n = 32, and, at n = 1, of the previous monolithic
 *    RbacPolicy access validator on the same 75-byte envelope.
 * Runs in the privileged core task after the self-tests, interrupts enabled:
 * observed distributions, not WCET. */
#include "paper_experiment.h"
#if GATEWAY_PAPER_GATE_N32
#include "gateway_log.h"
#include "main.h"
#include "../Generated/Gate/Gate.h"
#include "../Generated/Policy/RbacPolicyWrapper.h"
#include "paper_gate_n32_data.h"
#include <stdbool.h>
#include <string.h>

enum { SAMPLES = 1001 };
static GATE_SPEC_RULE table[8u * GATE_N32_PARTITIONS];
static uint32_t samples[SAMPLES];
static volatile uint32_t sink;
bool gateway_gate_decide_envelope(const uint8_t *e, uint32_t length);

static void put16(uint8_t *b, uint16_t x) { b[0] = (uint8_t)x; b[1] = (uint8_t)(x >> 8); }
static void put32(uint8_t *b, uint32_t x) { for (unsigned i = 0; i < 4; i++) b[i] = (uint8_t)(x >> (8 * i)); }

static void sort(uint32_t *a, unsigned n)
{
    for (unsigned i = 1; i < n; i++) {
        uint32_t v = a[i]; unsigned j = i;
        while (j && a[j - 1] > v) { a[j] = a[j - 1]; j--; }
        a[j] = v;
    }
}

static void report(const char *impl, unsigned n, const char *label, uint32_t answer)
{
    sort(samples, SAMPLES);
    gateway_log("[GATE-CYC] impl=%s n=%u case=%s answer=%lu min=%lu med=%lu max=%lu\n", impl, n, label,
                (unsigned long)answer, (unsigned long)samples[0], (unsigned long)samples[SAMPLES / 2],
                (unsigned long)samples[SAMPLES - 1]);
}

static void time_gate(unsigned n, const char *label, GATE_SPEC_REQUEST q, GATE_SPEC_SESSION s)
{
    uint8_t ctxt = 0, r = 0;
    for (unsigned i = 0; i < SAMPLES; i++) {
        uint32_t t0 = DWT->CYCCNT;
        r = GateLowGateDecide(n, table, q, s, &ctxt);
        samples[i] = DWT->CYCCNT - t0;
        sink += r;
    }
    report("verified_gate", n, label, r);
}

/* n = 1 only: the same decision through the adapter (envelope decode + gate)
 * and through the monolithic validator, on one 75-byte envelope. */
static void time_envelope(const char *label, GATE_SPEC_REQUEST q, GATE_SPEC_SESSION s)
{
    uint8_t e[75] = { 0 };
    e[0] = s.role; e[1] = s.count; put16(e + 2, s.sscope);
    for (unsigned i = 0; i < 8; i++) {
        uint8_t *b = e + 4 + 8 * i;
        put32(b, table[i].path); b[4] = table[i].mask; b[5] = table[i].min_role; put16(b + 6, table[i].rscope);
    }
    put32(e + 68, q.rpath); e[72] = q.meth;
    bool r = false;
    for (unsigned i = 0; i < SAMPLES; i++) {
        uint32_t t0 = DWT->CYCCNT;
        r = gateway_gate_decide_envelope(e, 75);
        samples[i] = DWT->CYCCNT - t0;
        sink += r;
    }
    report("adapter+verified_gate", 1, label, r);
    for (unsigned i = 0; i < SAMPLES; i++) {
        uint32_t t0 = DWT->CYCCNT;
        r = RbacPolicyCheckAccessRequest(e, 75);
        samples[i] = DWT->CYCCNT - t0;
        sink += r;
    }
    report("monolithic_rbac", 1, label, r);
}

static GATE_SPEC_REQUEST req_for(unsigned rule)
{
    uint8_t m = table[rule].mask;
    return (GATE_SPEC_REQUEST){ .rpath = table[rule].path, .meth = (uint8_t)(m & (uint8_t)-m) };
}

void gateway_paper_gate_n32_run(void)
{
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0; DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    /* Load the policy as data. */
    for (unsigned i = 0; i < 8u * GATE_N32_PARTITIONS; i++)
        table[i] = (GATE_SPEC_RULE){ .path = gate_n32_rules[i].path, .mask = gate_n32_rules[i].mask,
                                     .min_role = gate_n32_rules[i].min_role, .rscope = gate_n32_rules[i].scope };
    unsigned long accepts = 0, mismatches = 0, fail_closed = 0;
    uint8_t ctxt = 0;
    for (unsigned i = 0; i < GATE_N32_VECTORS; i++) {
        const GateN32Vector *v = &gate_n32_vectors[i];
        GATE_SPEC_REQUEST q = { .rpath = v->path, .meth = v->meth };
        GATE_SPEC_SESSION s = { .role = v->role, .sscope = v->scope, .count = v->count };
        uint8_t r = GateLowGateDecide(GATE_N32_PARTITIONS, table, q, s, &ctxt);
        accepts += r == 1u; fail_closed += r == 2u;
        if ((r == 1u) != (v->expected == 1u) || r == 2u) {
            if (mismatches < 5)
                gateway_log("[GATE-N32] MISMATCH vector=%u gate=%u oracle=%u\n", i, r, v->expected);
            mismatches++;
        }
    }
    gateway_log("[GATE-N32] policy=siemens-scalance-xb200 n=%u vectors=%u accepts=%lu mismatches=%lu fail_closed=%lu\n",
                (unsigned)GATE_N32_PARTITIONS, (unsigned)GATE_N32_VECTORS, accepts, mismatches, fail_closed);

    GATE_SPEC_SESSION top = { .role = 0xFF, .sscope = 0xFFFF, .count = 0 };
    GATE_SPEC_REQUEST absent = { .rpath = 0x7FFF0001u, .meth = 1 };
    unsigned last = 0;
    for (unsigned i = 0; i < 8u * GATE_N32_PARTITIONS; i++) if (table[i].path != 0xDEADDEADu) last = i;
    time_gate(GATE_N32_PARTITIONS, "first", req_for(0), top);
    time_gate(GATE_N32_PARTITIONS, "last", req_for(last), top);
    time_gate(GATE_N32_PARTITIONS, "absent", absent, top);
    time_gate(1, "first", req_for(0), top);
    time_gate(1, "last", req_for(7), top);
    time_gate(1, "absent", absent, top);
    time_envelope("first", req_for(0), top);
    time_envelope("last", req_for(7), top);
    time_envelope("absent", absent, top);
    gateway_log("[GATE-N32] done sink=%lu\n", (unsigned long)sink);
}
#endif
