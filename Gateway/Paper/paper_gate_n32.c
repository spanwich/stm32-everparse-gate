/* Section 14 experiment (labelled variant, GATEWAY_PAPER_GATE_N32 = 1).
 *
 * 1. Policy as data: the policy in paper_gate_n32_data.h (GATE_N32_POLICY;
 *    now the OPNsense 19.1.7 endpoint policy, 420 rules, n = 53; first run:
 *    SCALANCE XB-200, 254 rules, n = 32) is copied from flash data into a RAM
 *    rule table and decided by the unchanged extracted GateLowGateDecide
 *    against its oracle vectors.
 * 2. Cost: DWT cycles of the decision for first match, last rule and absent
 *    path at n = 1 and n = GATE_N32_PARTITIONS, and, at n = 1, of the previous monolithic
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
#if GATEWAY_PAPER_TIMING_DIST
#include "../Generated/Policy/Blob.h"
#include "FreeRTOS.h"
#include "task.h"
#endif
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


#if GATEWAY_PAPER_TIMING_DIST
/* Distribution timing (2026-10-21). Each sample brackets one call with two
 * DWT->CYCCNT reads; the empty bracket is reported separately (not subtracted
 * here). irq=on: interrupts enabled (deployed condition); irq=off: PRIMASK set
 * around each sample (the call's own cost). Observed values, not WCET. */
enum { DSAMPLES = 10000, DSAMPLES_BIG = 2000 };
/* One 20 KB buffer: 10,000 16-bit samples (n = 1, empty, update; all well
 * below 65,536 cycles) or up to 5,000 32-bit samples (n = 53). */
static union { uint16_t h[DSAMPLES]; uint32_t w[DSAMPLES / 2]; } dbuf;
static int dwide;
static unsigned long doverflow;
static inline void dput(unsigned i, uint32_t v)
{
    if (dwide) dbuf.w[i] = v;
    else { if (v > 0xFFFFu) { doverflow++; v = 0xFFFFu; } dbuf.h[i] = (uint16_t)v; }
}
static inline uint32_t dget(unsigned i) { return dwide ? dbuf.w[i] : dbuf.h[i]; }
static unsigned dcount = DSAMPLES;
/* Yield between samples (outside the timed region) so the 1 s watchdog task runs. */
static void dyield(unsigned i) { if ((i & 255u) == 255u) vTaskDelay(1); }

static void dsort(unsigned n)
{
    static const unsigned gaps[] = { 4001u, 1750u, 701u, 301u, 132u, 57u, 23u, 10u, 4u, 1u };
    for (unsigned g = 0; g < sizeof gaps / sizeof gaps[0]; g++)
        for (unsigned i = gaps[g]; i < n; i++) {
            uint32_t v = dget(i); unsigned j = i;
            while (j >= gaps[g] && dget(j - gaps[g]) > v) { dput(j, dget(j - gaps[g])); j -= gaps[g]; }
            dput(j, v);
        }
}

static void dreport(const char *what, unsigned n, const char *label, int irq, uint32_t answer)
{
    uint64_t sum = 0;
    for (unsigned i = 0; i < dcount; i++) sum += dget(i);
    dsort(dcount);
    gateway_log("[GATE-DIST] what=%s n=%u case=%s irq=%s answer=%lu samples=%u min=%lu mean=%lu p50=%lu p99=%lu max=%lu\n",
                what, n, label, irq ? "on" : "off", (unsigned long)answer, dcount,
                (unsigned long)dget(0), (unsigned long)(sum / dcount),
                (unsigned long)dget(dcount / 2), (unsigned long)dget((dcount * 99u) / 100u),
                (unsigned long)dget(dcount - 1));
    vTaskDelay(pdMS_TO_TICKS(20));
}

static void dist_gate(unsigned n, const char *label, GATE_SPEC_REQUEST q, GATE_SPEC_SESSION s, int irq)
{
    uint8_t ctxt = 0, r = 0;
    dcount = n == 1u ? DSAMPLES : DSAMPLES_BIG; dwide = n != 1u;
    for (unsigned i = 0; i < 100; i++) sink += GateLowGateDecide(n, table, q, s, &ctxt); /* warm-up */
    for (unsigned i = 0; i < dcount; i++) {
        dyield(i);
        uint32_t pm = __get_PRIMASK();
        if (!irq) __disable_irq();
        uint32_t t0 = DWT->CYCCNT;
        r = GateLowGateDecide(n, table, q, s, &ctxt);
        uint32_t t1 = DWT->CYCCNT;
        __set_PRIMASK(pm);
        dput(i, t1 - t0); sink += r;
    }
    dreport("decide", n, label, irq, r);
}

static void dist_empty(int irq)
{
    dcount = DSAMPLES; dwide = 0;
    for (unsigned i = 0; i < dcount; i++) {
        dyield(i);
        uint32_t pm = __get_PRIMASK();
        if (!irq) __disable_irq();
        uint32_t t0 = DWT->CYCCNT;
        __asm volatile("" ::: "memory");
        uint32_t t1 = DWT->CYCCNT;
        __set_PRIMASK(pm);
        dput(i, t1 - t0);
    }
    dreport("empty", 0, "bracket", irq, 0);
}

static void dist_update(const char *label, BLOB_SPEC_SESSION s, const uint8_t body[65], int irq)
{
    BLOB_SPEC_RULE pol[8]; uint8_t nr = 0, ctxt = 0, r = 0, b[65];
    dcount = DSAMPLES; dwide = 0;
    for (unsigned i = 0; i < dcount; i++) {
        dyield(i);
        memcpy(b, body, 65);
        uint32_t pm = __get_PRIMASK();
        if (!irq) __disable_irq();
        uint32_t t0 = DWT->CYCCNT;
        r = BlobLowUpdateDecide(s, b, pol, &nr, &ctxt);
        uint32_t t1 = DWT->CYCCNT;
        __set_PRIMASK(pm);
        dput(i, t1 - t0); sink += r + nr;
    }
    dreport("update", 1, label, irq, r);
}

/* Constructed worst case: every slot of every partition matches path, method
 * and role and fails the last conjunct (scope), so the short-circuit
 * evaluation checks all four conditions in all 8n slots and denies. */
static void fill_worst(unsigned n, uint32_t path)
{
    for (unsigned i = 0; i < 8u * n; i++)
        table[i] = (GATE_SPEC_RULE){ .path = path, .mask = 0x3Fu, .min_role = 0u, .rscope = 0x8000u };
}

static void timing_dist_run(unsigned last)
{
    GATE_SPEC_SESSION top = { .role = 0xFF, .sscope = 0xFFFF, .count = 0 };
    GATE_SPEC_REQUEST absent = { .rpath = 0x7FFF0001u, .meth = 1 };
    for (int irq = 1; irq >= 0; irq--) {
        dist_empty(irq);
        dist_gate(GATE_N32_PARTITIONS, "first", req_for(0), top, irq);
        dist_gate(GATE_N32_PARTITIONS, "last", req_for(last), top, irq);
        dist_gate(GATE_N32_PARTITIONS, "absent", absent, top, irq);
        dist_gate(1, "first", req_for(0), top, irq);
        dist_gate(1, "last", req_for(7), top, irq);
        dist_gate(1, "absent", absent, top, irq);
    }
    /* update gate: a valid 8-rule body built from the policy's first rules */
    uint8_t body[65] = { 8 };
    for (unsigned i = 0; i < 8; i++) {
        uint8_t *b = body + 1 + 8 * i;
        put32(b, table[i].path); b[4] = (uint8_t)(table[i].mask & 0x3Fu);
        b[5] = (uint8_t)(table[i].min_role > 2u ? 2u : table[i].min_role); put16(b + 6, table[i].rscope);
    }
    BLOB_SPEC_SESSION admin = { .role = 2, .count = 0 }, oper = { .role = 1, .count = 0 };
    for (int irq = 1; irq >= 0; irq--) {
        dist_update("valid", admin, body, irq);
        dist_update("wrong_role", oper, body, irq);
    }
    /* constructed worst case, last because it overwrites the policy table */
    GATE_SPEC_SESSION worst_s = { .role = 0xFF, .sscope = 0x7FFF, .count = 0 };
    GATE_SPEC_REQUEST worst_q = { .rpath = 0x12345678u, .meth = 1 };
    fill_worst(GATE_N32_PARTITIONS, worst_q.rpath);
    for (int irq = 1; irq >= 0; irq--) {
        dist_gate(GATE_N32_PARTITIONS, "worst", worst_q, worst_s, irq);
        dist_gate(1, "worst", worst_q, worst_s, irq);
    }
    gateway_log("[GATE-DIST] done sink=%lu core_hz=%lu overflow16=%lu\n", (unsigned long)sink, (unsigned long)SystemCoreClock, doverflow);
}
#endif

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
    gateway_log("[GATE-N32] policy=%s n=%u vectors=%u accepts=%lu mismatches=%lu fail_closed=%lu\n",
                GATE_N32_POLICY, (unsigned)GATE_N32_PARTITIONS, (unsigned)GATE_N32_VECTORS, accepts, mismatches, fail_closed);

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
#if GATEWAY_PAPER_TIMING_DIST
    timing_dist_run(last);
#endif
    gateway_log("[GATE-N32] done sink=%lu\n", (unsigned long)sink);
}
#endif
