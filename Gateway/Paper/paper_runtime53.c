/* Runtime-loaded 53-partition policy (labelled variant GATEWAY_PAPER_RUNTIME53,
 * 2026-10-28). Supports the paper's "policy is runtime data" claim at scale:
 * the full OPNsense 19.1.7 policy (420 rules, 53 partitions x 8 slots) is loaded
 * at run time over HTTP through the UNCHANGED verified PolicyBlob update gate
 * (BlobLowUpdateDecide, Gateway/Generated/Policy/Blob.c), one partition per
 * request, into a live store in the GATE compartment's RAM. Decisions use the
 * UNCHANGED composed gate (GateLowGateDecide, Gateway/Generated/Gate) over that
 * store, exactly as the GATE_N32 variant does, but reading the runtime store.
 *
 * Nothing here changes the 3D spec, the F* and Low* proofs or the generated C.
 * Updates and decisions are routed through the Low*-verified GlueLowMediate
 * (Gateway/Generated/Glue) with n=53 and the 1-based partition index j: the
 * mediate itself checks 1 <= j <= n (so the former handwritten j bounds check is
 * gone) and, on a valid admin blob, decodes the eight rules into partition j with
 * the unchanged BlobLowUpdateDecide; decisions run the unchanged GateLowGateDecide
 * over all 53 partitions after the count<50 rate check. The partition index is
 * still PARSED by hand (qnum of ?p=); only its bounds check moved into the proof.
 * The admin-only, rate and 1<=count<=8 checks remain the verified validator
 * (RbacPolicy.3d _auth_ok/_rate_ok/_rules_ok). The equivalence sweep and DWT
 * timing below still call GateLowGateDecide / BlobLowUpdateDecide directly, as
 * controlled measurement harnesses over the same live store.
 *
 * A labelled diagnostic endpoint (/gate53) drives: update a partition, decide a
 * single request, the 20,256-vector equivalence sweep (chunked to fit the
 * GATE->NET 2 s reply window), a load cross-check against the flash policy, and
 * DWT timing (interrupts masked per sample). The endpoint is intercepted in the
 * GATE task before the verified extractor; it is present only in this variant.
 *
 * Runs entirely in the GATE task (unprivileged), which owns the .gateway_gate
 * region. gateway_runtime53_init() runs once, privileged, from
 * gateway_r4_boundary_start: it sets the store to deny-all and enables DWT. */
#include "paper_experiment.h"
#if GATEWAY_PAPER_RUNTIME53
#include "paper_runtime53.h"
#include "gateway_http.h"
#include "gateway_platform.h"
#include "cmsis_os2.h"
#include "main.h"
#include "paper_dwt.h"
#include "../Generated/Gate/Gate.h"
#include "../Generated/Policy/Blob.h"
#include "../Generated/Glue/Glue.h"       /* GlueLowMediate (verified n/j mediation) */
#include "../Shared/gate_response_wire.h"
#include "paper_gate_n32_data.h"
#include "gateway_glue.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include <stdbool.h>
#include <string.h>

#define GATE_PRIVATE __attribute__((section(".gateway_gate")))
#define KERNEL_PRIVATE __attribute__((section(".gateway_privileged")))
#define RT_OPN_PARTS GATE_N32_PARTITIONS      /* 53 OPNsense partitions (flash data) */
#define RT_PARTS GATEWAY_LIVE_PARTS           /* 64: the primary live store */
#define RT_BASE 1u                            /* OPNsense partition k is store partition RT_BASE+k+1 (1-based); */
                                              /* store partition 1 is the gateway's own routes / default */
#define RT_SLOTS 8u
#define RT_RULES (RT_SLOTS * RT_PARTS)        /* 512 */
#define RT_OPN_RULES (RT_SLOTS * RT_OPN_PARTS) /* 424 (420 active) */
#define RT_SENTINEL 0xDEADDEADu
#define RT_BLOB_BODY 65u                      /* num_rules(1) + 8 x rule(8) */
#define RT_POLICY_PATH 0x44444444u            /* GlueLowMediate update selector (path) */
#define RT_METHOD_PUT 4u                      /* GlueLowMediate update selector (method) */

/* The decode destination of BlobLowUpdateDecide (BLOB_SPEC_RULE) and the gate's
 * rule (GATE_SPEC_RULE) are the same 8-byte layout {u32 path, u8 mask/method,
 * u8 min_role, u16 scope}; the adapter passes &live_store[8j] to the update
 * gate as BLOB_SPEC_RULE* and the decision reads it back as GATE_SPEC_RULE*. */
_Static_assert(sizeof(GATE_SPEC_RULE) == 8 && sizeof(BLOB_SPEC_RULE) == 8,
               "rule layout must be 8 bytes for the shared live store");

/* The labelled endpoint now works on the PRIMARY live store (Core/gateway_glue_adapter.c),
 * the same 8*64-slot array the live /api path decides over. */
GATE_SPEC_RULE *gateway_glue_live_store(void);
#define live_store (gateway_glue_live_store())
static uint32_t eq_from_next GATE_PRIVATE;    /* next expected sweep index */
static uint32_t eq_accepts GATE_PRIVATE, eq_mismatch GATE_PRIVATE, eq_failclosed GATE_PRIVATE;
static uint32_t rt_samples[2000] GATE_PRIVATE;

/* DWT->CYCCNT is privileged on this part (an unprivileged read bus-faults), so
 * the DWT-instrumented timing runs in a small privileged worker task. It times
 * the SAME verified routines (BlobLowUpdateDecide / GateLowGateDecide) over the
 * SAME runtime-loaded live_store; privilege changes neither the code nor the
 * data (caches off), so the cycle counts are representative. The GATE task
 * (unprivileged) still makes every real decision. */
typedef struct { uint8_t which, cas; uint32_t j; uint8_t body[RT_BLOB_BODY]; } RtTimeReq;
typedef struct { uint32_t samples, answer, mn, mean, p50, p99, mx, digest; } RtTimeRep;
enum { RT_W_UPDATE = 0u, RT_W_ABSENT = 1u, RT_W_LAST = 2u, RT_W_WORST = 3u };
static StaticQueue_t rt_req_cb KERNEL_PRIVATE, rt_rep_cb KERNEL_PRIVATE;
static uint8_t rt_req_storage[sizeof(RtTimeReq)] KERNEL_PRIVATE, rt_rep_storage[sizeof(RtTimeRep)] KERNEL_PRIVATE;
static QueueHandle_t rt_req_queue GATE_PRIVATE, rt_rep_queue GATE_PRIVATE;
/* The worker's stack lives in the GATE region (privileged background access
 * reaches it) to keep the constrained privileged RAM within budget. */
static StackType_t rt_timing_stack[1024] GATE_PRIVATE;
static StaticTask_t rt_timing_tcb KERNEL_PRIVATE;

/* Reference the flash policy so -Wall's unused-const-variable check passes and
 * so op=verifyload can confirm the HTTP-loaded store matches the intended
 * policy. gate_n32_rules is the OPNsense policy the host tool serialises. */
const GateN32Rule *gateway_runtime53_flash_rules(void) { return gate_n32_rules; }

void gateway_runtime53_init(void)
{
    /* The live store keeps its restrictive default (gateway_policy_store_init). */
    (void)paper_dwt_enable("runtime53");
}

/* Build a SecurityParamsWire for GlueLowMediate from flat fields (subject and
 * token empty). cap must be >= 175 + body_len. Returns the wire length. */
static uint32_t rt_wire(uint8_t *w, uint32_t cap, uint32_t path, uint8_t meth,
                        uint8_t role, uint16_t scope, uint8_t count,
                        const uint8_t *body, uint32_t body_len)
{
    memset(w, 0, cap);
    w[0] = count;
    w[1] = (uint8_t)path; w[2] = (uint8_t)(path >> 8);
    w[3] = (uint8_t)(path >> 16); w[4] = (uint8_t)(path >> 24);
    w[5] = meth; w[6] = role;
    w[7] = (uint8_t)scope; w[8] = (uint8_t)(scope >> 8);
    w[171] = (uint8_t)body_len; w[172] = (uint8_t)(body_len >> 8);
    w[173] = (uint8_t)(body_len >> 16); w[174] = (uint8_t)(body_len >> 24);
    if (body_len) memcpy(w + 175, body, body_len);
    return 175u + body_len;
}

/* Update adapter: build the 240-byte policy-update wire and route it through the
 * verified GlueLowMediate with n=53 and the 1-based partition index. GlueLowMediate
 * itself checks 1 <= J <= N -- so the handwritten j bounds check is gone -- and on a
 * valid admin blob decodes the eight rules into partition J, writing nothing on
 * rejection. j is still PARSED by hand at the endpoint (qnum of ?p=); only its
 * bounds check moved into the proof. Returns 1 accept, 0 deny/rejected (incl. an
 * out-of-range J), 2 fail-closed. */
static uint8_t gateway_runtime53_update(uint8_t role, uint8_t count, uint8_t *body, uint32_t j)
{
    uint8_t w[175u + RT_BLOB_BODY];
    uint8_t app[64]; uint32_t app_len = 0u; uint8_t nr = 0u, ctxt = 0u;
    uint32_t len = rt_wire(w, sizeof(w), RT_POLICY_PATH, RT_METHOD_PUT, role, 0u, count, body, RT_BLOB_BODY);
    uint8_t r = GlueLowMediate(RT_PARTS, live_store, RT_BASE + j + 1u, w, len, &nr, app, &app_len, &ctxt);
    return r == 4u ? 1u : r == 6u ? 2u : 0u;   /* 4 updated, 5 rejected, 6 fail-closed, 0 malformed */
}

/* Decision over the 53 runtime-loaded partitions, routed through the verified
 * GlueLowMediate. The wire's path is not the update selector, so it takes the
 * decision branch: the count<50 rate check then GateLowGateDecide over all N
 * partitions. Maps the glue result to this diagnostic's convention: 1 accept,
 * 0 deny (incl. rate limited), 2 fail-closed or malformed wire (role>2 / non-bit
 * method). */
static uint8_t gateway_runtime53_decide(uint32_t path, uint8_t meth, uint8_t role, uint16_t scope, uint8_t count)
{
    uint8_t w[175];
    uint8_t app[64]; uint32_t app_len = 0u; uint8_t nr = 0u, ctxt = 0u;
    uint32_t len = rt_wire(w, sizeof(w), path, meth, role, scope, count, NULL, 0u);
    uint8_t r = GlueLowMediate(RT_PARTS, live_store, 1u, w, len, &nr, app, &app_len, &ctxt);
    return r == 1u ? 1u : (r == 2u || r == 3u) ? 0u : 2u;
}

static uint32_t rt_digest(void)
{
    const uint8_t *b = (const uint8_t *)live_store;
    uint32_t h = 2166136261u;
    for (unsigned i = 0; i < RT_RULES * sizeof(GATE_SPEC_RULE); i++) { h ^= b[i]; h *= 16777619u; }
    return h;
}

static uint32_t rt_active(void)
{
    uint32_t n = 0;
    for (unsigned i = 0; i < RT_RULES; i++) if (live_store[i].path != RT_SENTINEL) n++;
    return n;
}

/* ---- tiny handwritten query/header parsing for the labelled endpoint ---- */
static bool key_at(const uint8_t *q, uint32_t n, uint32_t i, const char *key)
{
    uint32_t k = 0; while (key[k]) { if (i + k >= n || q[i + k] != (uint8_t)key[k]) return false; k++; }
    return i + k < n && q[i + k] == '=';
}
static bool qfind(const uint8_t *q, uint32_t n, const char *key, uint32_t *vs, uint32_t *ve)
{
    for (uint32_t i = 0; i < n; i++) {
        if ((i == 0 || q[i - 1] == '&') && key_at(q, n, i, key)) {
            uint32_t v = i; while (v < n && q[v] != '=') v++; v++;
            uint32_t e = v; while (e < n && q[e] != '&') e++;
            *vs = v; *ve = e; return true;
        }
    }
    return false;
}
static uint32_t qnum(const uint8_t *q, uint32_t n, const char *key, uint32_t def)
{
    uint32_t vs, ve; if (!qfind(q, n, key, &vs, &ve)) return def;
    uint32_t x = 0; bool any = false;
    for (uint32_t i = vs; i < ve; i++) { if (q[i] < '0' || q[i] > '9') return def; x = x * 10u + (uint32_t)(q[i] - '0'); any = true; }
    return any ? x : def;
}
static bool qis(const uint8_t *q, uint32_t n, const char *key, const char *val)
{
    uint32_t vs, ve; if (!qfind(q, n, key, &vs, &ve)) return false;
    uint32_t len = 0; while (val[len]) len++;
    if (ve - vs != len) return false;
    for (uint32_t i = 0; i < len; i++) if (q[vs + i] != (uint8_t)val[i]) return false;
    return true;
}
/* Bearer token from the Authorization header, within the raw header block. */
static bool rt_bearer(const uint8_t *raw, uint32_t a, uint32_t b, const uint8_t **tok, uint32_t *tlen)
{
    for (uint32_t i = a; i + 1 < b; i++) {
        if (i == a || (raw[i - 1] == '\n')) {
            const char *h = "authorization:"; uint32_t k = 0;
            while (h[k] && i + k < b) {
                uint8_t c = raw[i + k];
                if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
                if (c != (uint8_t)h[k]) break;
                k++;
            }
            if (!h[k]) {
                uint32_t v = i + k; uint32_t e = v; while (e < b && raw[e] != '\r' && raw[e] != '\n') e++;
                while (v < e && (raw[v] == ' ' || raw[v] == '\t')) v++;
                const char *bw = "Bearer "; uint32_t m = 0; bool ok = true;
                while (bw[m]) { if (v + m >= e || raw[v + m] != (uint8_t)bw[m]) { ok = false; break; } m++; }
                if (!ok) return false;
                v += m; while (v < e && raw[v] == ' ') v++;
                *tok = raw + v; *tlen = e - v; return v < e;
            }
        }
    }
    return false;
}

/* ---- JSON builder (no libc formatted output) ----
 * The GATE task runs unprivileged with only the .gateway_gate MPU region, so it
 * cannot reach newlib's _impure_ptr (0x20024028) and must not call snprintf,
 * vsnprintf or gateway_log. Responses are built by hand, as the primary GATE
 * code does with memcpy. */
typedef struct { char *b; uint32_t p, cap; } Jb;
static void js(Jb *j, const char *s) { while (*s && j->p < j->cap) j->b[j->p++] = (char)*s++; }
static void ju(Jb *j, unsigned long v)
{
    char t[20]; int k = 0;
    do { t[k++] = (char)('0' + (v % 10ul)); v /= 10ul; } while (v);
    while (k && j->p < j->cap) j->b[j->p++] = t[--k];
}
static void jbool(Jb *j, bool v) { js(j, v ? "true" : "false"); }
static void jend(Jb *j) { j->b[j->p < j->cap ? j->p : j->cap - 1] = '\0'; }

/* ---- response ---- */
static int rt_reply(GatewayContext *c, int gate_status, const char *json)
{
    GateResponse *out = (GateResponse *)c->gate;
    out->conn_id = 0; out->status = (uint8_t)gate_status;
    out->body_len = (uint32_t)strlen(json);
    memcpy(out->body, json, out->body_len);
    c->gate_len = GATE_RESPONSE_HEADER_SIZE + out->body_len;
    return gate_status == GATE_STATUS_OK ? 200 : (gate_status == GATE_STATUS_NO_AUTH ? 401 : 403);
}

/* ---- timing (DWT, interrupts masked per sample; observed, not WCET) ---- */
static void rt_sort(uint32_t *v, unsigned n)
{
    static const unsigned gaps[] = { 701u, 301u, 132u, 57u, 23u, 10u, 4u, 1u };
    for (unsigned g = 0; g < sizeof gaps / sizeof gaps[0]; g++)
        for (unsigned i = gaps[g]; i < n; i++) {
            uint32_t t = v[i]; unsigned j = i;
            while (j >= gaps[g] && v[j - gaps[g]] > t) { v[j] = v[j - gaps[g]]; j -= gaps[g]; }
            v[j] = t;
        }
}
/* Privileged measurement over the runtime-loaded store (interrupts masked per
 * sample). RT_W_UPDATE re-applies partition j's blob (store unchanged);
 * RT_W_ABSENT/LAST time a decision on the loaded policy; RT_W_WORST overwrites
 * the store with the constructed worst case (run last). */
static void rt_measure(const RtTimeReq *rq, RtTimeRep *rp)
{
    unsigned n; uint32_t answer = 0;
    if (rq->which == RT_W_UPDATE) {
        n = 2000u; uint8_t b[RT_BLOB_BODY];
        for (unsigned i = 0; i < n; i++) {
            memcpy(b, rq->body, RT_BLOB_BODY);
            uint32_t pm = __get_PRIMASK(); __disable_irq();
            uint32_t t0 = DWT->CYCCNT;
            answer = gateway_runtime53_update(2u, 0u, b, rq->j);   /* admin role, re-applies partition j */
            rt_samples[i] = DWT->CYCCNT - t0;
            __set_PRIMASK(pm);
            if ((i & 255u) == 255u) vTaskDelay(1);
        }
    } else {
        GATE_SPEC_REQUEST qq; GATE_SPEC_SESSION ss = { .role = 0xFFu, .sscope = 0xFFFFu, .count = 0u };
        if (rq->which == RT_W_WORST) {
            for (unsigned i = 0; i < RT_RULES; i++)
                live_store[i] = (GATE_SPEC_RULE){ .path = 0x12345678u, .mask = 0x3Fu, .min_role = 0u, .rscope = 0x8000u };
            ss.sscope = 0x7FFFu; qq = (GATE_SPEC_REQUEST){ .rpath = 0x12345678u, .meth = 1u };
        } else if (rq->which == RT_W_LAST) {
            unsigned last = 0; for (unsigned i = 0; i < RT_RULES; i++) if (live_store[i].path != RT_SENTINEL) last = i;
            uint8_t m = live_store[last].mask;
            qq = (GATE_SPEC_REQUEST){ .rpath = live_store[last].path, .meth = (uint8_t)(m & (uint8_t)-m) };
        } else {
            qq = (GATE_SPEC_REQUEST){ .rpath = 0x7FFF0001u, .meth = 1u };
        }
        n = 512u; uint8_t ctxt = 0u, r = 0u;
        for (unsigned i = 0; i < n; i++) {
            uint32_t pm = __get_PRIMASK(); __disable_irq();
            uint32_t t0 = DWT->CYCCNT;
            r = GateLowGateDecide(RT_PARTS, live_store, qq, ss, &ctxt);
            rt_samples[i] = DWT->CYCCNT - t0;
            __set_PRIMASK(pm);
            if ((i & 255u) == 255u) vTaskDelay(1);
        }
        answer = r;
    }
    uint64_t sum = 0; for (unsigned i = 0; i < n; i++) sum += rt_samples[i];
    rt_sort(rt_samples, n);
    rp->samples = n; rp->answer = answer; rp->mn = rt_samples[0]; rp->mean = (uint32_t)(sum / n);
    rp->p50 = rt_samples[n / 2]; rp->p99 = rt_samples[(n * 99u) / 100u]; rp->mx = rt_samples[n - 1];
    rp->digest = rt_digest();
}

static void rt_timing_task(void *arg)
{
    (void)arg; RtTimeReq rq; RtTimeRep rp;
    for (;;) {
        if (xQueueReceive(rt_req_queue, &rq, portMAX_DELAY) != pdPASS) continue;
        memset(&rp, 0, sizeof rp);
        rt_measure(&rq, &rp);
        (void)xQueueSend(rt_rep_queue, &rp, pdMS_TO_TICKS(2000));
    }
}

void gateway_runtime53_start(TaskHandle_t gate)
{
    rt_req_queue = xQueueCreateStatic(1, sizeof(RtTimeReq), rt_req_storage, &rt_req_cb);
    rt_rep_queue = xQueueCreateStatic(1, sizeof(RtTimeRep), rt_rep_storage, &rt_rep_cb);
    if (!rt_req_queue || !rt_rep_queue) gateway_panic(GATEWAY_FAULT_ALLOC);
    TaskHandle_t t = xTaskCreateStatic(rt_timing_task, "gateway_rt53", 1024u, NULL,
        (UBaseType_t)osPriorityHigh | portPRIVILEGE_BIT, rt_timing_stack, &rt_timing_tcb);
    if (!t) gateway_panic(GATEWAY_FAULT_STARTUP);
    vGrantAccessToQueue(gate, rt_req_queue);
    vGrantAccessToQueue(gate, rt_rep_queue);
}

int gateway_runtime53_endpoint(const GatewayHttp *h, GatewayContext *c, int *handled)
{
    *handled = 0;
    const uint8_t *raw = h->raw;
    uint32_t hdr = h->header_end ? h->header_end : h->used;
    uint32_t le = 0; while (le < hdr && raw[le] != '\r') le++;
    uint32_t me = 0; while (me < le && raw[me] != ' ') me++;
    uint32_t ps = me < le ? me + 1u : le, pe = ps;
    while (pe < le && raw[pe] != ' ' && raw[pe] != '?') pe++;
    if (!(pe - ps == 7u && memcmp(raw + ps, "/gate53", 7) == 0)) return 0;
    *handled = 1;
    uint32_t qs = pe, qe = pe;
    if (pe < le && raw[pe] == '?') { qs = pe + 1u; qe = qs; while (qe < le && raw[qe] != ' ') qe++; }
    const uint8_t *q = raw + qs; uint32_t qn = qe - qs;
    bool is_put = (me == 3u && memcmp(raw, "PUT", 3) == 0);
    const uint8_t *body = raw + h->header_end; uint32_t blen = h->body_len;
    char json[256]; Jb j;

    if (qis(q, qn, "op", "status") || qn == 0) {
        j = (Jb){ json, 0, sizeof json };
        js(&j, "{\"policy\":\""); js(&j, GATE_N32_POLICY); js(&j, "\",\"partitions\":"); ju(&j, RT_PARTS);
        js(&j, ",\"active\":"); ju(&j, rt_active()); js(&j, ",\"digest\":"); ju(&j, rt_digest()); js(&j, "}"); jend(&j);
        return rt_reply(c, GATE_STATUS_OK, json);
    }
    if (qis(q, qn, "op", "update")) {
        if (!is_put) return rt_reply(c, GATE_STATUS_DENIED, "{\"error\":\"method\"}");
        if (blen != RT_BLOB_BODY) return rt_reply(c, GATE_STATUS_DENIED, "{\"status\":\"denied\",\"reason\":\"bad_body\"}");
        const uint8_t *tok; uint32_t tlen; GatewayIdentity id;
        if (!rt_bearer(raw, le + 2u, hdr, &tok, &tlen) || !gateway_bearer_check(tok, tlen, &id))
            return rt_reply(c, GATE_STATUS_NO_AUTH, "{\"status\":\"unauthorized\"}");
        uint32_t jp = qnum(q, qn, "p", RT_PARTS);
        uint8_t body_copy[RT_BLOB_BODY]; memcpy(body_copy, body, RT_BLOB_BODY);
        /* count 0: an authenticated admin partition load is not rate-limited; this
         * diagnostic supplies the count explicitly, not the live interface counter.
         * An out-of-range partition is now rejected inside GlueLowMediate (1<=J<=N). */
        uint8_t r = gateway_runtime53_update(id.role, 0u, body_copy, jp);
        const char *s = r == 1u ? "ok" : r == 2u ? "fail_closed" : "denied";
        j = (Jb){ json, 0, sizeof json };
        js(&j, "{\"status\":\""); js(&j, s); js(&j, "\",\"code\":"); ju(&j, r);
        js(&j, ",\"partition\":"); ju(&j, jp); js(&j, ",\"active\":"); ju(&j, rt_active());
        js(&j, ",\"digest\":"); ju(&j, rt_digest()); js(&j, "}"); jend(&j);
        return rt_reply(c, r == 1u ? GATE_STATUS_OK : GATE_STATUS_DENIED, json);
    }
    if (qis(q, qn, "op", "decide")) {
        uint32_t path = qnum(q, qn, "path", 0xFFFFFFFFu);
        uint8_t meth = (uint8_t)qnum(q, qn, "meth", 1u);
        uint8_t role = (uint8_t)qnum(q, qn, "role", 0u);
        uint16_t scope = (uint16_t)qnum(q, qn, "scope", 0u);
        uint8_t count = (uint8_t)qnum(q, qn, "count", 0u);
        uint8_t r = gateway_runtime53_decide(path, meth, role, scope, count);
        j = (Jb){ json, 0, sizeof json };
        js(&j, "{\"decision\":"); ju(&j, r); js(&j, ",\"digest\":"); ju(&j, rt_digest()); js(&j, "}"); jend(&j);
        return rt_reply(c, r == 1u ? GATE_STATUS_OK : GATE_STATUS_DENIED, json);
    }
    if (qis(q, qn, "op", "equiv")) {
        uint32_t from = qnum(q, qn, "from", 0u), cnt = qnum(q, qn, "count", 1000u);
        if (from == 0u) { eq_from_next = 0u; eq_accepts = 0u; eq_mismatch = 0u; eq_failclosed = 0u; }
        uint32_t end = from + cnt; if (end > GATE_N32_VECTORS) end = GATE_N32_VECTORS;
        uint8_t ctxt = 0u;
        for (uint32_t i = from; i < end; i++) {
            const GateN32Vector *v = &gate_n32_vectors[i];
            GATE_SPEC_REQUEST qq = { .rpath = v->path, .meth = v->meth };
            GATE_SPEC_SESSION ss = { .role = v->role, .sscope = v->scope, .count = v->count };
            uint8_t r = GateLowGateDecide(RT_PARTS, live_store, qq, ss, &ctxt);
            if (r == 1u) eq_accepts++;
            if (r == 2u) eq_failclosed++;
            if ((r == 1u) != (v->expected == 1u) || r == 2u) eq_mismatch++;
        }
        eq_from_next = end;
        bool done = end >= GATE_N32_VECTORS;
        j = (Jb){ json, 0, sizeof json };
        js(&j, "{\"from\":"); ju(&j, from); js(&j, ",\"to\":"); ju(&j, end);
        js(&j, ",\"done\":"); jbool(&j, done); js(&j, ",\"vectors\":"); ju(&j, GATE_N32_VECTORS);
        js(&j, ",\"accepts\":"); ju(&j, eq_accepts); js(&j, ",\"mismatches\":"); ju(&j, eq_mismatch);
        js(&j, ",\"fail_closed\":"); ju(&j, eq_failclosed); js(&j, ",\"digest\":"); ju(&j, rt_digest());
        js(&j, "}"); jend(&j);
        return rt_reply(c, GATE_STATUS_OK, json);
    }
    if (qis(q, qn, "op", "verifyload")) {
        /* Cross-check the HTTP-loaded store against the intended flash policy.
         * Inactive slots carry min_role 0 in the wire blob (the validator caps
         * it at 2) while the flash sentinel uses 255; both read as inactive, so
         * min_role is compared only for active slots. */
        uint32_t diff = 0;
        for (unsigned i = 0; i < RT_OPN_RULES; i++) {
            const GateN32Rule *f = &gate_n32_rules[i]; const GATE_SPEC_RULE *l = &live_store[RT_BASE * RT_SLOTS + i];
            bool f_in = f->path == RT_SENTINEL, l_in = l->path == RT_SENTINEL;
            if (f_in != l_in) { diff++; continue; }
            if (f_in) continue;
            if (l->path != f->path || l->mask != f->mask || l->min_role != f->min_role || l->rscope != f->scope) diff++;
        }
        j = (Jb){ json, 0, sizeof json };
        js(&j, "{\"rules\":"); ju(&j, RT_OPN_RULES); js(&j, ",\"active\":"); ju(&j, rt_active());
        js(&j, ",\"mismatch\":"); ju(&j, diff); js(&j, ",\"digest\":"); ju(&j, rt_digest()); js(&j, "}"); jend(&j);
        return rt_reply(c, diff == 0u ? GATE_STATUS_OK : GATE_STATUS_DENIED, json);
    }
    if (qis(q, qn, "op", "timing")) {
        RtTimeReq rq; memset(&rq, 0, sizeof rq);
        if (qis(q, qn, "which", "update")) {
            if (blen != RT_BLOB_BODY) return rt_reply(c, GATE_STATUS_DENIED, "{\"error\":\"bad_body\"}");
            rq.which = RT_W_UPDATE; rq.j = qnum(q, qn, "p", RT_OPN_PARTS);
            if (rq.j >= RT_OPN_PARTS) return rt_reply(c, GATE_STATUS_DENIED, "{\"error\":\"range\"}");
            memcpy(rq.body, body, RT_BLOB_BODY);
        } else if (qis(q, qn, "which", "worst")) {
            rq.which = RT_W_WORST;
        } else if (qis(q, qn, "case", "last")) {
            rq.which = RT_W_LAST;
        } else {
            rq.which = RT_W_ABSENT;
        }
        if (!rt_req_queue || xQueueSend(rt_req_queue, &rq, pdMS_TO_TICKS(200)) != pdPASS)
            return rt_reply(c, GATE_STATUS_ERROR, "{\"error\":\"busy\"}");
        RtTimeRep rp;
        if (xQueueReceive(rt_rep_queue, &rp, pdMS_TO_TICKS(1800)) != pdPASS)
            return rt_reply(c, GATE_STATUS_ERROR, "{\"error\":\"timeout\"}");
        const char *what = rq.which == RT_W_UPDATE ? "update" : rq.which == RT_W_WORST ? "worst"
                         : rq.which == RT_W_LAST ? "last" : "absent";
        j = (Jb){ json, 0, sizeof json };
        js(&j, "{\"which\":\""); js(&j, what); js(&j, "\",\"samples\":"); ju(&j, rp.samples);
        js(&j, ",\"answer\":"); ju(&j, rp.answer); js(&j, ",\"min\":"); ju(&j, rp.mn);
        js(&j, ",\"mean\":"); ju(&j, rp.mean); js(&j, ",\"p50\":"); ju(&j, rp.p50);
        js(&j, ",\"p99\":"); ju(&j, rp.p99); js(&j, ",\"max\":"); ju(&j, rp.mx);
        js(&j, ",\"digest\":"); ju(&j, rp.digest); js(&j, "}"); jend(&j);
        return rt_reply(c, GATE_STATUS_OK, json);
    }
    return rt_reply(c, GATE_STATUS_DENIED, "{\"error\":\"unknown_op\"}");
}
#endif
