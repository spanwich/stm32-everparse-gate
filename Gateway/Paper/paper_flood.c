/* Measurement-only on-board flood (GATEWAY_PAPER_FLOOD, off in the primary image).
 * A low-priority privileged task drives the SAME decision path the live /api uses
 * (gateway_glue_set_identity -> gateway_glue_mediate: GlueRateCountAndIdentify, then
 * GlueLowMediate over the 64-partition store) with worst-case-deny requests as fast as it
 * can, beside the control task. The OPNsense policy is copied into partitions 2..54 first.
 * Per rate-counter window it logs requests scanned (admitted by the counter), refused,
 * DWT cycles inside admitted decisions (scans), inside refusals, and the window span.
 * It does not use the network and changes no gate, mediation or glue code. */
#include "paper_experiment.h"
#if GATEWAY_PAPER_FLOOD
#include "gateway_core.h"
#include "gateway_glue.h"
#include "gateway_log.h"
#include "gateway_platform.h"
#include "path_hashes.h"
#include "paper_dwt.h"
#include "paper_gate_n32_data.h"
#include "FreeRTOS.h"
#include "task.h"
#include "cmsis_os2.h"
#include <string.h>

typedef struct { uint32_t path; uint8_t mask, min_role; uint16_t scope; } FloodRule;   /* == GATE_SPEC_RULE layout */
#define FLOOD_STACK_WORDS 1024u
static StackType_t flood_stack[FLOOD_STACK_WORDS];
static StaticTask_t flood_tcb;

static void build_frame(uint8_t *w)
{
    memset(w, 0, 175);
    w[1] = (uint8_t)PATH_POLICY; w[2] = (uint8_t)(PATH_POLICY >> 8);
    w[3] = (uint8_t)(PATH_POLICY >> 16); w[4] = (uint8_t)(PATH_POLICY >> 24);
    w[5] = METHOD_GET;            /* count/role/scope/subject are written by set_identity */
}

static void flood_task(void *arg)
{
    (void)arg;
    if (!paper_dwt_enable("flood")) for (;;) vTaskDelay(portMAX_DELAY);
    FloodRule *store = (FloodRule *)gateway_glue_live_store_raw();
    for (unsigned i = 0; i < 8u * GATE_N32_PARTITIONS; i++)
        store[8u + i] = (FloodRule){ gate_n32_rules[i].path, gate_n32_rules[i].mask,
                                     gate_n32_rules[i].min_role, gate_n32_rules[i].scope };
    extern uint32_t gateway_platform_tests_complete(void);
    while (!gateway_platform_tests_complete()) vTaskDelay(pdMS_TO_TICKS(20));   /* self-tests use the synthetic clock + the rate counter */
    vTaskDelay(pdMS_TO_TICKS(1500));
    gateway_rate_state_init();
    gateway_log("[FLOOD] start window_ms=%lu partitions=%u (OPNsense in 2..%u), worst-case-deny, unpaced\n",
                (unsigned long)GATEWAY_RATE_WINDOW_MS, (unsigned)GATEWAY_LIVE_PARTS,
                (unsigned)(GATE_N32_PARTITIONS + 1u));
    uint8_t frame[175], subject[32] = { 0 }, app[64];
    int prev = -1;                                    /* last count; -1 = none (255 is a real, capped count) */
    uint32_t win = 0, scans = 0, refused = 0, scan_cyc = 0, ref_cyc = 0, win_t0 = DWT->CYCCNT, n = 0;
    uint32_t other = 0;
    for (;;) {
        build_frame(frame);
        gateway_glue_set_identity(frame, gateway_tick_ms(), ROLE_OPERATOR, 1u, 0u, subject);
        uint8_t count = frame[0];
        if (prev >= 0 && (int)count < prev) {             /* new rate window */
            uint32_t now = DWT->CYCCNT;
            gateway_log("[FLOOD] win=%lu scans=%lu refused=%lu other=%lu scan_cyc=%lu ref_cyc=%lu span_cyc=%lu\n",
                        (unsigned long)win, (unsigned long)scans, (unsigned long)refused, (unsigned long)other,
                        (unsigned long)scan_cyc, (unsigned long)ref_cyc, (unsigned long)(now - win_t0));
            win++; scans = refused = other = scan_cyc = ref_cyc = 0; win_t0 = now;
        }
        prev = (int)count;
        uint8_t nr = 0; uint32_t app_len = 0;
        uint32_t t0 = DWT->CYCCNT;
        uint8_t r = gateway_glue_mediate(frame, 175, &nr, app, &app_len, 1u);
        uint32_t dt = DWT->CYCCNT - t0;
        if (r == 3u) { refused++; ref_cyc += dt; }
        else if (r == 2u) { scans++; scan_cyc += dt; }
        else other++;
        if ((++n & 255u) == 0u) vTaskDelay(1);            /* let the 1 s watchdog task run */
    }
}

void gateway_paper_flood_start(void)
{
    TaskHandle_t h = xTaskCreateStatic(flood_task, "p_flood", FLOOD_STACK_WORDS, NULL,
                                       (UBaseType_t)osPriorityBelowNormal | portPRIVILEGE_BIT, flood_stack, &flood_tcb);
    if (!h) gateway_panic(GATEWAY_FAULT_STARTUP);
}
#endif
