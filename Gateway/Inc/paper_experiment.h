#ifndef PAPER_EXPERIMENT_H
#define PAPER_EXPERIMENT_H
/* Archived paper variants override these; the primary firmware stays at 0. */
#ifndef GATEWAY_PAPER_TIMING
#define GATEWAY_PAPER_TIMING 0
#endif
#ifndef GATEWAY_PAPER_CONTROL
#define GATEWAY_PAPER_CONTROL 0
#endif
#ifndef GATEWAY_PAPER_ALLOC
#define GATEWAY_PAPER_ALLOC 0
#endif
#ifndef GATEWAY_R4_MPU
#define GATEWAY_R4_MPU 1
#endif
#ifndef GATEWAY_R4_FAULT_INJECT
#define GATEWAY_R4_FAULT_INJECT 0
#endif
#ifndef GATEWAY_R4_NO_HTTP_LOG
#define GATEWAY_R4_NO_HTTP_LOG 1
#endif
#ifndef GATEWAY_R4_TRACE_NET
#define GATEWAY_R4_TRACE_NET 0
#endif
/* Section 14: access decisions by the verified composed gate (GateLowGateDecide);
 * 0 keeps the monolithic RbacPolicy access validator for matched comparisons. */
#ifndef GATEWAY_VERIFIED_GATE
#define GATEWAY_VERIFIED_GATE 1
#endif
/* Section 14 labelled variant: SCALANCE n = 32 policy-as-data check and gate cycles. */
#ifndef GATEWAY_PAPER_GATE_N32
#define GATEWAY_PAPER_GATE_N32 0
#endif
/* D1.8 final-image probes (separate labelled images): 1-15 run in NET, 20 GATE,
 * 21 APP, 22 AUTH. See Gateway/tools/d1_run_final_probes.py. */
#ifndef GATEWAY_D1_PROBE
#define GATEWAY_D1_PROBE 0
#endif
#ifndef GATEWAY_D1_TOKEN_BUCKET
#define GATEWAY_D1_TOKEN_BUCKET 1
#endif
#ifndef GATEWAY_D1_FAULT_ONCE
#define GATEWAY_D1_FAULT_ONCE 0
#endif
#ifndef GATEWAY_R4_FAST_CLOCK
#define GATEWAY_R4_FAST_CLOCK 0
#endif
#ifndef GATEWAY_R4_CACHES
#define GATEWAY_R4_CACHES 0
#endif
#ifndef GATEWAY_R4_OPT_O2
#define GATEWAY_R4_OPT_O2 0
#endif
#ifndef GATEWAY_R4_CONTROL
#define GATEWAY_R4_CONTROL 0
#endif
#ifndef GATEWAY_R4_CONTROL_HZ
#define GATEWAY_R4_CONTROL_HZ 1000
#endif
#ifndef GATEWAY_R4_CONTROL_HIGH
#define GATEWAY_R4_CONTROL_HIGH 1
#endif
#ifndef GATEWAY_R4_TIMING_MASK_IRQ
#define GATEWAY_R4_TIMING_MASK_IRQ 0
#endif
#endif
