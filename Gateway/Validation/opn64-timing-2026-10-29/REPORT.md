# Timing on glue/opn64-primary (n=64 live store, 500 ms rate window), 2026-10-29/30

Branch `glue/opn64-primary` (local, not pushed). Variants A0 / A1v / A2v, Debug images, 96 MHz, caches off,
354 self-tests on every image; DWT enable via `paper_dwt_enable()` (unlock + verify). Observed distributions, not WCET.
Live decision path: wire check -> rate test (count >= 50 refused, NO scan) -> `GateLowGateDecide` over N = 64 partitions.
Layout used for the n=64 cases: partition 1 = gateway default (3 rules), partitions 2..54 = the 420 OPNsense rules,
55..64 inactive sentinel. Distributions: 10 boots x 2,000 samples per case (interrupts off and on).

## k: worst-case decision at n = 64 (cycles; ms at 96 MHz = cycles / 96,000)

irq-off max over 10 boots | irq-on p99 / max:

| case | A0 | A1v (baseline) | A2v (ITCM) |
|---|---|---|---|
| first rule (partition 2, early exit) | 5,920 | 6,464 | 3,806 |
| last active rule (partition 54) | 150,162 | 156,476 | 91,673 |
| (a) installed OPNsense, full-scan deny (absent path) | 178,132 (1.86 ms) | 185,531 (1.93 ms) | 108,648 (1.13 ms) |
| (b) constructed worst: all 64 partitions full, every slot fails the last check (C_max) | 203,284 (2.12 ms) | **210,427 (2.19 ms)** | 125,417 (1.31 ms) |
| (b) irq-on p99 / max | 205,869 / 209,328 | 212,650 / 216,410 | 127,095 / 130,590 |
| n = 53 constructed worst (comparison) | 168,458 | 174,420 | 103,951 |

(a) is realistic: sentinel partitions 55..64 still cost a full-slot comparison, so the installed policy costs ~88% of (b).
The A1v n=53 worst here (174,420) vs the earlier glue campaign (173,872) and the paper's 168,519: same image family,
same decision code; the spread between builds of identical source is ~1-3% and follows flash layout (caches off); not isolated.

## l: CPU demand under the rate window (derived, 49 x C_max / window)

N_max = 50 -> at most 49 admitted (scanned) requests per window; refused requests pay only the wire check and counter step.

| | C_max | 49 x C_max | share of a 500 ms window | share of the old 49 ms window |
|---|---|---|---|---|
| A0 | 2.12 ms | 103.8 ms | 20.8 % | 212 % (unschedulable) |
| A1v | 2.19 ms | 107.4 ms | **21.5 %** | 219 % (unschedulable) |
| A2v | 1.31 ms | 64.0 ms | 12.8 % | 131 % (unschedulable) |

500 ms is the first window length for which N_max x C_max fits (the earlier 17% estimate used the n = 53 figure).
The measured on-board flood (busy cycles per window) is part of the opn64 experiment, run later.

## Control-task deadlines on the n = 64 primary (24 images x idle/valid/denied/malformed; 10,000 releases each)
Misses = late + collapsed releases. Full matrix: `variants-summary.json`; per-run files in each `*-control-*` dir.
- A1v (baseline): 0 misses everywhere except ONE late release at 10 kHz bucket 1 `valid`; max latency 11,339 cycles.
- A2v: 0 misses everywhere except ONE at 10 kHz bucket 1 `malformed`; max latency 11,123 cycles.
- A0: 0 misses at 1 kHz and 4 kHz (the earlier glue campaign had misses at 4 kHz bucket 0; not reproduced here);
  at 10 kHz misses 106-156 per run on valid/denied/malformed (both buckets); max latency 16,822 cycles.
- The single A1v/A2v misses at 10 kHz are new relative to the glue campaign (0). Not investigated; one release in 10,000.
- A0 critical sections (`crit-summary.json`, A0 crit images only): see file; caller `xQueueGenericSend queue.c:977`.
These load scenarios send valid / unauthenticated / malformed requests: the first two decide cheaply; the full-scan
OPNsense deny is the opn64 experiment, not part of this matrix.

## Reproduce
`bash run_opn64_timing.sh` (idempotent); provenance scripts in `provenance/`. SCALANCE n=32 images were not rebuilt
(gate-only cost, independent of the live path; see glue-timing-2026-10-29).
