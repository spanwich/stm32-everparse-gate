# Timing campaign on glue/verified (b8a7f4a + DWT fix), 2026-10-29

Variants A0 / A1v / A2v only (no A1/A2). Debug images, 96 MHz, caches off, 322
self-tests on every image. Gate/mediation/glue code is the committed `b8a7f4a` tip
(`GlueLowMediate`, `GlueRate` 49 ms window); the only source change in this
campaign is the measurement-only `Gateway/Paper/paper_dwt.h` (commit `5275073`).
Observed distributions, not WCET. Nothing was sent over the F767 serial port other
than read-only capture; no RESET; `/dev/ttyACM0` untouched. Not pushed.

## Discarded first dist run (kept for the record)

The first post-reboot timing-dist run (all five images, `discarded-no-dwt-unlock/`)
reported 0 cycles for every `[GATE-DIST]` sample. Cause: after the PC reboot the
Cortex-M7 DWT stayed locked (no debugger had unlocked it) and the firmware's
`DWT->CTRL |= CYCCNTENA` was ignored; the same ELF had produced real values before
the reboot because a debug session had unlocked the DWT. Fix: `paper_dwt_enable()`
(TRCENA, `DWT->LAR` unlock, `CYCCNT = 0`, `CYCCNTENA`, read-back, verify the counter
advances, loud abort otherwise; commit `5275073`), and `summarize_timing.py` now
rejects any image whose decide/update maximum is 0. The five dist images were rebuilt
and re-run (10 boots each); the control images were not affected (their max-latency and miss figures are
non-zero and vary with load, i.e. the counter ran). Raw zero logs retained, nothing deleted.

## Gate cost (timing-dist, 10 boots x 10,000 samples; interrupts off, max cycles)

| case | A0 | A1v | A2v | 2026-10-21 A0 / A1v / A2v |
|---|---|---|---|---|
| decide n=1 first | 3264 | 3593 | 2118 | 3293 / 3500 / 2124 |
| decide n=1 worst | 3940 | 4245 | 2504 | 3978 / 4147 / 2510 |
| decide n=53 worst | 170,734 | 173,872 | 103,957 | 170,898 / 168,519 / 103,962 |
| update n=1 valid | 4163 | 4552 | 3929 | 4220 / 4573 / 3970 |
| update n=1 wrong_role | 5895 | 6341 | 5753 | 5967 / 6308 / 5722 |

SCALANCE n=32 worst: A0 103,387, A1v 105,365 (summary in `variants-summary.json`).

**A1v n=53 worst differs from the paper's 168,519: 173,872 now (+5,353 cycles, +3.2%).**
A0 (170,734 vs 170,898) and A2v (103,957 vs 103,962) reproduce the earlier numbers
within 0.1%, so the decision code itself did not get slower; the A1v delta is
specific to that image. Probable cause (hypothesis, not isolated): the glue
integration changed the flash layout of the A1v image (the verified memcpy moved from
0x08030580 to 0x08030b40, text +2,164 B), and with caches off the n=53 scan loop is
sensitive to flash-line/prefetch alignment; the other two images (A0 flash layout not
affecting the loop, A2v running from ITCM) show no change. This was not isolated by an
alignment experiment.

## Control-task deadlines (24 images x idle/valid/denied/malformed)

Misses = late + collapsed releases over the 10,000-release window. Full matrix in
`variants-summary.json`; per-run summaries under each `*-control-*` dir.
- A1v and A2v (norank images): 0 misses at 1/4/10 kHz, bucket 0 and 1, all four loads.
  Maximum release-to-run latency under load: A1v 12,052 cycles, A2v 3,840 cycles.
- A0 (norank): 0 misses at 1 kHz; misses at 4 kHz bucket 0 (valid 161+486, denied
  137+368, malformed 137+299) and at 10 kHz (bucket 0: 18+643, 14+532, 12+504;
  bucket 1: 8+141, 2+121, 0+105). A0 4 kHz bucket 1 has 0 misses.
- A0 critical sections (`crit-summary.json`, crit-control images): longest section
  ~36.1k cycles, caller `xQueueGenericSend queue.c:977` (the byte-loop memcpy).
  Crit images exist for A0 only, by decision; A1v/A2v maxima come from the norank
  images.

## Code and ITCM sizes
text_flash: A0 246,016 B, A1v 246,404 B, A2v 252,372 B. A2v ITCM: privileged 5,848 B,
shared 4,944 B, free 5,592 of 16,384 B.

## D1 injection probes
A1v: 18 probes, A2v: 21 probes (16-18 are the ITCM-region probes, already in the
committed source). Every probe result field (escaped, reboot self-tests, operator
status after reset, board exit code) is identical to the committed 2026-10-21
baseline for both variants (`a1v-probes/`, `a2v-probes/`).

## Runtime-53 re-run (on `GlueLowMediate` n=53)
`runtime53/v11-runtime53-glue/`: 322/322 self-tests; 53/53 partitions loaded in
1.07 s through the verified update gate; verify-load 0 mismatches (420 active of 424
slots); 6 negative cases rejected with the digest unchanged; equivalence sweep
20,256/20,256, 0 mismatches, 0 fail-closed; e2e 200/200; DWT: update 7,081 mean
cycles (first/middle/last partition), decide n=53 worst 169,947 max; absent 149,909;
last 149,682. Privileged inventory taken from this image.

## Reproduce
`bash run_glue_timing.sh` (idempotent), `run_phase2_probes.sh`, `run_runtime53.sh`;
provenance scripts are in `provenance/`. Staged paper extract: `paper-extract/`
(regenerate with `provenance/refresh_extract.py`).
