# Decision-time distributions and critical-section attribution (2026-10-21)

NUCLEO-F767ZI, Cortex-M7 at 96 MHz (`core_hz=96000000` logged), caches off unless
stated, Debug images as in the paper's earlier F767 evidence. All values are DWT
cycle counts observed on the board: **observed, not WCET**. Source: the working
tree at `provenance/git-base.txt` plus the changes committed with this directory
(timing extension in `Gateway/Paper/paper_gate_n32.c` behind
`GATEWAY_PAPER_TIMING_DIST`, caller attribution in `Gateway/MPUPort/port.c` and
`Gateway/Paper/paper_control_r4.c` behind `GATEWAY_R4_CONTROL`). Images were
built with `provenance/build_timing.py` (sets flags, runs the unchanged
`Gateway/tools/build_firmware.py`, restores flags) and staged by a copy of
`d1_stage_variant.py` whose only change is the destination directory
(`provenance/stage-variant-path-rewrite.diff`). Each staged image has its
`source-manifest.json` (ELF and source hashes) and `build.log`.

## 1. Decision-time distributions (`timing-dist-*`)

Variants: the verified composed gate (`GateLowGateDecide`) with the OPNsense
policy (n = 53) and with the SCALANCE XB-200 policy (n = 32), each also at n = 1.
Per case: 100 warm-up calls, then 10,000 samples (n = 1, empty bracket, update)
or 2,000 samples (n = 32/53); min, mean, p50, p99, max. Each sample brackets one
call with two `DWT->CYCCNT` reads; the empty bracket is 10 cycles (reported, not
subtracted). `irq=on`: interrupts enabled (deployed condition); `irq=off`: PRIMASK
set around each sample (the call's own cost). The core task yields for one tick
every 256 samples (outside the timed region) so the watchdog task runs.

Cases: `first`/`last` match, `absent` path, and **`worst`**, a constructed
worst-case input: every slot of every partition matches path, method and role and
fails the last conjunct (scope), so the short-circuit evaluation
(`Partition8.c`: path, method, role, scope) checks all four conditions in all
8n slots and denies. Also the PolicyBlob update gate (`BlobLowUpdateDecide`) on a
valid 8-rule body (admin) and the same body from an operator (rejected).

10 fresh boots per variant (hardware reset; `boot01` flashed). **The results are
identical to the cycle across all 10 boots** although the boots' overall logs
differ: with caches off, no network load during the window and the per-256
yield aligning each batch to the 1 ms tick, the same periodic interrupts hit the
same samples. The boots therefore show reproducibility, not independent samples;
the irq-on excess over irq-off is periodic-interrupt preemption.

Cycles, min / mean / max (`summary.json` per variant has p50, p99 and all cases):

| Case | OPNsense build, irq on | irq off | SCALANCE build, irq on | irq off |
|---|---|---|---|---|
| n = 1, first match | 3,287 / 3,322 / 3,832 | 3,287 / 3,287 / 3,293 | 3,266 / 3,295 / 3,805 | 3,261 / 3,261 / 3,267 |
| n = 1, constructed worst | 3,956 / 4,015 / 7,821 | 3,956 / 3,972 / 3,978 | 3,930 / 3,987 / 4,479 | 3,930 / 3,946 / 3,952 |
| n = 53 (32), constructed worst | 172,072 / 172,461 / 176,107 | 170,876 / 170,891 / 170,898 | 104,287 / 104,404 / 108,146 | 103,440 / 103,455 / 103,462 |
| Update gate, valid (applied) | 4,162 / 4,238 / 8,023 | 4,200 / 4,200 / 4,220 | 4,166 / 4,208 / 4,936 | 4,169 / 4,169 / 4,190 |
| Update gate, operator (rejected) | 5,932 / 6,013 / 6,737 | 5,933 / 5,965 / 5,967 | 5,902 / 5,987 / 9,785 | 5,902 / 5,934 / 5,936 |

At 96 MHz: 3,978 cycles = 41.4 µs; 7,821 = 81.5 µs; 170,898 = 1.78 ms;
176,107 = 1.83 ms. The masked (own-cost) maximum is within 25 cycles of the
minimum in every case: the decision is essentially cycle-deterministic for a given
input. Equivalence on the board in the same boots: `[GATE-N32]` 20,256/20,256
(OPNsense) and 17,760/17,760 (SCALANCE) oracle vectors, 0 mismatches,
0 fail-closed.

**Build dependence.** The paper's earlier headline (4,643–4,906 cycles median at
n = 1, max 5,606) came from an earlier SCALANCE build. Both builds here measure
about 3.3k at n = 1 for the same gate code. The difference is a fixed per-call
cost that follows the placement of the C library's `memset` (called once per
decision) in flash with caches off: offset 24 mod 32 bytes in the slow build,
4 and 28 in the fast builds (see §2 for the same effect on `memcpy`). Across the
builds measured so far the n = 1 decision ranges about 3.3k–4.9k cycles median.

## 2. Critical-section attribution (`crit-control-*`)

Control images (control task at 1 kHz above all network tasks, as in the paper's
control experiments) with the new attribution: return address of the outermost
`vPortEnterCritical` and a top-8 table of the longest sections by caller
(`[CRIT]` lines). Loads via the unchanged `Gateway/tools/r4_control_capture.py`
(`--d1`), idle/valid/denied/malformed, each over the 10,000-release window.
`crit-summary.json` resolves callers with `addr2line`.

| Image | memcpy offset mod 32 | idle | valid | denied | malformed |
|---|---|---|---|---|---|
| token bucket on (`bucket1`) | 22 | 839 | 13,695 | 13,168 | 13,139 |
| token bucket off (`bucket0`) | 14 | 913 | **36,166** | **34,876** | **34,703** |
| token bucket off, I-cache on | 30 | – | 13,520 | 13,005 | – |

**Located.** In every image and loaded scenario the longest section is
`xQueueGenericSend` (`queue.c:977`), followed by `xQueueReceive`
(`queue.c:1537`): FreeRTOS copies each queue item with `memcpy` inside the
kernel's critical section, and the gateway's compartments exchange ~1.5 KB
messages (`AppJob` 1,608 B, `AppResult` 1,544 B, reply 1,564 B; storage in
`Gateway/Network/gateway_r4_boundary.c`). The ~36k-cycle section of the
2026-09-30 builds (`final-control` bucket 1 and `final2-control` bucket 0) is
reproduced by the current source with the token bucket off: same caller,
34.7–36.2k cycles, 0 misses at 1 kHz.

**Cause, as far as isolated.** The source is identical between the 13.7k and
36.2k images; the call path is the same; the queue storage is at identical
word-aligned addresses in both. What moves is code placement: `memcpy` sits at
offset 22 mod 32 in the fast image and 14 in the slow one. With the instruction
cache on, the slow configuration returns to 13.0–13.5k cycles. This is
consistent with instruction fetch from flash (caches off) making the copy loop's
cost depend on its alignment; it is not fully isolated, because enabling the
cache also moved `memcpy` (to offset 30).

**Consequence for deadlines.** Blocking of 13.1–13.7k cycles (≈143 µs) exceeds
the 10 kHz period (9,600 cycles), which explains the 10 kHz misses already
reported; 36k exceeds the 4 kHz period (24,000 cycles), which explains the 4 kHz
misses in the affected builds. Remedies, not applied here: enable the
instruction cache (or place `memcpy` in ITCM RAM), or stop copying 1.5 KB
messages inside the kernel's critical section (pass ownership of a buffer by
index instead of copying it through the queue).

## Not done / notes

- No WCET claim; no MBPTA. The constructed worst case is the structurally
  longest path of the decision; the measured values are observed.
- Whole-request (extract + authenticate + count + decide) distributions were not
  collected; the firmware's per-request logging gives averages only.
- `board_test.py` acceptance failed on every timing boot only because the
  measurement burst causes `log_drops` in concurrent heartbeat lines; all 23
  `[GATE-DIST]` lines and the `done` marker are present in every boot.
- The attribution table lives in ordinary RAM (the privileged region is full in
  control images); it is written only by privileged critical-section code and
  read after the window closes. Updating it adds a few cycles after the measured
  interval, before interrupts are re-enabled.
- `/dev/ttyACM1` no longer exists on this host; the tools use the stable
  `/dev/serial/by-id/...STLink_066FFF555567894967085545-if02` path, which is
  now `ttyACM2`.
