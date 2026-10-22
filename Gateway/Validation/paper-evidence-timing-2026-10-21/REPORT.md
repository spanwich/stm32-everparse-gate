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

## 3. Alternatives with trade-offs: A0 / A1 / A2 (2026-10-22)

The copy-based pipeline stays: copying through queues keeps the strongest
compartment boundary (no shared buffer, no check-then-use window). The variants
change only how fast and how placement-independent the copy and the gate run.

| Variant | What changes | Flags (source commit `2782477`) |
|---|---|---|
| **A0** baseline | newlib-nano `memcpy`/`memset` (byte loops) in flash, caches off | default |
| **A1** | word-at-a-time `memcpy`/`memset` (`Gateway/Platform/gateway_memops.c`), still in flash | `GATEWAY_FAST_MEMOPS=1` |
| **A2** | A1, plus FreeRTOS `queue.c`, the memops, the composed gate and the update-gate wrapper execute from ITCM RAM | `GATEWAY_FAST_MEMOPS=1 GATEWAY_ITCM=1` (linker script and startup from `Gateway/Provenance/itcm/`, swapped in at build time) |

A3 (FreeRTOS message buffers, copy outside the critical section) was dropped:
it is more complex and, per the analysis, slower than A2.

**A0 identity.** A0 images built from `2782477` have the same loadable bytes as
the 2026-10-21 images (`crit-control-1000-bucket1` rebuilt as
`identity-check-crit-control-1000-bucket1`; `objcopy -O binary` SHA-256
`e3b20d52…` for both). The new flags compile to nothing when 0.

### 3.1 A2 memory layout and MPU

ITCM RAM is 16 KB at `0x0` (zero wait state, CPU-only).
- `0x0000–0x07FF` is left empty, as a null guard.
- `0x0800–0x1FFF` holds `queue.c`'s privileged functions (5,848 B). Only
  privileged code reaches it, through the default map
  (`portMPU_BACKGROUND_ENABLE`).
- `0x2000–0x3FFF` holds the memops (438 B), the composed gate, `Partition8`,
  `UniversalRate` and the PolicyBlob wrapper (4,960 B in total). Every task
  that runs unprivileged gets this window as one read-only, executable 8 KB
  MPU region (`GATEWAY_ITCM_SHARED_REGION`, `paper_experiment.h`): APP, GATE,
  AUTH, NET input, and the platform network task and lwIP `tcpip` thread, which
  drop privilege at runtime.
- The startup code copies both images from flash before `.bss` is cleared.
  Calls back to flash go through linker-generated 8-byte veneers.
- `RbacPolicyValidatePolicyBlob` (4,216 B) did not fit in the 3,232 B left in
  the shared window, so it stays in flash.

**ITCM budget.** 10,808 of 16,384 B are used. The 5,576 B left are 2,048 B of
null guard, 296 B in the privileged window and 3,232 B in the shared window.
That is less than the "about 8 KB" estimated before the build. ITCM is a shared
resource: a co-located real-time application competes for it. If only
`queue.c` and the memops go to ITCM (all the critical-section result needs),
about 10 KB stay free. The gate in ITCM buys the decision speed-up of §3.2.

**First A2 image faulted** (`a2-timing-dist-opnsense53-fault1/`). The ITCM
region had been given only to the tasks created unprivileged. After the
measurement, the platform network task (`gateway_tcb`), which calls
`vPortSwitchToUserMode()` at runtime, took a MemManage fault: `CFSR=0x1`
(IACCVIOL) at `pc=0x20fa`, the start of `memset`. Fixed by granting the region
to both tasks that drop privilege (`gateway_platform.c`, `sys_arch.c`). The
lesson: on this port the set of unprivileged code is decided at runtime, not
only at task creation.

### 3.2 Decision cost (`a1-`/`a2-timing-dist-opnsense53`, 10 boots each)

Same method as §1, OPNsense build. Every A1 and A2 boot reproduces the oracle
equivalence (`[GATE-N32]` 20,256/20,256, 0 mismatches, 0 fail-closed). Each
A1's maxima are identical to the cycle across its 10 boots, as A0's were. A2's
vary by at most 2 cycles with interrupts masked and at most 220 cycles with them
enabled (update applied, 5,593–5,813). The cause of this small boot-to-boot
variation was not investigated.

Own cost (interrupts masked), cycles min / mean / max:

| Case | A0 | A1 | A2 |
|---|---|---|---|
| n = 1, first match | 3,287 / 3,287 / 3,293 | 3,527 / 3,548 / 3,556 | 2,405 / 2,405 / 2,414 |
| n = 1, constructed worst | 3,956 / 3,972 / 3,978 | 4,190 / 4,232 / 4,240 | 2,786 / 2,791 / 2,800 |
| n = 53, constructed worst | 170,876 / 170,891 / 170,898 | 171,110 / 171,152 / 171,159 | 104,288 / 104,293 / 104,305 |
| update applied | 4,200 / 4,200 / 4,220 | 5,375 / 5,375 / 5,441 | 4,967 / 4,967 / 4,974 |
| update rejected | 5,933 / 5,965 / 5,967 | 7,108 / 7,131 / 7,197 | 6,611 / 6,611 / 6,618 |

Maximum with interrupts enabled: n = 1 worst 7,821 / 8,054 / 3,324;
n = 53 worst 176,107 / 175,959 / 109,207; update applied 8,023 / 9,205 / 5,813.

- **A2** cuts the decision by 27–39% (n = 1 worst: 29 µs instead of 41 µs;
  n = 53: 1.09 ms instead of 1.78 ms).
- **A1 does not help the decision; it makes it 0.2–28% slower.** With caches
  off, the per-call cost still follows flash placement, and A1 moves the code.
  The word-wise memops may also cost more for the gate's small copies. These
  two effects were not separated.
- **The update gate is slower in A2 than in A0** (4,967 against 4,200 cycles).
  Its 4.2 KB validator stays in flash, behind a veneer.

### 3.3 Critical sections (attribution images `*crit-control-*`, plus the 18 no-attribution images)

Longest task-level critical section under load (valid / denied / malformed),
across 1/4/10 kHz × token bucket 0/1:

| Variant | Images | Range (cycles) | Depends on placement? |
|---|---|---|---|
| A0 | 12 | 13,100–13,695; 34,642–36,174 in the 2 images whose `memcpy` sits at 10 or 14 mod 32 | yes |
| A1 | 12 | 6,954–8,094 | yes, ±0.6k |
| A2 | 12 | 6,697–6,958 (identical per load across all 6 no-attribution images) | no |

The top caller is still `xQueueGenericSend` (now `queue.c` in ITCM for A2). A2's
section is the copy itself: about 1.5 KB at roughly 4 cycles per word from SRAM.

### 3.4 Deadlines (no-attribution images `a{0,1,2}-norank-control-*`)

Finding first. The caller attribution added to `vPortExitCritical` runs with
interrupts masked, and it inflates release latency.
- **Evidence:** idle at 10 kHz (bucket 1), A0 with attribution has 16–25 late
  releases and a maximum of 12.7k cycles (A2: 27–40, 13.4k), against 0 and 5.8k
  without (`a0-norank-control-10000-bucket1`). That matches the 2026-09-30
  images, which had no attribution (0 idle misses, maximum about 6.0–6.7k).
- **How it was found:** the release-PC diagnostic (`GATEWAY_R4_BLOCKER_PC`,
  `*-blocker-control-*`) put the late releases at the end of
  `vPortExitCritical`, in the ETH input thread's 100 ms timeout path (idle) and
  in `tcpip` (load). The late releases recur every 100 ms.

So the miss counts below come from images built with `GATEWAY_R4_CRIT_RANK=0`.
Their critical-section maxima agree with the attribution images.

Misses out of 10,000 releases per load (valid / denied / malformed; idle had 0
everywhere) count **late + lost** releases, as in the 2026-09-30 control matrix.
A lost (collapsed) release is a timer update that happened while its interrupt
was masked, so the task never saw it. The capture tool's `misses` field counts
only late ones. Lost releases come from the `[CTRL R4]` line. The table also
gives the maximum release-to-run latency in cycles:

| Rate (period) | A0 | A1 | A2 |
|---|---|---|---|
| 1 kHz (96,000) | 0, max 16,622 | 0, max 11,441 | 0, max 10,303 |
| 4 kHz (24,000) | 0, max 16,937 | 0, max 10,896 | 0, max 10,399 |
| 10 kHz (9,600), bucket 0 | 8+145 / 2+124 / 2+107, max 13,243 | 49+0 / 23+0 / 32+0, max 11,903 | 3+0 / 4+0 / 5+0, max 11,015 |
| 10 kHz (9,600), bucket 1 | 8+142 / 10+115 / 0+107, max 13,523 | 18+0 / 9+0 / 14+0, max 11,332 | 3+0 / 5+0 / 1+0, max 11,116 |

- **A0 at 10 kHz** misses 107–153. That reproduces the paper's 107–156 from the
  2026-09-30 images. Most misses are collapsed releases: the 13.6k-cycle copy is
  longer than the 9,600-cycle period, so a whole release disappears while the
  interrupt is masked.
- **A1 and A2 lose no releases**, because their copy is shorter than the
  period. What remains are late releases: the copy plus the 3–6k-cycle
  release-to-run base latency (ISR, notification, PendSV and MPU reprogramming,
  all from flash with caches off) can still exceed the period.
- **A2 misses 1–5 of 10,000 (30–100× fewer than A0); A1 misses 9–49.** Why A1
  is worse than A2 by more than its slightly longer section suggests is not
  explained; the windows hold only 21–28 requests (the 10 kHz control task
  leaves little CPU).
- **1 and 4 kHz:** no misses in any of the 18 no-attribution builds. In the 6
  A0 builds `memcpy` never landed at the slow offsets (all sections
  13.1–13.7k).
- **The slow placement misses 4 kHz deadlines when it occurs.** Evidence: the
  2026-09-30 `final-control-4000-bucket1` image (no attribution, 36.2k section)
  missed 149 under valid load. Today's two 36k builds also missed (188–261 late
  releases), but they carry the observer.
- A2 removes that placement risk.

### 3.5 Code size

`.text` + kernel + ITCM images:
- A0: 243,864 B.
- A1: +396 B (`memcpy` 250 B and `memset` 188 B replace newlib's 28 B and 16 B).
- A2: +6,372 B in total, with the 10,808 B of ITCM load images counted in
  both totals because that code moved rather than appeared. The extra is the
  memops, the veneers and section alignment.

RAM: no change outside ITCM.

### 3.6 Trade-off summary

| | A0 | A1 | A2 |
|---|---|---|---|
| Security boundary | copy through queues (strongest) | same | same. Adds one read-only/execute MPU region per unprivileged task; queue.c in ITCM stays privileged-only; ITCM is writable by privileged code (trusted, as flash-resident kernel code is not) |
| Longest copy critical section | 13.1–36.2k, placement-dependent | 7.0–8.1k, mildly placement-dependent | 6.7–7.0k, placement-independent |
| Misses at 1 / 4 kHz | 0, but 4 kHz misses in unfavourable builds | 0 | 0 |
| Misses at 10 kHz (of 10,000) | 107–153, mostly collapsed releases | 9–49, none collapsed | 1–5, none collapsed |
| Decision own cost, n = 1 worst | 3,978 | 4,240 | 2,800 |
| Cost | none | 396 B flash | 10.8 of 16 KB ITCM (5.4 KB left for other real-time code), MPU slot per unprivileged task, custom linker script |

### 3.7 Regression of A2 (isolation probes, `a2-probes/`)

Probes 1–15 (NET), 20 (GATE), 21 (APP) and 22 (AUTH) were rebuilt as A2 images
by an A2 copy of `d1_run_final_probes.py`
(`provenance/a2_run_probes.py`; it writes only into `a2-probes/`). Each probe
image differs from the A2 image only by `GATEWAY_D1_PROBE`.

- **Same outcomes as the 2026-09-30 baseline**
  (`paper-evidence-d1-2026-09-30/final-probes-summary.json`): the same fault
  class and target addresses (MemManage `CFSR=0x82` at the protected object; a
  BusFault/assert reset for 8, 14 and 15). Every probe rebooted to the
  restrictive default (operator `/api/status` → 403, self-tests 301/301 after
  reset where a reset occurred).
- Probe 14 prints `ESCAPED` here too. That is the documented baseline outcome
  (a forged slot index caught by the SHIM assertion, then a reset).
- **New probes for the ITCM boundary** (`2782477`, NET context):

| Probe | Action | Result |
|---|---|---|
| 16 | write the shared ITCM code at `0x2000` | MemManage DACCVIOL, `MMFAR=0x00002000`; reset; 403 |
| 17 | execute privileged ITCM (`queue.c` at `0x800`) | MemManage IACCVIOL at `pc=0x00000800`; reset; 403 |
| 18 | read the ITCM null guard at `0x0` | MemManage DACCVIOL, `MMFAR=0x00000000`; reset; 403 |

The A2 timing boots (§3.2) passed the 301 self-tests and the 20,256-vector
equivalence.

## 4. Verified copy routines: A1v (new baseline) and A2v (2026-10-22)

The hand-written word-at-a-time routines of §3 (A1/A2) are replaced by
Low*-verified loops: `paper-experiments/verified-memops` (`5d53ba4`, shim
`227d47c`). This gives A1v, the new baseline, and A2v, which is A1v plus ITCM.

**What is proved.** Memory safety, frame (only the destination is modified),
and functional correctness of the byte and word copy/fill loops: afterwards
the destination equals the source, or holds n copies of the value. The
`memset` word is proved to replicate the byte. Six planted bugs are each
rejected by F*.

**What is trusted.**
- **The shim** (`Gateway/Platform/gateway_memops.c`, about 30 lines):
  alignment dispatch, reinterpreting byte memory as words, and the lengths
  passed to the loops.
- **The toolchain:** F*, Z3, KaRaMeL and GCC.

**Integration** (STM32 `d712980`, `d5acc61`):
- `Gateway/Generated/Memops/Memops.{c,h}` hold the extraction, verbatim. They
  are excluded from separate compilation in `.cproject` and included by the
  shim. The shim compiles them at `-Os`, the level of all other generated code
  (`Gateway/Generated` is `-Os` in both configurations). It also disables
  loop-to-`memcpy` rewriting and strict aliasing, and declares every function
  `aligned(32)`. Every A1v and A2v build has `memcpy` at offset 0 mod 32.
- `GATEWAY_FAST_MEMOPS` now selects A1v. The hand-written A1/A2 images of §3
  remain as evidence.

**Caveat when comparing with §3.** The hand-written routines lived in
`Gateway/Platform/`, which the Debug configuration compiles at `-O0`. Most of
the gain from A1 to A1v is therefore the optimisation level, not verification.
The comparison that matters is A0 → A1v.

### 4.1 Decision cost (`a1v-timing-dist-{opnsense53,scalance32}`, `a2v-timing-dist-opnsense53`, 10 boots each)

Every case is identical to the cycle across its 10 boots in all three images.
Every boot reproduces the oracle equivalence (`[GATE-N32]`: 20,256/20,256 for
OPNsense, 17,760/17,760 for SCALANCE; 0 mismatches, 0 fail-closed). No boot
faulted.

Own cost (interrupts masked), cycles min / mean / max:

| Case | A0 OPNsense | A1v OPNsense | A1v SCALANCE | A2v OPNsense |
|---|---|---|---|---|
| n = 1, first match | 3,287 / 3,287 / 3,293 | 3,493 / 3,499 / 3,500 | 3,493 / 3,499 / 3,500 | 2,113 / 2,113 / 2,124 |
| n = 1, constructed worst | 3,956 / 3,972 / 3,978 | 4,115 / 4,146 / 4,147 | 4,115 / 4,146 / 4,147 | 2,499 / 2,499 / 2,510 |
| n = 53 (32), constructed worst | 170,876 / 170,891 / 170,898 | 168,487 / 168,500 / 168,519 | 102,106 / 102,119 / 102,138 | 103,951 / 103,951 / 103,962 |
| update applied | 4,200 / 4,200 / 4,220 | 4,564 / 4,564 / 4,573 | 4,564 / 4,564 / 4,573 | 3,965 / 3,965 / 3,970 |
| update rejected | 5,933 / 5,965 / 5,967 | 6,291 / 6,293 / 6,308 | 6,291 / 6,293 / 6,308 | 5,711 / 5,711 / 5,722 |

Maximum with interrupts enabled, n = 1 constructed worst: A1v 4,656
(OPNsense) and 7,939 (SCALANCE); A2v 6,467. n = 53: A1v 173,627; A2v 108,898.

- **A1v is build-independent for the n = 1 and update paths.** Both builds give
  identical cycle counts (4,147 and 4,573 cycles), where the A0 builds of §1
  differed by up to about 1.4k (3.3k against 4.6–4.9k medians).
- **The worst case is 43.2 µs at 96 MHz** (A0: 41.4 µs in its fast builds,
  about 15 µs more in unfavourable ones).
- **A2v** is 40% faster again: 26.1 µs at n = 1 and 1.08 ms at n = 53.

### 4.2 Critical sections and deadlines (`a{1v,2v}-norank-control-*`, no attribution)

1/4/10 kHz × token bucket 0/1 (6 builds per variant), four loads each. Misses
are late + collapsed releases, as in §3.4.

| | A0 (§3.4) | A1v | A2v |
|---|---|---|---|
| Longest copy critical section, loaded | 13.1–13.7k; 34.6–36.2k in unfavourable builds | 3,910–4,242 (valid 4,199–4,242) | 3,354 / 3,646, identical in all 6 builds |
| Misses at 1 kHz / 4 kHz | 0 / 0 (4 kHz misses in unfavourable builds) | 0 / 0 | 0 / 0 |
| Misses at 10 kHz (per load) | 107–153, mostly collapsed | 0–5, none collapsed | 0–2, none collapsed |
| Max release-to-run, loaded | 16,937 | 11,299 | 11,066 |
| Idle | 0 misses | 0 misses | 0 misses |

- **A1v's copy is 3.2× shorter than A0's typical copy and 8.6× shorter than its
  worst.** It now varies only by about 40 cycles between builds: `memcpy` and
  the loops are pinned, and only `queue.c`'s own code still moves in flash.
- **A2v** removes even that.

### 4.3 Size

- **A1v:** +376 B of flash over A0, and no ITCM.
- **A2v:** +6,356 B of flash (veneers, alignment). It uses 10,792 of 16,384 B of
  ITCM (`queue.c` 5,848; memops, gate and update-gate wrapper 4,944), leaving
  5,592 B.

### 4.4 Trade-off (replaces §3.6 for the paper)

| | A1v (baseline) | A2v |
|---|---|---|
| Boundary | copy through queues, MPU as A0 | same, plus a read-only/execute ITCM region per unprivileged task; `queue.c` privileged-only |
| Copy routines | Low*-verified loops, ~30-line trusted shim | same loops, in ITCM |
| Placement dependence | copy pinned (±40 cycles from `queue.c`); n = 1 decision identical in both builds | none observed |
| Cost | 376 B flash | 10,792 of 16,384 B ITCM (5,592 B left for co-located real-time code) |

### 4.5 Isolation probes (`a1v-probes/`, `a2v-probes/`)

Run by `provenance/v_run_probes.py`, an A1v/A2v copy of `d1_run_final_probes.py`
that writes only into its own directory.
- **A1v:** probes 1–15 and 20–22 (16–18 test ITCM and do not apply).
- **A2v:** all 21.
- **Result:** every probe has the same outcome as the A2 and 2026-09-30
  baselines: the same fault class and target address, probe 14's documented
  `ESCAPED` line, 21/22 without reset lines. Every probe reboots to the
  restrictive default (operator → 403).
- **A2v probes 16–18** fault as designed: DACCVIOL at `0x2000`, IACCVIOL at
  `pc=0x800`, DACCVIOL at `0x0`.
- **Build-guard fix:** the first A1v run stopped at probe 20, because my
  ITCM-only `#error` guard also covered probes 20–22. Fixed in `e223750`
  (preprocessor only); 20–22 were rerun. The summary was rebuilt from the
  per-probe `probe.json` files.

Functional results of the paper not rerun on A1v: the 12,527-case oracle
corpus and the 200 attack requests, measured on A0 images. A1v changes only
`memcpy`/`memset`, and every A1v boot re-checks the 301 self-tests and the
per-boot oracle vectors.

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
  read after the window closes. Updating it runs after the measured interval but
  before interrupts are re-enabled. **Correction (2026-10-22, §3.4):** that cost
  is not negligible for deadlines. It does not change the critical-section
  durations above, but the miss counts of the `*crit-control-*` images are
  inflated; deadline misses come from the `*-norank-control-*` images.
- `/dev/ttyACM1` no longer exists on this host; the tools use the stable
  `/dev/serial/by-id/...STLink_066FFF555567894967085545-if02` path, which is
  now `ttyACM2`.
