# How the long critical section was found (research notes, 2026-10-21)

A study note on the process, not just the result. The result is in `REPORT.md` §2;
this file explains how we got there, which dead ends were ruled out, and what
method transfers to other timing problems.

## 0. Starting point

- The paper reported that the 10 kHz control task misses deadlines because
  critical sections of up to 13,654 cycles exceed its 9,600-cycle period.
- It also said that "some earlier builds showed a critical section of about
  36,000 cycles", which would break the 4 kHz result, and that we had not
  located it. A CPS reviewer would ask about this first.
- What we already had: an instrumented FreeRTOS port (`Gateway/MPUPort/port.c`,
  behind `GATEWAY_R4_CONTROL`) that times every outermost critical section with
  the DWT cycle counter and keeps the **maximum**. It reports *how long*, not
  *where*.

The question splits into two:
- **Who** holds interrupts off that long?
- **Why** only in some builds?

Answer "who" first; "why" is much easier once you know what code you are
looking at.

## 1. Mine the data you already have

Before writing any code, every existing capture was searched for the
critical-section maximum:

```
grep -rIhoE "critical_max(_cycles)?[=\": ]+[0-9]+" Gateway/Validation | sort -n
# then: per image and scenario, from each */summary.json
```

The pattern that came out (from `paper-evidence-d1-2026-09-30/*control*`):

| Observation | What it suggests |
|---|---|
| ~36k appears only in some **images** (`final-control` bucket 1, `final2-control` bucket 0), at all three control rates | image-specific, not rate-specific |
| Sibling images from the same source show ~13.6k | not a source change; build or configuration |
| It appears under valid, denied and malformed load, **never when idle** (~0.9k) | the code runs when requests flow |
| Load to load, it is a constant ~+22.5k over the normal values (36.1k vs 13.6k, 34.8k vs 13.1k) | the *same* critical section, made slower by a fixed amount |

Two hypotheses followed:
1. A request-path operation runs inside a critical section.
2. Its cost depends on something the build changes, such as code or data
   placement, because the source is the same.

**Lesson:** a table of "max per image per scenario" turned an unexplained number
into a structured pattern, for free. Always look across all existing runs before
instrumenting.

## 2. Find the choke point

To attribute critical sections to code we needed one place that every critical
section passes through. In this FreeRTOS MPU port,
`configALLOW_UNPRIVILEGED_CRITICAL_SECTIONS` is 0 (`Core/Inc/FreeRTOSConfig.h`).
So only privileged code can enter a critical section, and every task-level
critical section goes through `vPortEnterCritical` / `vPortExitCritical`. That
pair is the choke point; the existing timer already sits there.

(ISR-level masking and `vTaskSuspendAll` scheduler locks are different
mechanisms. They were not the thing the existing counter measured, so they were
out of scope for reproducing *this* number.)

## 3. Instrument for "who": caller attribution

Added in `port.c` (still only in `GATEWAY_R4_CONTROL` images):
- **At outermost entry:** record `__builtin_return_address(0)`, the address in
  the function that called `vPortEnterCritical`, and `pxCurrentTCB`, the running
  task.
- **At exit:** after computing the duration, keep a **top-8 table by caller**
  (caller, task, longest duration, count), not just the global maximum.

`paper_control_r4.c` prints the table as `[CRIT]` lines after the 10,000-release
window closes. That avoids logging inside the measurement, which would add its
own critical sections.

Design points worth noticing:
- **Return address, not a stack trace.** On Cortex-M without frame pointers,
  `__builtin_return_address(1)` and deeper are unreliable. One level is enough
  here, because the caller is the kernel function that did the work.
- **Top-N by caller, not one maximum.** It shows the second- and third-longest
  sections too, which helped later: `xQueueReceive` scaled the same way as
  `xQueueGenericSend`.
- **Observer cost.** Updating the table adds a few cycles *after* the timed
  interval, before interrupts are re-enabled. That's acceptable and documented.

Problems hit, and how they were solved:
- **Build error, declaration order.** The reset function used the table before
  its type was declared. Moved the declarations up.
- **Link error.** The privileged RAM region (`RAM_PRIV`) overflowed by
  528 bytes. The table is diagnostic, written only from privileged code, so it
  moved to ordinary RAM in this labelled image. Lesson: on an MPU system, memory
  regions are tight and placement is part of the design.

## 4. Reproduce before you go back in time

The ~36k section was seen on commit `d7c753ec`. Two cheap checks came before
rebuilding old code:
- `git diff --stat d7c753ec HEAD -- port.c paper_control_r4.c` was empty, so
  the patch would apply to the old source as-is if needed.
- In the old data the long section appeared with the token bucket **off** in one
  image family. So the first try was the **current** source with the token
  bucket off.

It reproduced on the first try with the current source: valid 36,166, denied
34,876, malformed 34,703 cycles; with the bucket on, 13,695 / 13,168 / 13,139.
There was no need to rebuild old commits.

Loads came from the unchanged `Gateway/tools/r4_control_capture.py`
(idle / valid / denied / malformed, each over the 10,000-release window). The
images were staged with source and ELF hashes (`source-manifest.json`).

## 5. Turn addresses into code

```
arm-none-eabi-addr2line -f -i -p -e policy_gate.elf <address & ~1, in hex>
```

Two pitfalls hit here:
- **Thumb bit.** Return addresses on Cortex-M have bit 0 set; clear it.
- **Hex.** The shell's `$((...))` prints decimal, and addr2line silently treats
  its argument as hex. The first attempt printed `?? ??:0` for every address;
  `printf '%x'` fixed it.

Result, identical in both images:
- `0x08004923` → `xQueueGenericSend`, `queue.c:977`, the longest;
- `0x08004ce9` → `xQueueReceive`, `queue.c:1537`.

## 6. From "who" to "why"

**What the code does.** FreeRTOS copies a queue item into or out of the queue
storage with `memcpy` (`prvCopyDataToQueue` / `prvCopyDataFromQueue`) **inside**
the kernel's critical section. The gateway's compartments exchange requests
*by copy* through single-slot queues (`Gateway/Network/gateway_r4_boundary.c`):
`AppJob` 1,608 B, `AppResult` 1,544 B, the reply 1,564 B. So each request
forwards about 1.5 KB through `memcpy` with interrupts masked. That explains the
normal ~13k: it scales with message size.

**Why 2.6× slower in some builds?** Rule things out one at a time, using the
binaries themselves (`arm-none-eabi-nm`):

| Hypothesis | Check | Result |
|---|---|---|
| Queue storage misaligned (byte-wise `memcpy`) | addresses of `ingress_storage`, `app_storage`, ... in both ELFs | identical and word-aligned in both: **ruled out** |
| Different code path | caller addresses and kernel function addresses | identical: **ruled out** |
| Code placement | `nm` diff of the two ELFs | many symbols shifted; `memcpy` at offset 22 mod 32 (fast) vs 14 (slow) |

Cross-checked against the gate's own build-dependent cost (the paper's
"3.3k vs 4.6k cycles per decision" puzzle): `memset` at offset 24 mod 32 in the
slow build, 4 or 28 in the fast ones. That's the same kind of effect.

**Mechanism hypothesis.** With caches disabled, the Cortex-M7 fetches
instructions from flash through the flash interface. How a tight copy loop sits
relative to the flash fetch lines changes how many fetches each iteration costs.

**Controlled test.** Rebuild the slow image with the instruction cache on
(`GATEWAY_R4_CACHES=1`). If instruction fetch is the cause, the slowdown should
vanish. It did: 13,520 / 13,005 cycles (valid / denied).

**Confound, recorded honestly.** Enabling the cache also moved `memcpy` (to
offset 30), so placement and caching changed together. The result is
*consistent with* instruction-fetch alignment but not fully isolated. A clean
isolation would keep the code bytes fixed and change only the cache, for example
by enabling the I-cache at runtime through the debugger, or move `memcpy` alone.

## 7. What it means and what would fix it

- **Deadlines:** 13.1–13.7k cycles (about 143 µs) is above the 10 kHz period
  (9,600), which explains the 10 kHz misses. 36k is above the 4 kHz period
  (24,000), which explains the 4 kHz misses in the affected builds.
- **Fixes (not applied):**
  - enable the I-cache, or place `memcpy` in ITCM RAM: removes the placement
    sensitivity;
  - stop copying 1.5 KB inside the kernel's critical section: hand over buffer
    ownership by index through the queue. That shrinks the blocking time itself,
    which matters for the 10 kHz case.

## 8. Transferable method (checklist)

1. **Mine existing data** across all runs for the anomaly's pattern: which
   builds, loads and rates. A pattern shrinks the hypothesis space before any
   code changes.
2. **Find the choke point** every instance must pass through, and instrument
   there.
3. **Attribute first ("who"),** with cheap identifiers such as the return
   address and the task, and keep a top-N, not only the maximum.
4. **Reproduce on current code first;** check with `git diff` whether the
   instrumentation applies to the old commit before going back.
5. **Symbolise carefully** (Thumb bit, hex).
6. **Read the code you found** to understand the normal cost; that tells you
   what "slow" means.
7. **Diff the binaries** (`nm`) between the good and bad builds when the source
   is the same; rule out hypotheses one table row at a time.
8. **Make one controlled change** to test the mechanism, and write down any
   confound it introduces.
9. **State the claim at the strength the evidence supports:** "located" and
   "consistent with", not "proved".

## Reproduce

```
# build the attributed control images (flags set and restored by the script)
python3 provenance/build_timing.py crit-control-1000-bucket1 GATEWAY_PAPER_GATE_N32=0 GATEWAY_PAPER_TIMING_DIST=0 \
    GATEWAY_R4_CONTROL=1 GATEWAY_R4_CONTROL_HZ=1000 GATEWAY_R4_CONTROL_HIGH=1 GATEWAY_D1_TOKEN_BUCKET=1
#   ... bucket0 (GATEWAY_D1_TOKEN_BUCKET=0), and bucket0-icache (+ GATEWAY_R4_CACHES=1)
# run the four loads per image (first with --flash)
python3 Gateway/tools/r4_control_capture.py --elf <image>/policy_gate.elf --flash --scenario valid --d1 --output <image>/valid
# summarise with callers resolved
python3 provenance/summarize_crit.py Gateway/Validation/paper-evidence-timing-2026-10-21
```

---

# Companion note: how the decision-time distributions were measured

Short version of the choices and surprises, for study.

- **What we chose not to do:**
  - static WCET: aiT has no Cortex-M7 model, and TimeWeaver needs an ETM trace
    probe;
  - MBPTA: extreme-value fits need random timing variation, and with caches off
    the gate is near-deterministic; its variability comes from inputs, which MBPTA
    doesn't handle.
  - We report observed best, mean and worst instead, which is also how the
    Cortex-M7 literature (CAWET, ECRTS 2023) defines its ground truth: the maximum
    of many runs.
- **Worst-case input by construction:** read the generated validator
  (`Partition8.c`: path, method, role, scope, short-circuited) and build an input
  where every slot fails on the *last* check. That is the structurally longest
  path, instead of hoping a benchmark input finds it.
- **Two conditions:** interrupts masked around each sample (the gate's own cost)
  and enabled (the deployed experience). The difference is preemption, not gate
  work.
- **Engineering surprises:**
  - **RAM overflow:** 10,000 × 32-bit samples overflowed the RAM below a fixed
    MPU-aligned section. Fixed with 16-bit samples where values are below 65,536,
    in one shared 20 KB buffer.
  - **Watchdog:** long measurements could starve the 1 s watchdog task (8 s
    timeout). Fixed by yielding one tick every 256 samples, outside the timed
    region.
- **Unexpected finding:** results were **identical to the cycle across 10
  hardware resets**. We verified that the resets were real: different
  timestamps, different log lengths, programmer reports a hardware reset. The
  system is deterministic, because caches are off, nothing external happens
  during the window, and the periodic yield re-aligns each batch to the 1 ms tick.
  Consequence: report the boots as reproducibility, not as independent samples.
- **Build dependence:** the same gate code costs about 3.3k or about 4.6k cycles
  per call depending on the build, following where `memset` lands in flash with
  caches off. That's the same family of effect as the critical section in §6.

---

# Addendum (2026-10-22): testing the remedies, and three mistakes the data caught

Results are in `REPORT.md` §3. This note records how the A1/A2 experiment ran
and what went wrong along the way, because each mistake teaches a check worth
reusing.

## 1. Design: keep the strongest baseline, add alternatives

Copy semantics through queues (no shared buffer) stays the baseline. The
alternatives change only speed and placement sensitivity:
- **A1:** word-at-a-time `memcpy`/`memset`.
- **A2:** A1 plus the hot code in ITCM RAM.

Each is a build flag that defaults to 0. A rebuilt A0 image had the *same
loadable bytes* as the old one (`objcopy -O binary` + SHA-256). That check is
what lets new A1/A2 runs be compared with old A0 runs.

## 2. Mistake 1: the MPU region list was decided at task creation; privilege is decided at runtime

The first A2 image took a MemManage fault after the measurement:
`CFSR=0x1` (IACCVIOL) at `pc=0x20fa`, `memset` in ITCM.
- I had given the ITCM region to every task *created* unprivileged.
- Two tasks are created privileged and call `vPortSwitchToUserMode()` later:
  the platform network task and lwIP's `tcpip` thread.

How it was diagnosed: read the `[RESET]` record (CFSR bit, faulting PC, TCB
address), map the TCB address to a symbol with `nm` (`gateway_tcb`), then grep
for privilege drops.

**Check to reuse:** list unprivileged code by grepping for both
`xTaskCreateRestricted*` and privilege drops (`vPortSwitchToUserMode`,
`__set_CONTROL`).

## 3. Mistake 2: the observer changed what it observed

The caller attribution added on 2026-10-21 updates a table *after* the timed
interval but *before* interrupts are re-enabled. I had judged that "a few
cycles". The deadline data said otherwise:
- **Symptom:** idle misses at 10 kHz, which the older images never had.
- **Tool:** a second diagnostic (`GATEWAY_R4_BLOCKER_PC`). The release ISR saves
  the interrupted PC from its exception frame; late releases are ranked by PC.
- **Result:** almost all late releases resumed at the end of
  `vPortExitCritical`, at the exact moment interrupts were re-enabled. They
  recurred every 100 ms (the ETH input thread's semaphore timeout).
- **Controlled test:** the same image with attribution compiled out
  (`GATEWAY_R4_CRIT_RANK=0`) had 0 idle misses, as the 2026-09-30 images did.

Consequence: the critical-section *durations* are still valid, because they are
measured before the table update. Deadline misses come only from images without
the observer. The 2026-10-21 report note was corrected.

**Lesson:** any instrumentation that runs with interrupts masked is part of the
critical section for deadline purposes, even when it sits outside the timed
interval. Compare against an uninstrumented build before believing a deadline
number.

## 4. Mistake 3: comparing two different "miss" metrics

At first, A0 seemed to miss far fewer 10 kHz deadlines (0–10) than the paper
reported (107–156). The 2026-09-30 matrix counts **late + collapsed** releases;
the capture tool's `misses` field counts only late ones. Collapsed (lost)
releases are timer updates that happen while the interrupt is masked, so the
task never sees them. They appear in the firmware's `[CTRL R4]` line as
`lost_releases`.

With the same metric, A0 reproduces the paper (107–153). The mechanism also
becomes clear: A0's 13.6k-cycle copy is longer than the 9,600-cycle period, so
releases are swallowed whole. A1 and A2 never swallow one.

**Lesson:** before comparing to an earlier number, find the script that
produced it and confirm the definition, not just the field name.

## 5. What the data says, briefly

- **A2:** the copy is bounded at 6.7–7.0k cycles in every build
  (placement-independent); 10 kHz misses 1–5; the gate is 27–39% faster.
- **A1:** shortens the copy but does not stabilise the gate.
- **Cost of A2:** 10.6 of 16 KB ITCM. ITCM is shared with any co-located
  real-time code, and 5.4 KB is left. Keeping the gate in flash would leave
  about 10 KB, at the cost of the gate speed-up.
- **Still open:** why A2's maxima vary slightly between boots when A0's and
  A1's do not; why A1 misses more than A2 at 10 kHz; whole-request timing.
