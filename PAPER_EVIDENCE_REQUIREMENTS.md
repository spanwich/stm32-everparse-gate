> **Scope: STM32F767 (NUCLEO-F767ZI, FreeRTOS) worker session only.** The seL4
> gateway has its own, separate spec in
> `/home/iamfo470/phd/papers/experiments/http-acl-x86/source/SEL4_EVIDENCE_REQUIREMENTS.md`;
> do not implement anything from it here. Mentions of seL4 below are reference
> material only. Current work: §12 (Redesign D1) as amended by §13.

# Evidence requirements: verified ACL gate on a resource-constrained MCU

Requested by the paper side (IEEE S&P 2027 resubmission, "Access Control as
Verified Parse Constraints"), 2026-09-29. This file states **what must be
shown and what result is expected**. How to implement it is up to the session
working in this repository. Report results honestly: a failed hypothesis is a
research result and must be recorded as one, not tuned away.

## 1. Why this stage comes first

The paper's thesis is that authorization for embedded management interfaces can
be *verified by construction within the budgets of resource-constrained
devices*: the policy is runtime data, and the enforcement mechanism (generated
EverParse validator + F* extractor) is verified once for every policy. The seL4
gateway shows this with kernel-enforced isolation. This board has **no seL4**.
The hypothesis to test here is that a carefully constructed FreeRTOS system still
gives a **deterministic information flow in which every request that can cause a
protected effect passes the verified gate**, and that the gate costs little
enough to leave the MCU free for its real work.

This is a go/no-go stage. If the hypotheses in §3 fail, the research design
changes (see §7). Do not weaken a criterion to make it pass; report it.

## 2. Ground rules

- Board: NUCLEO-F767ZI on **`/dev/ttyACM1`**. `/dev/ttyACM0` is an STM32MP255
  board used by other work — do not open, flash or reset it.
- Do not modify generated algorithms (EverParse, F*/Low*, HACL*). Regenerate only
  through the existing proof/extraction tools, and record receipts.
- Keep the current platform configuration (96 MHz, caches disabled) as the
  **primary** configuration. Any other configuration (caches on, different clock,
  MPU port) is a separately labelled variant with its own evidence.
- Every result must identify the exact firmware: git commit, dirty-tree diff hash,
  ELF SHA-256, build configuration, and toolchain versions.
- Distinguish, as the existing reports do, what is **proved**, **model-checked**,
  **tested**, and **trusted**. Timing observations are not WCET bounds unless a
  WCET method is actually applied.
- The verified-mediation work on `research/verified-mediation` is the starting
  point. Its report lists as a *trusted* integration assumption: "no unmodeled
  task, DMA writer, memory corruption, indirect handler reference or direct
  client entry point bypasses the intended C call graph". §3 H3 and H4 exist to
  turn that assumption into evidence, or to show where it cannot be.

## 3. Hypotheses

| ID | Hypothesis | Failure means |
|---|---|---|
| H1 | The gate fits the MCU: the full verified gate path (F* extraction, verified serializer, EverParse validator) runs on the NUCLEO-F767ZI with a small, fixed footprint and **no heap use on the decision path**. | The approach does not fit constrained devices as claimed. |
| H2 | A decision costs a small, **bounded** number of cycles, leaving most CPU time to application tasks, and a time-critical task keeps its deadlines under request load, including attack floods. | The "spare MCU time for real tasks" claim fails. |
| H3 | **Complete mediation by construction:** every path from network input to any protected effect (handler, policy commit, state change) passes the verified gate for the same request, with no bypass path in the control flow. | The core security claim fails on this platform. |
| H4 | **Memory integrity without seL4:** with the FreeRTOS MPU port and correct task/region design, no code outside the gate (lwIP, drivers, other tasks) can write the gate's policy store, its validator input, or the protected application's input except through the gate's output. DMA cannot reach them. | A simple RTOS cannot replace kernel isolation for this gate; requires redesign. |
| H5 | **Security holds on the device:** the deployed gate makes exactly the decisions of the reference oracle, and CVE-pattern attacks fail closed. | Implementation diverges from the verified decision function. |

## 4. Required experiments

Each experiment lists: objective, what to measure, the expected result, and the
pass criterion. Use a fixed default policy of **8 rule slots (3 active, 5
inactive)**, matching the seL4 comparison, unless stated otherwise.

### M0 — Establish the verified-mediation build on the board

- **Objective:** the firmware under test is the verified-mediation build (Low*
  `Mediation.Format` serializer proved byte-for-byte equal to its specification,
  plus `Mediation.Wrapper`), not the older `main` image.
- **Measure:** fresh proof replay results; build hashes; flash; startup self-tests,
  live-policy, dashboard and HTTP regression suites on the board.
- **Expected:** all existing suites pass on the new image as they did on
  `1069e4b` (287/287 self-tests, 43/43 live policy, 129/129 dashboard, 34/34 HTTP
  groups).
- **Pass:** all pass, with no regression in stack margins or heap.

### M1 — Footprint (H1)

- **Objective:** show exactly what the verified gate costs in flash and RAM, and
  that a general engine does not fit.
- **Measure:**
  - Per-component flash (text+rodata) and RAM (data+bss), from the linker map:
    EverParse validators, F* extractor, Mediation serializer/wrapper, HACL* and
    login, lwIP, FreeRTOS, HAL/drivers, dashboard assets, application handlers.
  - Stack high-water mark of the gateway task over the full test campaign; the
    static stack use of the decision path (compiler stack usage reports).
  - Heap: confirm with instrumentation (e.g. wrapped `pvPortMalloc`/`malloc`
    counters) that **zero allocations occur on the decision path** over all tests.
  - Cedar fit attempt: try to build `cedar-policy` 4.12.0 for
    `thumbv7em-none-eabihf` (no_std). Record the exact outcome: build error and
    cause (e.g. `std` dependency), or, if it builds, flash/RAM size and whether it
    fits alongside the gateway in 2 MB flash / 448 KB general SRAM. Do not spend
    more than a bounded effort; a documented failure with its cause is a result.
- **Expected:** the gate path is on the order of tens of KB of flash and a few KB
  of RAM with no heap; the whole firmware fits with margin (Release was ~128 KB
  text, ~175 KB bss). Cedar does not build as no_std or does not fit (for
  reference, on seL4 Microkit it needed ~6 MB of reserved memory and ≥720 KB heap).
- **Pass:** zero decision-path allocations; per-component table complete; Cedar
  outcome documented.

### M2 — Decision cost and boundedness (H2)

- **Objective:** cycles per decision on the MCU, and evidence that they are
  bounded.
- **Measure** with the DWT cycle counter (`DWT->CYCCNT`), interrupts handled as
  documented (report whether measured with interrupts masked or not):
  1. validator only (`AccessRequest` check on a prepared buffer);
  2. serializer + validator (prepared metadata → decision);
  3. F* extraction of a prepared HTTP request;
  4. full request processing inside the gateway task (from receiving the request
     bytes to queuing the response), excluding network transmission.
  Cases: first-rule allow, last-rule allow, absent path, method deny, role deny,
  scope deny, rate deny. At least 10,000 samples per case; also rule counts 4, 8,
  16 and 24 if monolithic validators for them are available.
  Report min, median, p99, max cycles and µs at 96 MHz; subtract nothing but
  report the empty-measurement overhead separately.
- **Baseline:** a straightforward handwritten C gate implementing the same
  predicate (path equality, method mask subset, role ≥ minimum, scope subset,
  count < limit, deny by default) over the same rule table, measured identically.
  It must agree with the oracle (M5) before timing.
- **Expected:** validator decisions on the order of 10²–10³ cycles
  (microseconds or less); max close to median (bounded: no data-dependent loops
  beyond the fixed rule count, no allocation); generated gate within a small
  factor of the handwritten baseline.
- **Pass:** every case measured; max/min spread explained by the rule position
  (short-circuit) only; repeatable across ≥5 fresh boots.
- **Optional (label separately):** caches enabled; static WCET estimate of the
  validator path (e.g. by bounding the generated control flow), if feasible.

### M3 — CPU share and a time-critical task (H2)

- **Objective:** show that enforcing policy leaves the MCU free for its real job.
- **Measure:**
  - Add a periodic high-priority "control" task (e.g. 1 kHz) that records its
    release-to-completion jitter and any deadline miss (DWT timestamps; optionally
    toggle a GPIO for an oscilloscope/logic analyser).
  - Load scenarios: idle; sustained valid requests at the highest stable rate;
    a flood of denied requests (unauthenticated, wrong role, unknown paths);
    malformed requests. Run each for a fixed duration (e.g. 10 minutes).
  - FreeRTOS run-time statistics per task (enable `configGENERATE_RUN_TIME_STATS`
    with the DWT or a timer), and the fraction of gateway-task time spent in the
    gate decision versus networking/HTTP.
- **Expected:** gate decision time is a very small share (≪1%) of CPU time even
  under flood; the control task has zero deadline misses and bounded jitter in
  every scenario; networking/lwIP, not the gate, dominates request cost.
- **Pass:** zero control-task misses under all loads, with per-task CPU shares
  reported.

### M4 — Complete mediation (H3)

- **Objective:** show there is no path to a protected effect that avoids the gate.
- **Measure:**
  - **Static:** enumerate *all* entry points in the image: tasks, ISRs, lwIP
    callbacks, timers, and any function pointers or indirect calls. Extend the
    existing post-link call-graph check so that every path from network input to
    any protected handler or policy commit passes `Mediation_Wrapper_run` and the
    EverParse validator, and so that indirect calls are either resolved or
    reported. List every indirect-call site and how it was resolved.
  - **Dynamic:** instrument a per-request identifier. For every protected-handler
    invocation and policy commit, record the matching gate acceptance for the
    same request identifier and snapshot. Run ≥100,000 mixed requests (valid,
    denied, malformed, concurrent connections, reconnects, policy updates).
  - **Structural:** show which task owns request buffers, how data moves between
    tasks (queues, notifications, shared memory), and that the protected
    application receives input only from the gate's output.
- **Expected:** static check finds no bypass path; every effect has exactly one
  preceding matching acceptance; zero violations.
- **Pass:** zero bypass paths and zero unmatched effects; every indirect call
  accounted for.

### M5 — Functional equivalence and CVE-pattern attacks (H5)

- **Objective:** the board makes the same decisions as the reference oracle, and
  the attack classes that motivate the paper fail closed.
- **Measure:**
  - **Differential:** run a decision corpus on the device and compare with an
    independent host oracle of the decision function. Reuse the 12,527-case
    corpus of the seL4 HTTP gateway (`experiments/http-acl-x86` or
    `http-acl-microkit` host differential tests in the papers repository) where
    applicable, plus boundary cases for every field (count 49/50/255, each method
    bit, role 0/1/2, scope bits, inactive sentinel, path 0).
  - **Adversarial HTTP corpus** sent over Ethernet, each request labelled with its
    expected outcome, covering at least:
    - role escalation: operator or limited user issuing write/admin operations
      (pattern of CVE-2024-41797, CVE-2015-6464);
    - direct URL access to protected resources without or with wrong credentials
      (CVE-2016-8346, CVE-2016-9362);
    - query-string smuggling, e.g. `/demo?api/status` or `?api/core/menu`
      (CVE-2019-11816);
    - path spelling variants: `%2e`, `%2f`, `//`, `/./`, `..`, `..;/`, trailing
      slash, case changes, encoded `?`, overlong UTF-8 (CVE-2025-0108,
      CVE-2025-20362);
    - identity smuggled in headers (e.g. `X-Role`, `X-Forwarded-User`, duplicate
      `Authorization`) (CVE-2024-0012);
    - method confusion (lowercase, `HEAD`, unknown methods), oversized and
      fragmented requests, and rate-limit exhaustion.
- **Expected:** 100% agreement with the oracle; every request that the policy
  does not explicitly permit is denied (403/401/404/429) **with no handler
  effect**; permitted requests succeed. Zero fail-open cases.
- **Pass:** zero disagreements and zero fail-open results; every request's
  expected/actual outcome and effect counter recorded.

### M6 — Memory integrity without seL4 (H4)

- **Objective:** test whether FreeRTOS with the Cortex-M7 MPU can stand in for
  kernel isolation for this gate. This is the central hypothesis of this stage.
- **Measure:**
  - Document the current state first: with `configENABLE_MPU 0`, every task can
    write every RAM address, so integrity rests on all firmware (the weaker claim).
  - Build a variant using the FreeRTOS MPU port (`ARM_CM7_MPU`, `configENABLE_MPU
    1`): network, lwIP, diagnostics and application tasks unprivileged; the gate
    task alone has write access to the policy store, validator buffers and the
    gate→application channel; the application reads only its input region.
    Document the region map and the MPU region budget used.
  - **DMA:** the Ethernet DMA is not governed by the MPU. Show from the linker
    map and DMA descriptor configuration that DMA targets only the reserved
    Ethernet region, and that gate/application memory lies outside it.
  - **Fault injection** (each run separately, in a test build): an unprivileged
    task or lwIP hook tries to (a) write the policy store, (b) write the validator
    input buffer between serialization and validation, (c) write the application
    input, (d) call a protected handler directly, (e) raise its own privilege.
    Record the fault (MemManage/HardFault/SVC rejection), and show the system
    fails closed: no protected effect happens, and the system stops or resets
    rather than granting access.
  - Re-run M2 and M3 on the MPU variant and report the overhead.
- **Expected:** every injected write or call faults before any protected effect;
  DMA ranges are disjoint from gate state; MPU overhead is small; the region
  budget suffices.
- **Pass:** all five injections fail closed with zero protected effects, and the
  DMA disjointness argument is complete.
- **If it fails:** record which step fails and why (region budget, lwIP needing
  privileged access, shared buffers that cannot be separated, performance). This
  is the redesign trigger in §7.

## 5. Deliverables

Put everything under a new dated directory, e.g.
`Gateway/Validation/paper-evidence-2026-MM-DD/`:

- `REPORT.md`: per hypothesis, the verdict (supported / not supported / partial),
  the evidence, and the proved/model-checked/tested/trusted table updated for this
  firmware.
- `summary.json`: all headline numbers in machine-readable form (keys listed in
  §6).
- Raw data: per-sample cycle CSVs, per-request attack and differential CSVs,
  control-task jitter logs, run-time statistics, UART logs.
- Build provenance: ELF and map files (or hashes), build configuration, toolchain
  lock, proof receipts, the static call-graph and entry-point report, and the MPU
  region map.
- A `SHA256SUMS` over the evidence directory.

## 6. Numbers the paper needs (summary.json keys)

| Key | Source | Fills in paper |
|---|---|---|
| `validator_cycles` {case: min/median/p99/max} | M2 | STM32 decision cost |
| `gate_path_cycles` (serializer + validator), `extract_cycles`, `request_cycles` | M2 | decision vs request cost |
| `handwritten_cycles` {case: …} | M2 | cost of verification vs handwritten C |
| `cpu_share_gate` per load scenario; `control_task_misses`, `control_task_jitter_us` | M3 | "spare MCU time" claim |
| `flash_bytes`, `ram_bytes` per component; `decision_path_allocations` | M1 | footprint; no heap |
| `cedar_no_std_outcome` (error or size) | M1 | "general engines do not fit" |
| `bypass_paths`, `unmatched_effects`, `requests_tested` | M4 | complete mediation |
| `oracle_disagreements`, `fail_open`, `attack_requests` per class | M5 | security holds |
| `mpu_injections` {case: fault, effect}, `dma_disjoint`, `mpu_overhead_cycles` | M6 | isolation without seL4 |
| firmware commit, ELF SHA-256, clock, cache state | all | provenance |

## 7. Decision gate

- **Go:** H1, H2, H3 and H5 supported, and H4 supported with the MPU variant.
  The paper can claim the gate is deployable on an MCU with complete mediation
  and hardware-enforced integrity under stated FreeRTOS/MPU assumptions.
- **Partial:** H1–H3 and H5 supported, H4 not. The paper may claim control-flow
  mediation and cost, but must state that memory integrity on the MCU rests on
  all firmware being correct; the research design needs a stronger isolation
  mechanism for MCUs (e.g. TrustZone-M on a newer part, or a verified RTOS).
- **No-go:** H3 or H5 fails. The core claim does not hold on this platform; stop
  and report before further paper work.

## 8. What not to claim from this stage

- Timing observations are not WCET unless a WCET analysis is performed.
- The MPU variant does not make FreeRTOS verified; FreeRTOS, HAL, lwIP and the
  MPU configuration remain trusted.
- Passing tests do not prove absence of bypass; the static entry-point/call-graph
  analysis and the MPU fault evidence carry that argument, within their stated
  limits (no protection against a malicious privileged task or hardware faults).
- Lab credentials and plaintext HTTP remain demonstration settings, not
  production authentication.

---

## 9. Revision after first results (2026-09-29, paper side)

Reviewed `Gateway/Validation/paper-evidence-2026-09-29/`. The results so far
are good and kept as they are: gate path ≈12.4 KB of flash; Cedar 4.12.0 fails to
build no_std; 100,000 requests with every effect matched to one acceptance;
12,527/12,527 agreement with the oracle; 0 fail-open among 31 attacks. Decisions
and changes follow. They override §4 where they differ.

### R1 — Run the same validator as the seL4 gateway (new, required before M2/M5 re-runs)

The firmware runs the legacy CAmkES-era specification
(`Gateway/Provenance/specifications/RbacPolicy.3d`: method IDs compared by
equality, inactive slots marked by method 0; `RbacPolicy.c` SHA-256
`b1b91cea…`). The paper's policy language, and the seL4 gateway it measures,
use method **bit masks with subset matching** (request method ∈ {1,2,4,8,16,32};
a rule mask may combine them) and the inactive-slot path sentinel
`0xDEADDEAD`. The paper claims that one verified mechanism runs on both
platforms, so the MCU must run the same one.

- Reference, papers repository
  `experiments/http-acl-x86/source` @ `353666b`:
  - `vendor/everparse/RbacPolicy.3d` — SHA-256 `1fc9d6d5…096a1d`
  - `engines/everparse/generated/RbacPolicy.c` — SHA-256 `6186ee3a…06f63c`
  - `engines/everparse/generated/RbacPolicy.h` — SHA-256 `026705fa…a1d7d3`
  - F* extractor sources in `verified/HTTP.Extract.*.fst`
- **Required:** the MCU build links the reference `RbacPolicy.c`/`.h`
  **byte-identically** (verify by hash), or regenerates them from the reference
  `.3d` with a recorded, hash-identical result. Do not edit generated code.
- Adapt the handwritten integration (method encoding, rule-slot encoding,
  inactive-slot sentinel, policy-update wire format, dashboard encoding) to the
  new layout. Update the Low* `Mediation.Format` specification to the new 75-byte
  AccessRequest layout, and re-prove it: the serializer must still be proved
  byte-for-byte equal to its specification, now matching the reference `.3d`.
- Record the old image's results as a labelled historical baseline; do not mix
  them with results from the new image.
- **Expected:** all existing suites pass on the new image. M5's differential then
  **replays the seL4 12,527-case corpus unchanged** (its generator/oracle is the
  `make differential-test` target, `host_tests/test_equivalence.c`, in the
  reference tree), with 0 disagreements, plus boundary fixtures for rate 49/50/255,
  role 0, path 0 and inactive slots.

### R2 — Query semantics: the query is ignored, as on seL4

Decision: both gateways use the seL4 extractor's semantics. The path ends at the
first space, `?` or CR; the query never creates a separate resource identifier
and never changes which rule applies.

- Revert the "query-target fix" (rejecting `?`/`#` with 400) in
  `Gateway/Core/gateway_http.c`. Keep its evidence as a labelled historical image.
- Match the reference extractor's behaviour exactly for `?`, `#`, `..` and
  unknown spellings; list any remaining difference explicitly.
- **Change the attack expectation.** The property is: for every role, path and
  query suffix, the decision on `path?query` equals the decision on `path`, and a
  query can never turn a denied request into an allowed one. `GET
  /api/status?api/policy` as operator is therefore *expected* to return 200 with
  no policy effect — not a fail-open. The baseline result for request 14 is a
  test-expectation mismatch, not a bypass; re-label it that way.

### R3 — Remaining work, in priority order

1. **R1** (validator parity), then **R2**.
2. **M2/M3 (H2)** on the R1 image — the evidence the paper most needs: DWT cycles
   for the seven cases over five fresh boots, the handwritten C baseline, the
   empty-measurement overhead, then the 1 kHz control task under idle, valid load,
   denied flood and malformed flood.
3. **Decision-path allocation counters (H1).**
4. **Indirect calls (H3):** resolve all 125 register-indirect sites, starting
   with the 8 reachable from `serve` before `Mediation_Wrapper_run`, or remove
   them from the architecture.
5. **Soak timeout:** find the cause of the first 1,000-request soak stopping at
   600 (it passed on repeat). An unexplained stall matters for the availability
   and control-task claims; reproduce and explain it, or show it came from the
   host/network side.
6. **Larger attack corpus:** at least 20 generated variants per class (currently
   1–10), keeping the per-request CSV format.
7. **M6 (H4):** split the global context shared by self-tests and network
   operation, reconcile FreeRTOS MPU regions with the Ethernet regions, then the
   MPU variant and the five fault injections.

---

## 10. Round R4 — isolation boundary, cost floor and real-time fit (2026-09-29, paper side)

Reviewed `paper-evidence-r1-2026-09-29`. Kept as established: reference validator
byte-identical on the board; 12,527/12,527 reference cases; 200 attacks with
0 fail-open; 100,000-request effect audit; 12.9 KB verified gate; zero decision
allocations; Cedar does not build for the target; 1 kHz control task with 0
misses under all loads. The paper will describe the MCU honestly as a
correctness-and-fit deployment whose integrity currently rests on all firmware.

Two corrections to the earlier requirements:

- The "≪1% CPU" expectation in M3 had no principled basis; CPU share scales with
  request rate. Replace it with per-decision cycles, the maximum sustainable
  request rate, and interference on real-time tasks (R4.3).
- H4 is not refuted, only untested: the current firmware puts network input and
  gate state in one task and one context. R4.1 tests the hypothesis properly.

### R4.1 — Enable the MPU and find the isolation boundary (first priority)

Goal: not all-or-nothing isolation, but an honest **boundary**: which assets the
MPU protects from which writers, and which remain trusted.

1. Make the FreeRTOS MPU port (`ARM_CM7_MPU`, `configENABLE_MPU 1`) link and boot:
   add the privileged flash/RAM and MPU section symbols to the linker script, and
   reconcile the port's fixed regions with the Ethernet MPU regions (ETH
   descriptors/payload must stay non-cacheable/shareable as now).
2. Restructure so that isolation is possible: split the gateway into at least a
   network-facing task (lwIP netconn, HTTP assembly), a gate task (policy store,
   validator input, serializer, EverParse call), and a protected-application task,
   connected by bounded queues that copy bytes. Keep the verified extractor,
   serializer and validator unchanged.
3. Make as much as possible unprivileged, starting with the network-facing and
   application tasks. Record every component that must stay privileged, and why
   (e.g. HAL/ETH driver, lwIP core if it cannot be confined).
4. Produce an **isolation boundary table**: rows = assets (policy store, validator
   input, gate→app channel, application input, credentials/keys, MPU
   configuration); columns = writers (network task, lwIP/TCP-IP task, ETH driver
   and DMA, app task, diagnostics, ISRs). Each cell: *MPU-enforced*, *trusted*
   (with reason), or *not applicable*.
5. Run the five fault injections from M6 on the MPU image for every cell marked
   MPU-enforced. Expected: fault before any protected effect, and the system
   fails closed.
6. Re-run M2/M3 and the M5 attacks on the MPU image; report the overhead.

Decision: supported for the cells that are MPU-enforced and pass injection; the
rest of the table is the accepted trust boundary that the paper will state.
If the boundary cannot protect at least the policy store and validator input
from the network-facing code, report that as the failure point.

### R4.2 — Cost floor and cost attribution

Measure each stage (validator; serializer; serializer + validator; extractor;
handwritten baseline; full request processing) in labelled variants, M2 method
(DWT, ≥5 boots, 10,000 samples per case):

| Variant | Clock | Caches | Optimisation |
|---|---|---|---|
| V0 primary (as R1) | 96 MHz | off | -Os |
| V1 | 216 MHz | I-cache + D-cache on (ETH region non-cacheable) | -Os |
| V2 | 216 MHz | on | -O2 |

Attribute the cost, so the paper can explain it:

- **EverParse 64-bit positions.** The generated validator uses `uint64_t`
  positions and results (231 uses in `RbacPolicy.c`); this is fixed in EverParse's
  LowParse (`pos_t = U64.t`, error codes in the upper 32 bits) and is **not** a 3D
  option. Do not modify EverParse. Quantify its share (e.g. instruction counts of
  64-bit operations in the disassembly of the validator path).
- **Serializer design.** `Mediation_Format` uses no 64-bit types; its cost comes
  from per-byte interpretation (a `select` decision tree per output byte). As a
  labelled variant, implement a field-level Low* serializer that is still proved
  byte-for-byte equal to the same specification, and report before/after cycles.
- Report instruction counts or cycles for the validator path with interrupts
  masked, to separate execution cost from interrupt noise.

### R4.3 — Determinism and real-time interference

The claim to test: the gate's execution is bounded and does not obstruct
higher-priority real-time work.

- Per stage, report min/max over all boots with interrupts masked; the max/min
  ratio; and the number of distinct execution paths exercised (the validator has
  at most 8 rule checks). If feasible, a static bound for the validator path from
  its control flow (no loops beyond the fixed rule count, no recursion, no
  allocation); label it as a static estimate unless a WCET tool is used.
- Show the gate path contains **no interrupt masking and no critical sections**
  (or report their longest duration).
- Control tasks at 1 kHz, 4 kHz and 10 kHz, at priorities above and below the
  gate task, under idle, valid load, denied flood and malformed flood: deadline
  misses and exact jitter percentiles (retain samples, not only histograms).
- Maximum sustainable request rate for valid requests without control-task
  misses, per variant.

### R4.4 — Which applications fit (honest mapping)

From R4.2/R4.3, produce a table of application classes with their timing budget,
the measured worst per-decision cost and interference, and a verdict
(*supported with margin*, *supported*, *not supported*). Include at least:
HTTP management plane; MODBUS/TCP request authorization; IEC 61850 GOOSE
messages if the gate were placed in-line per message; IEC 61850 Sampled Values;
a 1–10 kHz control loop sharing the MCU. Take the timing budgets from primary
sources (e.g. IEC 61850-5 transfer-time classes) and cite them; do not guess. A
"not supported" row is an acceptable and useful result.

### R4.5 — Availability defect

Find the root cause of the stalls when per-request UART logging is disabled
(connections stop after 4–14 successes) and of the earlier 600/1,000 soak stall.
A timing-dependent stall undermines the determinism claim, so fix it or explain
it before R4.3 is reported as final.

### Priority

R4.1 → R4.5 → R4.2 → R4.3 → R4.4. Keep every variant's ELF hash, source
manifest and evidence separate, as in R1.

---

## 11. Round R5 — push the isolation boundary, fix the priority configuration (2026-09-29, paper side)

Reviewed `paper-evidence-r4-2026-09-29` (commit `863bd60`). Accepted: the MPU
image with unprivileged network-facing and application tasks, six injections
faulting, masked determinism (validator 2,274–2,276 cycles), the proved field
serializer (16.6× faster), the linger fix and the 5,000-request soak.

### Finding from the configuration: the deadline misses are a priority artefact

In the R4 control matrix, "above gate" is `osPriorityHigh`, which is **equal**
to `TCPIP_THREAD_PRIO` (`osPriorityHigh`). With preemption, time slicing and a
1 kHz tick, a control task released while the TCP/IP thread runs waits for
that thread to block or for the next tick. That wait is up to ~1 ms, which
matches the ~950 µs worst cases at V0. Malformed floods, which bypass the
verified gate, miss as often as valid floods. So the verified gate is not the
cause. R4's statement that the 4/10 kHz loops are "not supported" describes this
priority configuration, not the platform's limit.

### R5.1 — Priority and scheduling (first)

- Document the complete priority map: every task (with FreeRTOS priority and
  privilege), every ISR (NVIC priority), `configMAX_SYSCALL_INTERRUPT_PRIORITY`,
  `configUSE_PREEMPTION`, `configUSE_TIME_SLICING`, tick rate.
- Re-run the control matrix (V0 primary and V2; 1/4/10 kHz; four load classes)
  with the control task **strictly above** every network task (e.g.
  `osPriorityRealtime`, above TCP/IP and ETH input), and keep the existing
  "equal to TCP/IP" and "below gate" rows as labelled comparisons.
- Measure what remains: ISR latency and the longest critical sections
  (FreeRTOS queues, lwIP `SYS_ARCH_PROTECT`), attributed to their callers.
- Add ingress rate limiting / budgeting for network processing (e.g. bounded
  packets per tick, ETH interrupt moderation, or a budgeted network task) as a
  labelled variant, and report whether it removes floods' effect on the control
  task. This is also a denial-of-service defence.
- Expected: with the control task above the network stack, 1 kHz and 4 kHz meet
  every deadline in the primary image; 10 kHz is limited only by the longest
  critical section/ISR, which must be reported.

### R5.2 — Deploy the proved field serializer

Replace the original serializer in the running gateway with the proved
`Mediation.Field` serializer (no hand edits to generated C). Re-run the 12,527
reference corpus, the 200 attacks, the HTTP suite and soak, and the DWT stages
(V0, V2). Expected: serializer+validator falls from ~17,000 to ~3,200 cycles at V0.

### R5.3 — Shrink what can write gate memory

Report the current answer to "what can write the policy store and validator
input", then reduce it, in this order:

1. **Keep only verified code in the gate task.** Move handwritten HTTP framing,
   authentication and response formatting out of the privileged gate task into
   the unprivileged network-facing task. The gate task should run only the
   verified extractor, serializer and validator plus a minimal audited adapter.
2. **Make the gate task unprivileged too**, with its private RW region, if the
   port allows; otherwise state why.
3. **Minimise privileged code**: list every privileged task and ISR, and try to
   make the lwIP TCP/IP thread unprivileged with access only to pbuf pools and
   the Ethernet payload region. If that is not possible, record the reason.
4. **DMA**: Ethernet DMA is not governed by the MPU. Show that descriptors are
   placed in the reserved region and that the driver validates every buffer
   address it programs against that region; add a check if missing, and a fault
   injection with a descriptor pointing into gate memory (expected: rejected by
   the driver check).
5. Update `R4_BOUNDARY.md` after each step and re-run the injections.

Note (for the report, not an implementation task): ARMv7-M MPU permissions
cannot deny privileged code while allowing unprivileged access, so on this
part anything privileged can reach gate memory. Hardware that can push further
is TrustZone-M (Cortex-M33, e.g. STM32U5/H5 with GTZC blocking non-secure
masters, including DMA, from secure SRAM). Mention it as the next-step
platform; do not port.

### R5.4 — Per-task access to kernel objects

The project uses the CubeIDE FreeRTOS **V10.2.0**, whose MPU port does not
control which task may use which queue. FreeRTOS **V10.6+** "MPU wrappers v2"
adds opaque kernel-object handles and per-task access control lists
(`configENABLE_ACCESS_CONTROL_LIST`, `vGrantAccessToQueue`, and
`configENFORCE_SYSTEM_CALLS_FROM_KERNEL_ONLY`). Check whether a release with
this feature supports the `ARM_CM7_MPU` port; if it does, upgrade, grant each
task only its own queues, and add an injection where the network task uses the
app queue handle (expected: rejected). If not supported for CM7, document it.

### R5.5 — Close R4's open items

- Root-cause the intermittent V1 cached bus fault (`CFSR=0x8200`,
  `BFAR=0x7e792384`), e.g. cache maintenance around DMA buffers or MPU/cache
  ordering; until then cached results stay research-only.
- Redo the post-link entry-point and indirect-call audit on the split-task image,
  including queue-handle reachability.

### Priority

R5.1 → R5.2 → R5.3 → R5.4 → R5.5. Same evidence conventions as R1/R4.

### R5.0 — Threat model change and a kernel privilege-escalation hole (do first)

**Threat model (from the paper side):** treat lwIP (TCP/IP thread, HTTP
assembly) and the Ethernet driver as **untrusted and possibly compromised**.
The gate's security must hold even if an attacker runs arbitrary code inside
them. Trusted: FreeRTOS kernel, a minimal privileged Ethernet/DMA shim and its
ISR, the gate's verified code, hardware.

**Hole found in the R4 image.** The project runs FreeRTOS **V10.2.0**, and
`Gateway/MPUPort/port.c` raises privilege for *any* caller of
`svc portSVC_RAISE_PRIVILEGE` (the `case portSVC_RAISE_PRIVILEGE` handler has
no caller check). This is **CVE-2021-43997** (V10.2.0–10.4.5: non-kernel code
can call `xPortRaisePrivilege`); **CVE-2024-28115** (through V10.6.1:
escalation by jumping into MPU wrappers / ROP) also applies. R4's injection 5
only tried writing `CONTROL` directly, which the hardware ignores, so it did
not test this path.

1. **Demonstrate the hole on the current R4 image:** from the unprivileged
   network-facing task, (a) `svc` with `portSVC_RAISE_PRIVILEGE`, then write the
   policy store; (b) call `xPortRaisePrivilege` directly; (c) branch into an MPU
   wrapper after its privilege raise. Expected: the writes **succeed**. Record
   this as the R4 boundary's failure, not a pass.
2. **Upgrade the kernel** to FreeRTOS ≥ V10.6.2 (prefer the current V11.x) with
   MPU wrappers v2 for the `ARM_CM7_MPU` port, `configUSE_MPU_WRAPPERS_V1 0`,
   `configENFORCE_SYSTEM_CALLS_FROM_KERNEL_ONLY 1`, and
   `configENABLE_ACCESS_CONTROL_LIST 1` (this also delivers R5.4). If the CM7
   MPU port does not support v2 in any release, report that and stop R5.0 at
   step 1.
3. Re-run (a)–(c) and the six R4 injections on the upgraded image. Expected:
   all rejected before any protected effect.

**Untrusted lwIP/driver injections (after R5.3 step 3):** with the TCP/IP
thread and Ethernet driver logic unprivileged:

- compromised TCP/IP thread writes the policy store / validator input;
- compromised driver writes Ethernet MAC/DMA registers directly (expected:
  MPU fault; only the trusted shim maps them);
- compromised driver asks the shim for a DMA descriptor pointing into gate
  memory (expected: rejected by the shim's address check).

The trusted shim (descriptor programming, address check, ISR) should be as
small as possible and is a candidate for a later Low* proof; list its size.

**Report honestly** which of these the F767 can enforce. The ARMv7-M MPU cannot
restrict privileged code or the Ethernet DMA master; the residual trusted base
is the kernel, the shim and its ISR. That is the expected, stated limit of
this platform class.

---

## 12. Redesign D1 — compartmentalised gateway (2026-09-29, paper side; supersedes §11 R5)

R5 (§11, including R5.0) is folded into this redesign. Do not continue R5 as a
patch series on the R4 image; build D1 as described here. Keep R1/R4 evidence
as labelled history.

### D1.1 Objective and security property

> Note (2026-09-30): the SHIM, as the only code that programs the Ethernet DMA,
> is trusted — consistent with seL4's proof assumption that DMA-capable
> devices and their drivers are trusted, which the seL4 realisation now adopts
> too (no IOMMU). NET (lwIP, driver logic without DMA control, HTTP framing)
> remains untrusted.

Show that the paper's verified gate can be deployed on a conventional MPU-only
MCU such that the following **integrity** properties hold **even if every piece
of code in the NET compartment is compromised** (attacker runs arbitrary code in
lwIP, the Ethernet driver logic or the HTTP framing):

- **P1 Complete mediation:** every protected effect (application handler,
  policy commit) is caused only by a request the verified gate accepted, using
  exactly the bytes it validated.
- **P2 Gate integrity:** only GATE, the kernel and the SHIM can write the policy
  store and the gate's input/output buffers.
- **P3 Identity integrity:** role and scope come only from AUTH; only AUTH (and
  privileged code) can read the keys.
- **P4 Policy updates** happen only through the gate's admin-only PolicyBlob
  validator.
- **P5 No starvation:** attacker-driven work cannot make a higher-priority
  real-time task miss its deadline.

Confidentiality is **not** claimed (plaintext HTTP; TLS deferred).

### D1.2 Topology

```
 ETH DMA ─► [SHIM + ETH ISR]   trusted, privileged, minimal
               │ frame copies
            [NET]   untrusted, unprivileged: lwIP, driver logic, HTTP framing
               │ raw request bytes (bounded copy)
            [GATE]  trusted, unprivileged, exclusive region:
             │      F* extractor (on the raw bytes), rate counter,
             │      Low* field serializer, EverParse validator, policy store
             │ ── extracted token ──► [AUTH]  unprivileged: keys + HACL*
             │ ◄── role, scope ───────┘       (never sees the rest of the request)
               │ accepted request (bounded copy)
            [APP]   unprivileged: protected handlers ──► response ──► NET
```

- NET only finds request boundaries. GATE re-extracts every field with the
  verified extractor, so a lying NET can cause only denials.
- AUTH is an **identity oracle**: GATE sends the token it extracted from this
  request; AUTH returns role and scope. No other compartment can use the
  GATE↔AUTH queues.
- No channel from APP back into GATE. APP acts only on jobs GATE accepted.
- Responses go APP/GATE → NET → client (not mediated; no integrity claim on
  responses).

### D1.3 Kernel and privilege

- Upgrade to FreeRTOS **≥ V10.6.2 (prefer V11.x)** with **MPU wrappers v2**:
  `configUSE_MPU_WRAPPERS_V1 0`, `configENFORCE_SYSTEM_CALLS_FROM_KERNEL_ONLY 1`,
  `configENABLE_ACCESS_CONTROL_LIST 1`; grant each task only its own queues.
  This closes CVE-2021-43997 and CVE-2024-28115 present in V10.2.0. First
  confirm the Cortex-M7 (r0p1) MPU port supports wrappers v2 in that release;
  if not, stop and report.
- Privileged: kernel, SHIM (descriptor programming, frame copy, ETH ISR), a
  privileged initialiser, a small privileged logger. Everything else is
  unprivileged, including GATE.
- The ETH ISR only acknowledges and notifies the SHIM.

### D1.4 Memory and MPU regions (paper-side check; confirm on the real port)

With 8 MPU regions and the V10.2 layout (regions 0–3 static, 4 stack, 5–7 per
task), each compartment needs 1–2 of its 3 configurable regions:

| Compartment | Privilege | Configurable regions |
|---|---|---|
| SHIM, logger, initialiser | privileged | 0 |
| NET | unprivileged | 1: own contiguous RAM (lwIP heap, pbuf pools, globals) |
| GATE | unprivileged | 1: policy store, validator buffers, extractor scratch |
| AUTH | unprivileged | 1: HACL* state, RAM copy of keys |
| APP | unprivileged | 1: `.gateway_app` |

Proposed placement: DTCM `0x20000000` (128 KB): kernel/privileged RAM, GATE
(16 KB), AUTH (8 KB); SRAM1: NET (128 KB), APP (16 KB), stacks; `0x20070000`
(64 KB): ETH descriptors and DMA buffers, privileged only.

Conditions (verify each):

1. **Keys** live inside the privileged flash region (region 1); the privileged
   initialiser copies them into AUTH's RAM at boot. No other unprivileged task
   can read them.
2. **No libc state** in unprivileged compartments (newlib `_impure_ptr`,
   `printf`); otherwise a shared writable region is needed. If unavoidable, it
   must contain nothing security-relevant; document it.
3. **Diagnostics** from unprivileged tasks go through a queue to the privileged
   logger.
4. **Caches off** in the primary configuration. A caches-on variant needs a
   non-cacheable ETH region in every task (still within budget; report it).
5. Compartment RAM sizes are powers of two, aligned to their size (use
   subregion disables to trim).
6. Queues are created with MPU wrappers v2 so their storage is kernel-owned;
   compartments share no writable memory.

**DMA:** the F767 Ethernet DMA is an AHB bus-matrix master and can reach all
SRAM including DTCM ("accessible by all AHB masters", RM0410); there is no
hardware DMA barrier. The SHIM must be the only code that writes ETH MAC/DMA
registers and descriptors, and must check every buffer address against the
reserved DMA region. Keep the SHIM minimal and report its size (a later Low*
proof target).

### D1.5 Scheduling (standard FreeRTOS)

Preemptive priorities with time slicing **on** (FreeRTOS default), no custom
scheduler. Distinct priorities, highest first:

`control/RT > SHIM task > AUTH > GATE > APP > NET`

- AUTH must be **at or above** GATE (the oracle call would otherwise suffer
  priority inversion through APP).
- The control task is **strictly above** every network task (the R4 misses
  came from sharing `TCPIP_THREAD_PRIO`).
- NVIC: control timer IRQ above the ETH IRQ.
- The SHIM rate-limits frames/interrupts with a token bucket (flood defence).
- P5 argument: real-time tasks can be delayed only by ISRs and kernel critical
  sections; measure both.

### D1.6 Policy default and faults

- Policy is RAM-only. The firmware default policy is the **most restrictive**:
  deny everything except the admin endpoints needed to re-apply policy, so a
  reset can never grant access (prevents rollback-by-crash).
- **Any compartment fault → full system reset** (MemManage/HardFault handler
  and an independent watchdog). Record the fault first (CFSR, MMFAR, task).
  Accepted limitation: repeated crashes deny service, never grant access.

### D1.7 Build-up order (each step leaves a working, tested image)

1. Port to FreeRTOS V11 MPU wrappers v2 with the current R4 task split; re-run
   the six R4 injections **plus** privilege raising via `svc
   portSVC_RAISE_PRIVILEGE`, direct `xPortRaisePrivilege`, and a jump into an MPU
   wrapper. Expected: all rejected. (Also run the same three on the R4 image
   first and record that they succeed.)
2. Split AUTH out as the identity oracle; move keys to privileged flash + AUTH
   RAM; GATE runs only verified code plus a minimal adapter.
3. Make GATE unprivileged with its exclusive region.
4. Introduce the SHIM; make lwIP and driver logic unprivileged in NET.
5. Apply the priority map, time slicing, token bucket and restrictive default.
6. Deploy the proved `Mediation.Field` serializer.

### D1.8 Evidence required (on the final D1 image unless stated)

| ID | Evidence | Expected |
|---|---|---|
| E-P2a | Injections from NET code (running as NET): write policy store, validator input, AUTH keys, APP input; call GATE/AUTH/SHIM functions; use GATE/APP queue handles | MPU/kernel fault or ACL rejection before any effect; system resets |
| E-P2b | Privilege escalation from NET: `svc` raise, `xPortRaisePrivilege`, wrapper jump, write `CONTROL` | rejected |
| E-P2c | NET writes ETH MAC/DMA registers directly; NET asks SHIM for a descriptor into GATE/AUTH memory | MPU fault; SHIM rejects |
| E-P3 | NET and APP read AUTH keys; NET forges role/scope in the request bytes | fault; GATE uses AUTH's answer only |
| E-P1 | 100,000 mixed requests with the effect audit (every effect paired with one acceptance of the same request) | 0 unmatched |
| E-P4 | Policy update as operator, as forged admin, and malformed PolicyBlob | rejected; policy unchanged |
| E-P5 | Control task at 1/4/10 kHz strictly above network; idle, valid, denied, malformed floods; with and without token bucket; longest ISR and critical section attributed | 0 misses at 1 and 4 kHz; 10 kHz limited only by reported ISR/critical-section maxima |
| E-func | 12,527 reference corpus, 200 attacks, HTTP suite, 5,000-request soak | 0 disagreements, 0 fail-open |
| E-cost | DWT stages (V0; V2 as labelled variant) incl. field serializer, extra copies and the oracle round trip | report; no pass threshold |
| E-fault | For each compartment, an induced fault → reset → restrictive default policy | no access granted after reset |
| E-map | Final region map, linker map, privileged-code inventory with sizes, entry points and indirect calls | complete inventory; every indirect call resolved or listed |

### D1.9 Deliverables

Evidence under `Gateway/Validation/paper-evidence-d1-<date>/` with the same
conventions as R1/R4 (per-image ELF hash, source manifest, raw logs, SHA256SUMS,
`summary.json`, `REPORT.md` with verdicts per P1–P5 and the proved /
model-checked / tested / trusted table). Also update the boundary document to
the D1 compartment × asset table.

### D1.10 What not to claim

The FreeRTOS kernel, SHIM, ISRs, initialiser, logger and hardware remain
trusted; the MPU cannot restrict privileged code or the Ethernet DMA; no
confidentiality; DWT maxima are not WCET.

---

## 13. D1 alignment with the paper story and the seL4 realisation (2026-09-30, paper side)

These amend §12 (Redesign D1). Where they differ, §13 wins.

### 13.1 Role of this experiment in the paper

The paper argues: (1) a decision verified once for every policy, cheap enough
for MCUs; (2) an enforcement architecture that keeps that guarantee when the
network stack is compromised (P1–P5). The seL4 realisation supplies P1–P4 and
deployment cost under strong isolation; **this MCU realisation supplies P1–P4
on a conventional Cortex-M7, P5 (no starvation of real-time work), fit and
determinism, and cost against handwritten C.** All real-time claims in the
paper come from this board.

### 13.2 Login and identity (same design as seL4)

- The private GATE↔AUTH channel carries two message types:
  `IDENTIFY(token)` → role, scope (or invalid), and `LOGIN(credential bytes)` →
  token (or bad credentials). For `/api/login`, GATE extracts the body with the
  verified extractor, forwards it as `LOGIN`, and returns AUTH's answer; login
  is a public route needing no role.
- AUTH alone holds the credential table and the token-signing key (HMAC); GATE
  carrying the issued bearer token is acceptable (tokens cross untrusted NET in
  plaintext anyway; the paper claims identity integrity, not token secrecy).

### 13.3 Restrictive boot policy and the functional suites

- Default policy at boot and after any reset: only `login`, `logout` and the
  admin endpoints to read and re-apply policy.
- The functional/regression harness logs in as admin and installs the previous
  demo policy before the existing suites, which then run unchanged.
- Separate checks: after a fresh boot an operator protected request is denied
  and admin can apply a policy; after an induced fault and reset the restrictive
  default is back.

### 13.4 Injection criteria (corrected, same as seL4)

- **Memory accesses** by NET/APP/AUTH/GATE outside their regions (writes,
  reads, execution) must raise a MemManage/HardFault before any protected
  effect, followed by the reset policy.
- **Kernel-object misuse** (a task using a queue or task handle it was not
  granted by the access-control list) must have **no effect at the target**:
  nothing delivered, target counters unchanged. An error return or a fault are
  both acceptable. Record which outcome occurred.
- **Privilege escalation** attempts must not yield privilege (fault or error).

### 13.5 P5 method

- Report the **idle baseline** of the control task at each rate on the exact
  image, then the misses under valid, denied and malformed floods;
  interference = loaded minus idle. Expected on this hardware (DWT, hardware
  timer): idle baseline ≈ 0 and **0 misses at 1 and 4 kHz** under all loads
  with the control task strictly above the network tasks; report 10 kHz with the
  attributed ISR/critical-section maxima.
- Keep a timing variant for the control-task matrix separate from the image
  used for the P1–P4 and functional evidence only if they must differ; if they
  differ, state exactly how.

### 13.6 Attack corpus labelled by CVE class

The paper will classify published management-interface CVEs into A
(authorization enforcement — prevented), B (web-stack/parser compromise before
authorization — contained), and C–E (authentication, post-authorization handler
bugs, client-side — not addressed). Label every request in the 200-case attack
corpus with its class (A or B), and add B-class tests: malformed, oversized and
fragmented HTTP aimed at NET, plus the NET-compromise injections of §12 D1.8,
showing the gate and protected functions stay intact (availability loss
allowed).

### 13.7 Optional, after the switch role-model study is ready

The paper side is extracting documented role/endpoint models of managed
switches (Moxa, SCALANCE, Hirschmann) into policies in
`/home/iamfo470/phd/papers/drafts/access-control-as-constraints-s-and-p/studies/switch-role-models/policies/`.
When available, load one such policy on the board (as runtime data, no
re-verification) and run a small functional check that its role rules are
enforced. This demonstrates "policy as data" with a realistic device model.

## 14. Link the verified composed gate (2026-09-30, paper side; amends §12–§13)

The paper's decision theorem is now the **composed gate**, machine-checked in
F*/Low* against EverParse's own specification (no admits):
`/home/iamfo470/phd/papers/experiments/verified-combiner/` (README: integration
contract). Its serializer and combiner are proved, so the handwritten encoding
glue and the 75-byte monolithic buffer are no longer part of the decision.
**Do not re-implement or edit the gate; link the extracted C as the GATE's
decision entry point and write platform glue only.**

- **Files (copy verbatim, record sha256 in the report):**
  `extracted/Gate.c`, `extracted/Gate.h`, `extracted/internal/Gate.h`,
  `extracted/Partition8.{c,h}`, `extracted/UniversalRate.{c,h}`,
  `extracted/internal/EverParse.h`, `generated/EverParse.h`,
  `generated/EverParseEndianness.h`. Record the papers-repo commit you copied.
- **Call:** `uint8_t GateLowGateDecide(n, rules, q, s, ctxt)`; policy is an array
  of `8n` `GATE_SPEC_RULE` (unused slots: path `0xDEADDEAD`); `q` comes from the
  verified extractor, `s` from AUTH and the counter; `ctxt` is any private byte.
  Accept only on result `1` (0 = deny, 2 = fail-closed deny).
- **Glue allowed:** receiving `q`/`s` in the GATE task, holding the policy array
  in GATE-private memory, the mailbox/ACL plumbing, acting on the answer. The
  policy-update path keeps its own validator; it must write `GATE_SPEC_RULE`
  entries (not bytes) into the GATE's array.
- **Stack:** the gate uses two stack buffers (75 B) and `GateLowScan` is a tail
  call; build with `-O2` and **report the GATE stack high-water mark** at n = 1
  and n = 32, and confirm (disassembly) that the recursion is a loop.

Evidence (report failures as results):

1. **Equivalence at n = 1:** the existing on-board self-tests, live-policy,
   dashboard and HTTP regression groups pass with the new gate; decisions are
   identical to the previous gate on the whole corpus.
2. **Switch-model policy as data:** load
   `drafts/access-control-as-constraints-s-and-p/studies/switch-role-models/policies/siemens-scalance-xb200.json`
   (254 rules, n = 32) as runtime data, no rebuild; run the paper-side oracle
   vectors for that policy (subset from `verified-combiner/test/gen_vectors.py`,
   ≥ 5,000 decisions): 0 mismatches.
3. **Cost (DWT cycles at the same clock as §13):** gate decision first match,
   last match and absent path at n = 1 and n = 32; flash and RAM of the gate
   objects vs the previous gate; per-request CPU share at the §13 request rates.
4. P1–P4 and P5 results of §12–§13 are re-run on the image with the new gate
   (same image for functional, timing and isolation evidence), or the report
   states precisely which image each result used.
