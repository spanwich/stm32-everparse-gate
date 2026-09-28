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
