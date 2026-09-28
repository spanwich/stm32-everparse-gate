# R1 paper evidence: NUCLEO-F767ZI verified ACL gate

**Decision: no-go for the proposed complete-mediation and isolated-MCU claim.**
The paper-reference EverParse validator and F* extractor run on the board, and
the functional tests agree with the reference oracle. The target for a cheap
decision fails, the static audit cannot close 125 indirect-call sites, and the
current FreeRTOS image has no task memory isolation. These are results, not
revised pass criteria. This report supersedes the pre-R1 image results in
[`paper-evidence-2026-09-29`](../paper-evidence-2026-09-29/REPORT.md).

| Hypothesis | Verdict | Decisive result |
| --- | --- | --- |
| H1, fit/no decision heap | **Partial** | 12,890 attributed Release flash bytes for F* + Low* + EverParse + bridge; 0 gateway-task allocations in 5,276 observed decision windows. The zero-allocation run covers a separate 60 s instrumentation image, not every R1 test. |
| H2, small bounded cost/spare CPU | **Not supported** | First-rule validator median 2,191 cycles versus 214 handwritten; serializer + validator 16,979 cycles. Under valid load the gate was 5.54% of CPU and 41.7% of measured request processing, versus the expected ≪1%. No WCET analysis was done. A 1 kHz control task did meet every observed deadline. |
| H3, complete mediation | **Partial; pass criterion not met** | The linked direct-call graph has zero known network-to-effect bypasses, and the dynamic audit must match each completed effect with one acceptance. There remain 125 register-indirect call sites, including reachable formatting callbacks whose targets were not enumerated. No complete call-graph or arbitrary-write argument follows. |
| H4, integrity without seL4 | **Not supported** | Primary `configENABLE_MPU=0`; an isolated FreeRTOS MPU-port build failed at link and the current task/context design cannot assign the requested permissions. No protected MPU image or five fault-injection outcomes exist. |
| H5, board equivalence/fail-closed attacks | **Supported for tested corpus** | The unchanged paper 12,527-case corpus passed on the board; 200 labelled Ethernet attacks across ten classes had zero oracle disagreement, fail-open result or observed audit mismatch. This is testing, not proof of every possible input. |

## Exact image and comparison contract

The primary R1 image is `m0/primary-build-final/debug-policy_gate.elf` (see
`source-manifest.json`, maps and build log there). Its Debug ELF SHA-256 is
`ced6a4516cdd2369e89ea46d15bf760d0e47533e24e33f7d4816e1d99a088ef6`;
Release SHA-256 is
`65d70c75ccac2414bb9a0bbe73f184e8b52cd6ad62972627bb90c3e6f0987658`.
The build-time parent commit was
`f645b6e6a385ff401b3efc10b1a68196a6fac179`, with dirty-tree diff SHA-256
`e9db24d4674f9a83001a2cc7d3f573f282295da98c8b9359052502496a6b322a`
and source-tree SHA-256
`19cbaf28416ddc6eb26f3d575bd59b8d117f0e811553cbce8f102618cb96ec56`.
The implementation was subsequently committed as
`7000fab1440301ccb76c8c61c1ea854d1ceeb89b`; every one of the 601
compiled-source files in the build manifest still matched its hash at that
commit. The complete source-file inventory is in that manifest. Variants have distinct
ELF hashes and source manifests in their own directories. All board results
identify which image produced them. The CPU is 96 MHz, instruction/data caches
disabled; DWT measurements have interrupts enabled. Tool identities are in
[`Verification/toolchain.lock.json`](../../../Verification/toolchain.lock.json),
the manifests and build logs; ARM GCC was 13.3.1.

The linked R1 `RbacPolicy.c` and `.h` are byte-identical to the paper reference
(`6186ee3a4ad786c6ce19c29614ef359ab498b9a008f93ea1a3777fbe4706f63c`
and `026705fa22630e7022459d3548d1490fcc1bf5837a72824124e542180febd7d3`).
The `.3d` SHA-256 is
`1fc9d6d586b0465571efacd46af3785843e8d1e460f03cab07c9e27f2d096a1d`.
These match the supplied paper source, although the claimed `353666b` Git object
was unavailable locally. R1 uses method-bit subset matching and `0xDEADDEAD`
inactive path slots. Its Low* serializer was regenerated through
`Verification/tools/prove.py --extract`, with no hand edits to generated
mediation C. The paper extractor replay required the paper-side pinned F*
binary; the project's older F* could not discharge its new obligation. The
paper F* receipt is
[`reference-extractor-receipt.json`](../../../Verification/evidence/reference-extractor-receipt.json),
and the R1 replay log is [`m0/proof-replay.log`](m0/proof-replay.log).

The path ends at the first `?`; the query cannot change the resource ID.
`GET /api/status?api/policy` as operator is therefore an authorized status
read with no policy commit. `#` remains literal and unsupported spellings
reject; `..` is rejected by the imported extractor. The handwritten HTTP
adapter also validates ASCII URI bytes, HTTP version, Host and header framing
before calling that extractor, so its HTTP error status need not equal a call
to the extractor alone on malformed input. No known resource-ID difference
remains for `?`, `#`, `..` or unknown spellings in the tested corpus. Earlier
strict-query rejection and its attack expectation are historical.

## M0 and M1: build, board regression and fit

The primary image was flashed and verified on `/dev/ttyACM1` through its
ST-LINK. [`m0/board-final/uart.log`](m0/board-final/uart.log) records
301/301 startup self-tests and `[PAPER CORPUS] comparisons=12527 failures=0`.
The gateway task had 3,368/8,192 free stack bytes in the final startup capture,
diagnostics 876/2,048, minimum FreeRTOS heap free 60,672 bytes and zero UART
log drops. On that image the HTTP suite passed 34 groups including a 1,000
request soak, live policy 43/43, and dashboard 129/129. Their summaries and
serial captures are under `m0/*-final*`. Host ASan/UBSan passed 301/301 with
leak detection disabled; the lab-auth-off suite passed 219/219. The first host
sanitizer invocation died in LeakSanitizer's runtime/ptrace setup, rather than
an assertion; the failure log remains in `m0/host-final/`.

`m1/release-footprint.json` attributes input sections by linked object. The
Release image has `.text=139,956`, `.data=120`, `.bss=190,072` bytes; Debug
has `.text=200,896`, `.data=116`, `.bss=190,080`. The per-component numbers
below omit unassigned linker padding, vector boundaries and heap/stack
reservations, so they do not sum exactly to the whole image.

| Component | Flash bytes | RAM bytes |
| --- | ---: | ---: |
| EverParse validators | 8,984 | 0 |
| F* extractor and IPC | 2,190 | 0 |
| Low* serializer and wrapper | 488 | 12 |
| Trusted mediation adapter/bridge | 1,228 | 0 |
| HACL* and login | 29,611 | 116 |
| lwIP | 27,183 | 39,082 |
| FreeRTOS | 9,756 | 70,621 |
| HAL/Ethernet/PHY | 10,787 | 24,039 |
| Dashboard assets | 7,879 | 0 |
| Application handlers/core | 928 | 0 |
| Self-tests | 24,167 | 24,889 |
| Other gateway integration | 7,890 | 25,528 |
| Startup/board/C runtime | 2,314 | 806 |

The gateway-task-filtered allocation variant (`m1/variant-owner-alloc`, ELF
`68d39f565cd3cfd063b94c28b74930aa447d26240c0b3642e180693e3ec79427`)
observed 5,276 decision windows, including 5,220 valid requests, with zero
`malloc`/`pvPortMalloc` calls from the owning gateway task. The earlier global
wrapper saw 673 allocations by *other tasks* overlapping 48,902 gateway
decisions; it cannot be used as a decision-path allocation count. Static
`-fstack-usage`/post-link analysis reports a known 3,072-byte `gateway_mediate`
frame chain and no optimized extractor self-calls, but library and indirect
callees prevent a whole-chain stack bound (`m1/debug-stack.json`). The
Cedar 4.12.0 `thumbv7em-none-eabihf --no-default-features --locked --offline`
attempt is **historical, pre-R1** and copied to `m1/cedar-historical/` for a
single bundle: it failed because `memchr` requires `std`. There is no linked
Cedar footprint or evidence that it could coexist with the gateway.

## M2: DWT cost on the reference validator

The timing variant ELF is
`207b345b23da9d95ece9a6ea66b5026286b63d5ae546d6639a571542d18c8818`.
Five separately reset boots each produced 10,000 samples for every one of seven
cases and five measured stages, plus empty measurements: 1,800,000 raw samples
in [`m2/five-boots/`](m2/five-boots/). All five cycle-CSV hashes agree. No
overhead was subtracted; empty median was 72 cycles, max 531. The handwritten
gate implements the same path/method-mask/role/scope/rate predicate and agreed
with the EverParse validator in each of the seven prepared timing cases. The
separate M5 corpus checks the reference oracle on a broader set. Median
examples at 96 MHz:

| Case | Validator | Serializer + validator | Extractor | Handwritten | HTTP feed + process |
| --- | ---: | ---: | ---: | ---: | ---: |
| First-rule allow | 2,191 | 16,979 | 11,327 | 214 | 114,392 |
| Last-rule allow | 2,215 | 17,003 | 11,327 | 316 | 114,415 |
| Absent path | 2,632 | 17,420 | 3,347 | 492 | 66,037 |
| Method deny | 2,628 | 17,416 | 11,452 | 537 | 111,800 |
| Role deny | 2,627 | 17,415 | 11,334 | 547 | 76,556 |
| Scope deny | 2,650 | 17,438 | 11,327 | 569 | 111,641 |
| Rate deny | 2,337 | 17,125 | 11,264 | 113 | 111,476 |

Each case's min, median, p99, max and microseconds are in `summary.json` and
[`m2/five-boots/summary.json`](m2/five-boots/summary.json). First-rule
validator max was 2,637 cycles; 2,191 median is about 22.8 µs and 10.2 times
the handwritten median. The full serializer + validator median is about 177 µs
and 79 times the handwritten median. The spread is not explained by rule
position alone: interrupts were enabled, and the serializer contributes most
of the measured time. Measurements show repeatability, not a WCET bound.
Only the eight-slot monolithic reference validator was available; 4/16/24-slot
comparison images were not fabricated. The `request_processing` probe covers
`gateway_http_feed` and `gateway_http_process`, ending before response header
formatting/netconn queue; it is narrower than the requested receive-to-queue
interval.

## M3: real-time load

The selected control-load image is `m3/variant-highdiag-log/policy_gate.elf`
(SHA-256 `4fae52cd179e896b4ede71950639161ce873a37f1b84e3c9e4832daa38e16018`).
A priority-40 1 kHz control task used DWT timestamps; diagnostics at priority 32
captured per-task runtime counters while the gateway ran at priority 24. Each
scenario used the same 3-active/5-inactive policy
(`5f05a83b9a8877650467e42e0881235832c795bf65af8c5956da33e061e9b827`)
for approximately 600 s. Per-request UART logging stayed enabled.

| Scenario | Requests | Control samples | Misses | Maximum release-to-completion | p99 histogram bucket | Gate CPU share |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Idle | 0 | 604,020 | 0 | 239 µs | 28 µs | ~0% |
| Valid, 10 ms client cadence | 48,902 | 604,023 | 0 | 407 µs | 60 µs | 5.54% |
| Denied flood | 56,642 | 604,022 | 0 | 594 µs | 56 µs | ~0% |
| Malformed flood | 57,236 | 604,024 | 0 | 596 µs | 148 µs | ~0% |

There were zero driver status mismatches or transport errors in these selected
runs. Valid-load gateway-task share was 53.85%, TCP/IP 25.68%, Ethernet RX 7.19%,
diagnostics 8.16%, control 4.94%, idle 0.18%. The gate occupied 10.29% of
gateway-task runtime and 41.7% of measured HTTP processing; networking does
**not** dominate that measured processing interval in this configuration.
Denied and malformed requests mostly terminate before the verified access gate;
their near-zero gate share must not be interpreted as cheap verified decisions.
The jitter statistic is a bucketed p99, not an exact percentile. The control
task accumulates samples into one-second UART histograms and maximum counters;
individual jitter samples were not retained. Raw request CSVs, UART logs and
runtime counters are under `m3/*-highdiag-log-600/`.

[`m3/VARIANTS.md`](m3/VARIANTS.md) documents failures retained as evidence.
The first runtime observer scanned task stacks while scheduling was suspended
and caused 844 idle deadline misses; an observer using `vTaskGetInfo` avoided
that scan. Suppressing per-request logging reproducibly stalled connections
after 4–14 successes in separate variants, despite trying both diagnostics
priorities. The root cause and relationship to the historical one-off 600/1,000
soak timeout are unresolved. Those variants are availability failures and not
grounds to claim robust maximum throughput.

## M4: effect audit and static gap

The primary linked-image report
[`m4/entrypoints-final-primary.json`](m4/entrypoints-final-primary.json)
enumerates the vector table, registered tasks/callbacks and 125 register-indirect
call sites. Its direct-edge search found no network-input-to-protected-effect
path around `Mediation_Wrapper_run`. Two `netconn` callbacks are null for the
current listener and a custom-pbuf free callback is restricted by current
configuration; five reachable `printf` callbacks and the other 117 indirect
sites are not all target-enumerated. The review is
[`m4/INDIRECT_REVIEW.md`](m4/INDIRECT_REVIEW.md). A register-indirect call,
corrupted pointer or arbitrary task write remains a trusted path beyond the
direct graph. H3's criterion requires all indirect sites accounted for, so
**no complete static mediation result is claimed**, regardless of the dynamic
campaign outcome.

The single gateway task owns the netconn, HTTP assembly buffer, security
parameters, candidate policy and response. lwIP TCP/IP and Ethernet RX tasks
pass pbufs through the netconn boundary; the gateway copies bytes into its
owned request context and invokes the Low* wrapper synchronously. Protected
handler calls and policy commits go through the wrapper's trusted C `invoke`
bridge in the observed path. The audit bridge assigns a request ID, checks the
same request/policy/login snapshot and records acceptances and effects; it is
instrumentation in trusted C, not an independent proof of all memory effects.

The final mixed-request campaign is under
[`m4/campaign-100000-rawsocket-final-primary/`](m4/campaign-100000-rawsocket-final-primary/).
Its CSV includes expected/actual status, request ID, acceptance/effect counts,
snapshot check, policy hash and transport error for each request; `uart.log`
is the concurrent raw serial capture. Its final receipt records
**100,000/100,000 matched responses, 59,901 paired acceptances and effects,
zero unmatched effects, zero transport errors, 99 concurrent pairs and restored
RAM policy** in 1,189.4 s. These are completed response observations, not a
proof that no unobserved write occurs. The initial `http.client` attempt stalled
at request 171 and could not restore RAM policy; the board was reset. A raw
socket client that stops at the declared Content-Length completed a 2,000
request pilot and then the full campaign. The initial failure and its UART
trace are retained separately. After the full campaign, five more 1,000-request
network suites all passed 34/34 with separate serial captures under
`m4/repeated-soak-primary/`. The prior one-off 600/1,000 timeout did not
reproduce under these raw-socket runs; its precise host/lwIP cause remains
unresolved.

## M5: reference oracle and attacks

The imported paper `host_tests/test_equivalence.c` is unchanged (SHA-256
`54ce7f107186bc8be8859e8c8497697c9149ea44b88b8519907e5cb341b38377`)
and runs through a board wrapper. The final primary UART records 12,527
comparisons and zero failures. The imported corpus itself covers rate
49/50/255, role 0, path 0, each supported method bit, scope and inactive
sentinel; STM32 self-tests add integration boundary fixtures. This is an
on-device comparison with a separately implemented oracle;
the oracle and the adapter are trusted test code.

The final primary Ethernet attack run has
[`m5/attacks-200-final-primary/requests.csv`](m5/attacks-200-final-primary/requests.csv):
20 generated examples in each of ten classes (direct URL, fragmentation,
framing, identity header, method confusion, oversize, path spelling, query
smuggling, rate limit, role escalation). All 200 matched labelled status and
observed effect counters; zero fail-open results, zero audit mismatches. The
policy was read back unchanged and restored. Query suffixes have the R2
expectation of *same resource decision*; an allowed status read with a query
is not mislabeled as a bypass. The test establishes behavior for these inputs,
not all possible encoded paths or HTTP parser states.

## M6: MPU and DMA

[`m6/REGION_ANALYSIS.md`](m6/REGION_ANALYSIS.md) records the isolated
`ARM_CM7_MPU/r0p1` port attempt. Adding the FreeRTOS wrappers advanced it from
compile failure to link failure: the maintained linker script lacks privileged
flash/RAM and MPU segment symbols. No MPU image was flashed; fault injections
(policy, validator input, app input, direct handler, privilege escalation),
MPU timing overhead and MPU control-load results are **not performed**. The
port reserves regions 0–3 for fixed flash/privileged/peripheral mappings, 4
for each task stack and 5–7 for custom task regions. Its startup would overwrite
the present HAL Ethernet MPU regions 1–2. More fundamentally, the gateway task
both accepts network data and owns an 8,860-byte `GatewayContext` containing
policy, validator input and application input. The current design cannot make
the network side unprivileged while limiting gate writes by region attributes
alone. It requires separate tasks, aligned state and a bounded IPC channel.

The primary linked image puts this context at
`0x20002450`–`0x200046eb` and the control variant at
`0x20002468`–`0x20004703`, both outside reserved Ethernet DMA memory
`0x20070000`–`0x2007ffff`; configured
descriptors and payloads end at `0x2007473f`. This is disjointness for the
linked objects and configured buffers, not a proof that faulty DMA programming
or a privileged writer cannot reach gate state.

## Assurance boundary and decision

| Status | What it establishes here | What remains outside it |
| --- | --- | --- |
| Proved | Fresh Low* byte/frame/admission obligations for the R1 serializer/wrapper; the paper F* extractor obligations discharge under its pinned F* and Z3. | Correctness of the C FFI, authentication, network parsing and all effects; no formal proof of every task or callback. |
| Model-checked | The finite TLA+ mediation model and its deliberately faulty counterexamples from the earlier experiment remain relevant to the abstract lifecycle. | No refinement relation to this R1 firmware or unbounded-state theorem. |
| Tested | Reference C hashes, ARM builds, board self-tests, host sanitizers, Ethernet regressions, DWT costs, four load scenarios, effect instrumentation and attack corpus as stated above. | Untested requests, fault paths, worst-case timing and hostile memory corruption. |
| Trusted | FreeRTOS, HAL, lwIP, ARM GCC/linker, hardware, parser/auth snapshots, FFI validator bridge, leaf-effect code, oracle, test harness and exclusive buffer ownership. | MPU task protection is absent; indirect call targets and arbitrary writes are not fully constrained. |

H3 has **not passed** its static criterion, and H4 cannot be tested on a
protected image. Under §7 of `PAPER_EVIDENCE_REQUIREMENTS.md` this is a
**no-go for a paper claim of complete mediation with hardware-enforced
integrity on this board**. H1's measured fit and H5's measured functional
agreement are useful narrower results. H2's observed deadline success cannot
be turned into “small bounded cost” or spare-CPU language: the valid-load
gate share and generated-versus-handwritten ratio contradict that expectation,
and neither five repeated boots nor a maximum observed sample is a WCET proof.
Plaintext HTTP and lab credentials remain demonstration settings.
