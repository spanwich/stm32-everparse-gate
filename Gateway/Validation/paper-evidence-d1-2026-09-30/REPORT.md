# D1 evidence — stages 1–7 and ongoing final tests, 2026-09-30

**Verdict (updated after D1.8, see "D1.8 final evidence"): P1-P4 tested on the
final verified-gate image with the scoped exceptions listed there (probes 14,
15 and 22 inconclusive; latent long critical section); P5 holds for the
primary configuration at 1 and 4 kHz.** Original stage-1-7 verdict:
**D1 was not yet established.** Steps 1–7 now have working board images:
FreeRTOS V11.3.1 MPU wrappers v2, a private AUTH oracle and unprivileged GATE,
a bounded SHIM/NET handoff, restrictive reset policy, proved field serializer,
and a chunked NET→GATE queue. The full P5 timing matrix is complete. The final
NET-compromise injection matrix, 100,000-request effect audit, labelled A/B
corpus, cost image and privileged-code inventory remain open. P1–P4 are not yet
established; P5 has the measured boundary below.

## Restrictive policy, serializer and bounded queue

The live GATE starts with only login, logout and admin policy read/re-apply
available. `v11-field-stage6/board/uart.log` records 301/301 board checks;
`v11-field-stage6/network-suite` and its simultaneous UART trace record fresh
operator denial, admin policy installation, all 34 existing network checks and
200 mixed requests, followed by restoration of the restrictive policy. The
separate `v11-fault-reset-once2/board/uart-raw.log` contains a NET policy-write
MemManage fault, IWDG reset and second successful boot. Its
`post-reset-policy-uart/uart.log` and check record operator denial after reset
and admin re-application. The first one-shot fault image repeatedly faulted
inside its handler; its raw logs are retained, and the corrected handler reads
the current TCB directly in privileged handler mode.

The pinned `Verification/tools/prove.py --extract` replay passed and generated
the active `Mediation.Field.build_access` call for access kind 2. Other kinds
still use `Mediation.Format.build`. The proof covers byte equality to the
reviewed scratch mapping and frame/bounds properties; it does not prove the
kernel, queue integration, HTTP semantics or execution time.

Sustained loaded timing exposed a watchdog design error: the low-priority
diagnostics feeder was starved and the board reset. A separate privileged
watchdog task above NET priority now feeds the IWDG. It also exposed the large
4,100-byte NET→GATE queue item: at 4 kHz valid load, a 33,625-cycle FreeRTOS
critical section caused 19 late delivered releases and 84 collapsed TIM7
updates. This failing image and all superseded timing logs are retained in
`development-timing-invalid.tar.zst` (SHA-256
`7c76a657293304da783139b0a2d81795ee932b45f0edead78e2aad3b95f7a96b`).
The replacement queues at most 256 bytes per item and reassembles the exact
request in GATE-private memory. `v11-chunk-ingress-stage7` passed 301/301 on
the board, the 34-check HTTP suite, 200 mixed requests and the 4,096-byte
request case. Both configurations built with zero warnings.

## P5 timing matrix

`control-matrix.csv` and `control-matrix.json` link all 24 final captures to
their image hashes, raw `uart.bin`, and 10,000 exact per-release samples. For
each rate and bucket setting, idle and valid/denied/malformed loads used the
same ELF. The collector requires HTTP READY before timer START, completed
requests inside every loaded window, exactly one boot, and no parser or
critical-counter anomalies at 1/4 kHz. TIM7 CNT and DWT reconstruct the latest
hardware update; gaps count releases lost when its single update flag coalesces.

| Rate | Bucket | Idle misses | Loaded total misses (valid / denied / malformed) | Loaded completed requests |
|---|---|---:|---|---|
| 1 kHz | on | 0 | 0 / 0 / 0 | 531 / 623 / 673 |
| 1 kHz | off | 0 | 0 / 0 / 0 | 714 / 624 / 674 |
| 4 kHz | on | 0 | 0 / 0 / 0 | 107 / 124 / 134 |
| 4 kHz | off | 0 | 0 / 0 / 0 | 107 / 125 / 134 |
| 10 kHz | on | 0 | 162 / 134 / 116 | 23 / 27 / 28 |
| 10 kHz | off | 0 | 160 / 132 / 113 | 23 / 27 / 29 |

At 10 kHz the loaded critical-section maxima are 13,122–13,642 cycles,
exceeding the 9,600-cycle period. Timer ISR maxima are approximately 1,400
cycles and Ethernet ISR maxima approximately 3,000 cycles. Most 10 kHz misses
are collapsed releases (113–159 per run); three or six delivered releases
were also late in some runs. Each denied 10 kHz run has one reconstructed-gap
anomaly, so its exact total has an uncertainty of one release. These DWT
maxima are observed values, not WCET bounds. The control task runs strictly
above SHIM, AUTH, GATE, APP and NET; TIM7 IRQ priority 5 is above ETH priority
7. The 1/4 kHz zero-miss result applies to the measured sequential HTTP loads,
whose achieved rates and transport errors are in the CSV, not to unmeasured
line-rate saturation.

The final stage-one Debug ELF is `v11-stage1-final/policy_gate.elf`, SHA-256
`9b8635dc33e961902cf18b66e4e1af10d5e12833123904e592538b9d23fddf37`.
Its `board/uart.log` records 301/301 startup checks, HTTP READY, link UP and
heartbeats without UART drops. `http-probe/command.log` records an unauthenticated
`GET /api/status` response of 401; `http-probe/uart.log` is the simultaneous
serial trace. The earlier live-request fault and its diagnosis are retained in
`v11-tcpiptrace`: the exception frame pointed to `vPortEnterCritical`, called
from `rx_free` in the unprivileged network task. The final image uses atomic
byte state transitions in that callback.

## Port and hardware findings

- The official FreeRTOS Kernel V11.3.1 `GCC/ARM_CM4_MPU` port was used. This
  ARMv7-M MPU port also builds and runs on this Cortex-M7. Wrappers v2, syscall
  origin checks, kernel-object ACLs and FPU support are enabled. The one local
  change in `mpu_wrappers_v2.c` places the initialized syscall-dispatch table
  in `privileged_data_init`; the old NOLOAD placement zeroed it at startup.
- The measured CPUID was `0x411fc270`, Cortex-M7 r1p0. The §12 assumption of
  r0p1 was wrong for this board. The r0p0/r0p1-only erratum workaround caused
  an assertion in `port.c:840`; it was disabled for the observed revision.
- The privileged SRAM reservation grew to 128 KiB to hold the 64 KiB kernel
  heap and stage-one gate state. APP has a separate 16 KiB region. In stage
  one the GATE task was still privileged; stage three moves it to its own
  region. NET still sees broad nonprivileged RAM, so D1 isolation is open.
- CMSIS mutex handles now encode the V11 opaque handle separately from the
  recursive flag. The old adapter interpreted the first valid handle `1` as
  null, dropping all post-boot logs. The final image has zero log drops.
- V11's MPU wrapper configuration does not retain the old software stack hook
  in the linked image; MPU stack protection applies to unprivileged tasks.
  A whole-call-chain stack bound has not been proved.

## AUTH and GATE build-up

The current working stage-three Debug ELF is
`v11-gate-stage3b/policy_gate.elf`, SHA-256
`4a868ea4a2415503602301a12450db5c584d4a93c696ee454bee3ef98d3b66e6`.
Its `board/uart.log` records 301/301 startup checks and sustained heartbeats.
`http-smoke` and `http-repeat-200` record successful LOGIN and IDENTIFY
round trips, issued-token and fixture-token access, forged-token rejection,
bad-credential rejection, and 200 sequential authenticated requests. The
network suite passed every check, including bytewise fragmentation, 4096-byte
input, policy update/rollback, trickle timeout, connection recovery, and 200
mixed requests; see `network-suite/results.json`, `network-suite/summary.json`,
and simultaneous `network-suite-uart/uart.log`.

AUTH alone holds the credential table, fixture-token table and HMAC key in
`.gateway_auth` at `0x20060000–0x20063fff`. The privileged initializer copies
precomputed credential hashes and the key from the privileged flash bank.
No plaintext demo passwords are linked into the board image. GATE sends
`IDENTIFY(token)` and `LOGIN(credential bytes)` over kernel-owned queues;
only GATE and AUTH receive ACL grants for those queues. The raw credential
body reaches AUTH after the verified login envelope check. The GATE policy,
buffers, audit state and stack occupy `.gateway_gate` at
`0x20050000–0x2005ffff`; generated mediation/extractor mutable globals are
placed there by the linker without editing generated C. GATE and AUTH both
run unprivileged. NET and APP have their GATE/AUTH SRAM subregions disabled.

On-board read probes `v11-auth-net-read-key` and `v11-auth-app-read-key`
produced MemManage data faults with `MMFAR=0x20061000` (key address), before
any key byte was observed. Separate `v11-gate-net-write` and
`v11-gate-app-write` probes produced MemManage data faults at the policy
byte `0x20054250`. The marked probes and raw UART/SWD logs are retained in
their directories. The board was restored to the working stage-three image.

The stage-three host ASan/UBSan binary passed 301/301 linked vectors and the
12,527-case paper reference corpus. LeakSanitizer was disabled for this host
run because it fails under the environment's ptrace supervision; its first
failure is retained in `stage3-host/tests.log`, and the successful run in
`stage3-host/tests-asan-ubsan.log`. The on-board image is the primary evidence
for task isolation; host tests establish only pure-code behavior.

The first stage-three live-request variant faulted on generated mutable
`Mediation_Format_zero` at `0x200261e8`. The linker fix placed it at
`0x2005a014`; the working image then passed the live suites. The first AUTH
variant exposed a DMA-backed pbuf read at `0x20071668` when NET's Ethernet
bank was prematurely disabled. Until D1.7 step 4 copies frames through SHIM,
NET retains temporary read access to that bank. Another AUTH variant exposed
V11's privileged-only `vQueueDelete` during netconn cleanup. A bounded
privileged cleanup worker now reclaims registered lwIP objects; its broad
registration must be narrowed to exact ownership in step 4.

## SHIM/NET step-four checkpoint

The working `v11-tcpip-broker-stage4j/policy_gate.elf` (SHA-256
`680e23a04e184976e24007176f310516011f0dbf1e4a361f201255f4ed193f8a`)
was flashed and tested on the board. Its `board/uart.log` records 301/301 startup checks, sustained
heartbeats, and no stack-margin or UART-drop failure. `http-smoke/uart.log`
records the concurrent LOGIN/IDENTIFY run with 20 authenticated requests.
`network-suite/results.json` and `network-suite-uart/uart.log` record all 34
existing network checks passing, including 200 mixed requests. This is an
intermediate image, not the final D1 security or P5 evidence image.

The privileged Ethernet SHIM now owns the HAL handle, PHY state, DMA buffers,
descriptor rings, task stacks and kernel queue storage. It validates and copies
received frames into bounded NET SRAM slots; an unprivileged NET input task
allocates lwIP pbufs and calls the lwIP input path. TCP/IP drops privilege after
network setup. Its transmit callback sends a length-bounded copied frame to a
privileged SHIM transmit worker. The port's general MMIO MPU region is now
privileged-only, and unprivileged UART logging uses a copied queue serviced by
a privileged logger. V11 does not permit unprivileged dynamic queue creation;
a bounded privileged worker creates and reclaims registered lwIP mailboxes and
semaphores. The NET task MPU maps exclude the DMA, GATE and AUTH banks and
overlay APP as privileged-only.

Failed variants are retained. The first unprivileged-TCPIP build faulted when
the privileged link task passed a message from its protected stack into TCP/IP.
Link-state callbacks now originate in NET. The next variant faulted on a
per-call semaphore created by unprivileged NET input, so link callbacks use
`tcpip_callback`. The first live HTTP request then faulted on an unprivileged
lwIP mailbox creation; the bounded object worker resolved this. Earlier MMIO
variants exposed link and diagnostics stack margins; stack sizing and a
non-inlined queue logger restored acceptance. These are raw development
observations, not passing fault-reset evidence.

Step four still needs an explicit privileged-code/indirect-call audit and
SHIM surface reduction. The link monitor and MAC reset path remain privileged
driver logic. The ETH ISR still invokes HAL's handler, rather than only
acknowledging and notifying the SHIM task. The object worker grants the two NET
threads their lwIP objects broadly and has not yet undergone exact ACL and
adversarial-handle testing. These gaps prevent a final P1–P4 claim.

## Inherited and escalation injections

All fault probes are separate, verified Debug images. Their boot-test command
returns nonzero when the deliberate fault stops heartbeats. A nonzero exit is
expected for these probes; the SWD state, not that exit code alone, determines
the result. Each variant directory has an ELF hash, manifest, build log, raw
`board/uart.log`, and `swd.log`. Probe 2 has a simultaneous HTTP trigger log.

| Image/probe | Observed board result |
|---|---|
| R4 `r4-escalation-7`, raw `svc 102` | `CONTROL` became privileged (`line=70`); policy byte changed to `0xA7`; no memory fault. **V10.2 vulnerable.** |
| R4 `r4-escalation-8`, direct `xPortRaisePrivilege` | `CONTROL` became privileged (`line=80`); policy byte changed to `0xA8`; no memory fault. **V10.2 vulnerable.** |
| R4 `r4-escalation-9`, jump to wrapper-interior `svc 2` with crafted return frame | The SVC at `xPortRaisePrivilege+0x12` returned to attacker code with privileged CONTROL (`line=90`); policy byte changed to `0xA9`; no memory fault. **V10.2 vulnerable.** The exact temporary probe source and ELF disassembly are retained. |
| V11 `v11-escalation-7`, raw `svc 102` | Remained unprivileged (`line=71`); policy write faulted (`CFSR=0x82`, `MMFAR=0x20002250`); policy unchanged at 4. |
| V11 `v11-escalation-8`, direct old helper | V11 exports no `xPortRaisePrivilege`; the weak symbol was absent. `line=81` records unprivileged CONTROL; policy unchanged at 4. The final deliberate unprivileged panic caused a separate HardFault. |
| V11 `v11-escalation-9`, jump to `MPU_xTaskGetTickCount` SVC at entry+`0x12` | The syscall returned with unprivileged CONTROL (`line=91`); policy unchanged at 4. The final deliberate unprivileged panic caused a separate HardFault. The exact SVC offset is visible in the staged ELF disassembly. |
| V11 `v11-fault-1`, NET policy write | MemManage data fault, `MMFAR=0x20002250`. |
| V11 `v11-fault-2`, NET validator-input write during HTTP | MemManage data fault, `MMFAR=0x20007234`. |
| V11 `v11-fault-3`, NET APP-input write | MemManage data fault, `MMFAR=0x20020048`. |
| V11 `v11-fault-4`, NET direct `xPortStartScheduler` | MemManage instruction fault (`CFSR=1`). |
| V11 `v11-fault-5`, NET `CONTROL=0` then policy write | `CONTROL` stayed unprivileged; policy write faulted at `0x20002250`. |
| V11 `v11-fault-6`, APP policy write | MemManage data fault at `0x20002250`. The first run was invalid because the network probe guard panicked before APP; the saved final run corrected that ordering. |

The V11 wrapper-entry test shows no persistent privilege, but it is a
legitimate syscall and does not by itself prove all wrapper-entry gadgets
safe. No arbitrary-code compromise corpus has been run yet.

## Verified composed gate linked (§14)

Access and public-route decisions now call the extracted, verified
`GateLowGateDecide` (papers repo `experiments/verified-combiner`, commit
`f3daaef`; files and hashes in `Gateway/Provenance/manifest.json`, copied
verbatim except the bare-metal byte-order header shared with the policy
validator). `Gateway/Core/gateway_gate_adapter.c` decodes the 75-byte envelope
built by the proved `Mediation.Field` serializer into one partition (n = 1) and
calls the gate; policy updates and login keep their validators.
`GATEWAY_VERIFIED_GATE=0` restores the monolithic access validator.

| Evidence | Result |
|---|---|
| Host equivalence, gate vs monolithic validator on the same envelope (`tools/test_gate_equivalence.c`, ASan/UBSan) | 1,000,000 envelopes (500k structured, 500k random bytes), 105,493 accepts, **0 mismatches** |
| Host suite (`test_host.py`) | 301/301 self-tests, 119/119 legacy vectors |
| Final image `v11-verified-gate-final` (Debug, SHA-256 `d168322b…`) on the board | 301/301 boot self-tests; network suite 34/34 incl. 200 mixed requests; live policy 43/43; dashboard 129/129 |
| SCALANCE XB-200 policy as data, n = 32 (variant `v11-verified-gate-n32-variant`) | 17,760 oracle vectors, 2,622 accepts, **0 mismatches**, 0 fail-closed |
| Flash / static RAM (Release, gate vs monolithic access) | +4,392 B text, +0 B data/bss |
| GATE stack | lowest free 3,808 of 8,192 B during the network suite; gate chain frames are static and independent of n (≈ 536 B, `.su`); `GateLowScan` compiles to a loop (no recursive call in either configuration) |

Decision cycles (DWT, 96 MHz, caches off, interrupts enabled, 1,001 samples,
median; observed, not WCET). The n = 32 policy is loaded from flash data into a
RAM table by the privileged core task in the variant image, not through a
runtime update path (the 65-byte PolicyBlob carries eight rules).

| Case | Monolithic validator, n = 1 | Verified gate, n = 1 | Adapter + verified gate, n = 1 | Verified gate, n = 32 |
|---|---:|---:|---:|---:|
| First rule matches | 1,983 | 4,592 | 6,641 | 4,592 |
| Last rule matches | 2,093 | 4,693 | 6,742 | 92,712 |
| Absent path (deny) | 2,537 | 4,863 | 6,919 | 92,902 |

At n = 1 the verified gate costs about 2.3× the monolithic validator (48 µs vs
21–26 µs): it serializes each partition through LowParse writers and calls the
rate validator separately. A full n = 32 scan costs 0.97 ms.

## D1.8 final evidence on the verified-gate image (2026-09-30, paper side)

Final image: `v11-verified-gate-final2` (Debug, SHA-256 `12bc5490…`, source
`d7c753e`): verified composed gate (§14), `MEMP_NUM_NETCONN` 32 (was 3), no
per-second GATE stack log. The 95k audit (`v11-verified-gate-netconn32`) and
the probe images differ from it only by that one diagnostic line (probes: plus
`GATEWAY_D1_PROBE`).

| ID | Evidence | Result |
|---|---|---|
| E-func | Boot self-tests (incl. 12,527-case reference corpus through the verified gate), network suite, live policy, dashboard | 301/301, 34/34, 43/43, 129/129 |
| E-func | 200-case R1 attack corpus (`attacks-r1/`) | 0 disagreements, 0 fail-open, 0 audit mismatches, policy preserved and restored |
| E-func | 5,000-request `http.client` soak | 5,000/5,000; median / p99 / max 18.5 / 19.5 / 20.2 ms |
| E-P1 | Effect audit (`v11-verified-gate-netconn32/e-p1-audit-100000`) | 95,532/95,532 matched, 57,225 effects each paired with one acceptance, 0 violations, 0 transport errors (stopped by the host job time limit, not the board) |
| E-P2a/E-P3 | NET probes 1-7: write GATE policy, write validator input, write/read AUTH key, write APP input, call a GATE function, call the AUTH client | each MemManage data fault at the target region (GATE `0x2005xxxx`, AUTH `0x20061000`, APP `0x20020048`), faulting task NET |
| E-P2a | Probe 8: forged job on a leaked GATE->APP queue handle | kernel ACL rejects the send (`send=0`); APP never received a job |
| E-P2b | Probes 9-11: SVC raise, wrapper-interior SVC (`svc 13` at `MPU_xTaskGetTickCount+0x12`, checked in the ELF), CONTROL write, each followed by a policy write | policy write still faults: no privilege gained |
| E-P2c | Probe 12: NET writes ETH MAC register; probe 13: NET writes the Ethernet DMA buffer | MemManage at `0x40028000` and `0x20074140` |
| E-P2c | Probes 14 (forged RX slot index) and 15 (overlong TX request) | **inconclusive**: the harness did not drive the probe's frame path within its window; code review: the SHIM asserts `slot < FRAME_SLOTS` before any write and rejects TX length > frame size |
| E-fault | Every contained probe: fault -> IWDG reset -> restrictive boot policy | operator 403 after each reset (NET, GATE probe 20: GATE writes AUTH key -> fault at `0x20061000`; APP probe 21: APP writes GATE policy -> fault at `0x20054250`, see `v11-final-probe-21/board/uart-raw.log`) |
| E-fault | AUTH probe 22 | **inconclusive**: probe did not fire in the final run |
| E-map | Privileged-code inventory and region map (`v11-verified-gate-final/e-map/privileged-inventory.json`) | 9 privileged tasks and 12 ISRs; SHIM closures RX 5.6 KB, TX 8.8 KB, link 12.3 KB, ETH ISR 2.1 KB; 81 unresolved register-indirect call sites listed |
| E-cost | Verified gate DWT cycles (§14 section above) | n = 1: 4.6-4.9k cycles (48-51 µs) vs monolithic 2.0-2.5k; n = 32 scan 93k |
| E-P5 | Control task 1/4/10 kHz × bucket on/off × idle/valid/denied/malformed (`final2-control-*`) | **bucket on (primary configuration): 0 misses at 1 and 4 kHz** under all loads; 10 kHz 92-117 misses (critical-section max 13,145-13,664 cycles > 9,600-cycle period), as at stage 7. **Bucket off: 0 misses at 1 kHz, 480-704 at 4 kHz, 630-887 at 10 kHz**, critical-section max 34,620-36,119 cycles. Idle baseline 0 in every image. |

Findings from this round:
- **NET liveness under load (fixed).** With 3 netconns the normal peak
  (listener + served connection + pending accept) filled the pool; 343
  allocations failed in a 48k-request run (client connection resets), and one
  run ended with NET blocked in `netconn_delete` on a never-signalled semaphore
  (SWD task dump in `v11-verified-gate-final/e-p1-hang/`). netconns are
  released after every close (no leak). With 32 netconns: 0 failures, peak 3.
- **Latent long critical section (not fixed, not located).** Some builds show a
  critical section of ~36k cycles (~375 µs) under load: the previous final image
  in its bucket-on build, the final2 image in its bucket-off build; the other
  build of each pair shows ~13.6k, as at stage 7 (stage-7 source rebuilt now:
  13,639). It appears in one build or the other rather than following the
  verified gate, the netconn pool or the GATE stack log (`bisect-*`); the
  earlier commit message attributing it to the GATE log is wrong. Until it is
  located, 4 kHz P5 holds for the measured primary image only.
- **Design weakness (not fixed).** NET<->GATE and GATE<->APP use one-slot reply
  queues with 2 s timeouts and no sequence number; a late reply could be paired
  with the next request. AUTH's exchange already checks a sequence number.

## Property boundary

| Claim | Stage-one status and reason |
|---|---|
| P1 complete mediation | **Open**: GATE is unprivileged and NET/SHIM copies work, but the 100,000-request exact-effect audit and final injection matrix are missing. |
| P2 gate integrity | **Open**: named NET/APP writes faulted and NET no longer maps DMA, but final entry-point and privileged-code audits are missing. |
| P3 identity integrity | **Partial**: AUTH owns the key/table and named NET/APP reads faulted; full compromised-NET and forged-role corpus is pending. |
| P4 policy updates | **Open**: functional update/rollback tests pass, but final D1 compartment injections and reset-default tests remain. |
| P5 no starvation | **Open**: priorities, token bucket and §13.5 idle/loaded timing matrix are not installed. |

The paper-reference EverParse and Low* mediation artifacts retain the R1/R4
proof and test boundary. This port did not perform a fresh proof run. The
FreeRTOS kernel, all privileged code, the Ethernet DMA, HAL, and board hardware
remain trusted. DWT maxima, when later measured, will not be WCET bounds.

Next per D1.7: complete steps 5–6 and the amended §13 final evidence. The eventual final
D1 report must replace this no-go verdict.
