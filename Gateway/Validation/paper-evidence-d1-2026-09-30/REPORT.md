# D1 evidence — stage 1, 2026-09-30

**Verdict: D1 is not established.** This directory records the first D1.7
build-up step: an operational FreeRTOS V11.3.1 MPU wrappers v2 port of the R4
task split, with inherited MPU and privilege-escalation probes on the
NUCLEO-F767ZI. GATE, AUTH and SHIM have not been separated as §12–§13 require.
P1–P5, the restrictive reset policy, the labelled A/B corpus, P5 timing
matrix, and final cost claims remain open.

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
  heap and current gate state. APP has a separate 16 KiB region. The current
  network task still sees broad nonprivileged RAM and the GATE task is still
  privileged. This is a transitional R4 split, not D1 isolation.
- CMSIS mutex handles now encode the V11 opaque handle separately from the
  recursive flag. The old adapter interpreted the first valid handle `1` as
  null, dropping all post-boot logs. The final image has zero log drops.
- V11's MPU wrapper configuration does not retain the old software stack hook
  in the linked image; MPU stack protection applies to unprivileged tasks.
  A whole-call-chain stack bound has not been proved.

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

## Property boundary

| Claim | Stage-one status and reason |
|---|---|
| P1 complete mediation | **Open**: gate remains privileged; no 100,000-request effect audit on D1. |
| P2 gate integrity | **Open**: named NET/APP writes faulted, but current NET still sees broad general RAM and no full compartment map exists. |
| P3 identity integrity | **Open**: credentials and HMAC key have not moved to AUTH-only memory. |
| P4 policy updates | **Open**: existing R4 validator tests are not D1 compartment evidence. |
| P5 no starvation | **Open**: priorities, token bucket and §13.5 idle/loaded timing matrix are not installed. |

The paper-reference EverParse and Low* mediation artifacts retain the R1/R4
proof and test boundary. This port did not perform a fresh proof run. The
FreeRTOS kernel, all privileged code, the Ethernet DMA, HAL, and board hardware
remain trusted. DWT maxima, when later measured, will not be WCET bounds.

Next per D1.7: build the private `IDENTIFY`/`LOGIN` AUTH oracle, move its table
and HMAC key into AUTH-only RAM initialized from privileged flash, then make
GATE unprivileged with a disjoint region. The eventual final D1 report must
replace this stage-one no-go verdict and satisfy §13 where it amends §12.
