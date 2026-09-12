Current dashboard/login port: [DASHBOARD.md](DASHBOARD.md). TLS remains deferred.

# STM32F767 FreeRTOS policy-gate core

> **Current: milestone 2 HTTP/Ethernet integration.** Read [NETWORK.md](NETWORK.md)
> for the running server, Bearer fixtures, memory budget and test commands, and
> [NETWORK_VALIDATION.md](NETWORK_VALIDATION.md) for current evidence. The text
> below describes the preserved milestone-1 baseline; its test counts, heap size
> and networking status are historical.

Milestone 1 implements and exercises the extraction → trusted identity attributes →
EverParse policy → protected dispatch path under the existing FreeRTOS scheduler.
The identity and rate values are synthetic test fixtures. Ethernet, credentials,
stateful rate limiting, TLS and network request assembly are subsequent work.
See [VALIDATION.md](VALIDATION.md) for the exact tested images and observations.

## Application structure

`gateway_core` owns a 4096-byte request, separate 1536-byte security/application/
response buffers, a 37-byte identity-population buffer and the active policy.
One task owns and mutates this context. These arrays must remain stable during
synchronous core calls; tasks, DMA and future socket input must not share writable
access. The context and larger self-test buffers are static, not task locals.

The call sequence in `Inc/gateway_core.h` is:

1. `gateway_init` once, then `gateway_begin_request` for each request.
2. Fill initialized bytes in `request`, set `request_len`, call `gateway_extract`.
3. On successful extraction, supply an independently stored, trusted
   `GatewayIdentity` to `gateway_set_identity`, including the rate value.
4. `gateway_evaluate` either denies, commits a validated policy update, or permits
   forwarding. Only `gateway_dispatch` consumes the forwarding result; it cannot
   dispatch the same authorization twice.

Incomplete/malformed extraction has a separate `extraction_code`. The future
transport must assemble a bounded complete request and enforce HTTP framing and
connection lifecycle rules. The extractor supports a restricted method/path set;
it is not a general HTTP server/parser. Never treat caller-supplied roles or
`GatewayIdentity.valid` as network authentication.

`Core/extractor_adapter.c` includes only the extractor runtime;
`Core/control_pipeline.c` includes only the EverParse runtime. This separation
avoids conflicting generated macros. `gateway_core.c` checks lengths and state,
uses a candidate policy for transactional updates, and implements the reference
ProtectedApp responses. The adapted pipeline requires exactly 65 policy body
bytes and neutralizes inactive rule slots, because the access validator evaluates
all eight slots without a `num_rules` field.

## Scheduling and diagnostics

`Platform/gateway_platform.c` creates a static 8192-byte core task and a static
2048-byte diagnostics task, using CMSIS priorities Normal and Low. The core runs
191 checks once, then blocks; diagnostics toggle LD1 and print a heartbeat every
second. There are no busy-wait demonstration workloads. The default generated
task has been removed from both the source and `.ioc` configuration.

UART3 remains PD8/PD9, 115200 8-N-1. `gateway_log` serializes complete bounded
messages using a static priority-inheritance mutex and reports truncation/timeouts
as dropped logs. Logging is task-context only. The `_write` override supports
length-delimited libc output; application messages should use `gateway_log`.

Stack overflow mode 2, allocation-failure hooks, `configASSERT` and CPU exception
handlers enter `gateway_panic`, light LD3 and preserve `gateway_fault_record` for
the debugger. This path does not allocate, log, or acquire a mutex. The record
contains the reason, CFSR/HFSR, MSP/PSP and available assertion/task information.
It is RAM-only and is cleared on reset. LD3 also indicates test failure or a low
measured stack margin. A high-water margin below 25% is reported as `LOW`.

The existing heap_4 budget remains 15360 bytes. Startup allocates and immediately
frees one byte to initialize its lazy accounting and check the allocator. Long-lived
application tasks, stacks and mutex storage are static. The reported FreeRTOS
heap is separate from libc allocation and any future lwIP/TLS budgets. The main
stack linker reservation is 4096 bytes, separate from task stacks. Neither that
reservation nor task high-water readings prove worst-case interrupt stack bounds.

## Build and repeat tests

From the project root:

```sh
python3 Gateway/tools/check_project.py
python3 Gateway/tools/test_host.py --sanitize
python3 Gateway/tools/build_firmware.py
```

The host runner builds the same generated C, handwritten core and 191 vectors
with GCC warnings as errors. Sanitizer mode uses ASan and UBSan with fatal
undefined-behavior diagnostics. Host tests do not exercise the FreeRTOS adapter.

The firmware builder uses the installed CubeIDE 2.0.0 headless builder in an
isolated IDE workspace, matching STM32 GCC 13.3.1, and checks both Debug and
Release. Close CubeIDE before changing project metadata or running a headless
build against the same project. `--output /tmp/a-chosen-directory` retains logs
at a known location. Outputs are `Debug/policy_gate.elf` and
`Release/policy_gate.elf`. Building does not flash the board.

Both configurations compile `Gateway/Generated` with `-Os`, including Debug.
This is required because unoptimized extracted recursion can exhaust an MCU
stack. Each build runs `check_firmware.py`, inspecting actual ELF calls, strong
fault hooks, generated compile recipes and stack-usage reports. It rejects
recursive extractor call cycles or unresolved extractor indirect calls, and
writes `gateway.disassembly.txt` and `gateway.stack.json` beside the ELF.
Known-frame sums exclude unmeasured library/assembly/interrupt costs; they are
build evidence, not a complete stack bound. Revalidate when changing compiler,
flags, generated code, library usage or task workloads.

## CubeMX/CubeIDE consistency

The maintained configuration is `.cproject` plus `policy_gate.ioc`. Board startup,
96 MHz clocks, TIM6 HAL tick and scheduler SysTick are retained. Application entry
points, fault hooks and includes use CubeMX user-code regions or separate modules.
There are no generated CubeMX tasks; the application creates its own tasks after
`osKernelInitialize` and before `osKernelStart`.

After regeneration, review the source changes, then run:

```sh
python3 Gateway/tools/configure_project.py
python3 Gateway/tools/check_project.py
python3 Gateway/tools/build_firmware.py
```

The configuration script maintains Gateway source discovery, include paths,
per-folder `-Os` and post-link checks. It does not repair arbitrary regenerated
C or `.ioc` changes; the consistency check reports discrepancies. Do not maintain
integration by editing generated `Debug/*.mk` or `Release/*.mk` files. The host
entry point and provenance files are excluded from firmware compilation.

## Board execution

The test board's stable serial device is:
`/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02`.
Open a serial reader at 115200 8-N-1 before resetting; retain a fresh `[BOOT]`
marker and the ensuing `[CORE SELFTEST] PASS 191/191`, followed by at least five
PASS heartbeats with `margin=OK` and `log_drops=0`. Do not accept buffered output
from a previous firmware image as a test result.

The installed STM32CubeProgrammer executable is under:
`/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.linux64_2.2.300.202508131133/tools/bin/STM32_Programmer_CLI`.
For an intentional Debug deployment, its arguments are:

```text
-c port=SWD sn=066FFF555567894967085545 mode=UR freq=1000 -d Debug/policy_gate.elf -v -rst -run
```

These arguments program flash and reset/run the MCU. Under-reset connection was
needed on this board; hot-plug identification failed. No option-byte changes,
readout unlock, mass erase or probe firmware updates were performed. A full 2 MiB
pre-port flash backup is recorded in the validation report.

## Provenance and remaining work

[Provenance/manifest.json](Provenance/manifest.json) records reference paths,
commit and original/local SHA-256 hashes. Generated algorithm files are unchanged;
the only generated runtime adaptation is an explicit GCC little-endian ARM branch
in `EverParseEndianness.h`. Adapted runtime/pipeline/tests have reviewable diffs in
`Provenance/patches`. Original license notices are retained.

The six legacy suites retain all 119 vectors. Their IPC suite now invokes the
actual generated IPC routines. Another 72 checks cover buffer boundaries,
incomplete requests, identity clearing, policy allow/deny and transactional
updates, inactive slots, truncation and guarded dispatch. No new F* proof checking
or extraction was performed; the original unknown tool-version markers remain.
The handwritten port, scheduling and tests are not automatically verified by F*,
EverParse or HACL*. FreeRTOS tasks do not reproduce seL4 component isolation.

Next is milestone 2: lwIP RTOS mode, Ethernet/PHY input, confirmed F767 DMA/cache
placement, and one bounded connection through the core. Existing ETH peripheral
initialization and descriptor declarations do not establish a working network;
DMA sections/cache ownership still need review before Ethernet starts. Milestone
3 adds authenticated HTTPS, real entropy, credential/token lifecycle and stateful
rate-window semantics, followed by complete memory and failure measurements.
