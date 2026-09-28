# Verified mediation research branch — 2026-09-12

This branch adds `Verification/` and generated Low* mediation code under
`Gateway/Generated/Mediation`. Read `Verification/README.md` and
`Verification/REPORT.md` for the exact claims, trusted FFI contracts, replay gap,
and reproducible tools. HTTP now admits public assets and login through the gate
as well as protected APIs and policy updates. The original generated cores are
unchanged. Do not hand-edit the new generated C; use `Verification/tools/prove.py
--extract`. The installed board firmware and `main` have not been changed by this
experiment. Host tests and ARM builds do not authorize or establish deployment.

# Live policy editing — current

The dashboard now exposes admin-only operator-access toggles for `/demo` and
`/api/status`. `/demo` is a protected plain-text GET route, denied to operator
by default; admin access remains enabled. Actual policy readback replaces the
placeholder response. See `Gateway/DASHBOARD.md` and current
`Gateway/LIVE_POLICY_VALIDATION.md`. Generated algorithms remain unchanged;
`gateway_routes.h` and the HTTP adapter supply the distinct demo path ID.

# Dashboard/login port — 2026-09-12

The dashboard and bounded lab username/password login are implemented. Read
`Gateway/DASHBOARD.md` and `Gateway/DASHBOARD_VALIDATION.md` for current status.
HACL algorithms are unchanged under `Gateway/Generated/Auth`; handwritten
`Gateway/Auth` adaptations and original HTML are tracked in `Provenance/auth.json`.
TLS is deferred by user instruction. Tokens are deterministic lab HMAC tokens;
logout clears the browser token but does not revoke it server-side. The original
static Bearer fixtures remain compatible. Earlier milestone counts below are
historical; use current validation evidence.

# STM32F767 gateway port — project context and working instructions

## Current implementation status — milestone 2, 2026-09-10

The Ethernet/HTTP implementation is in `Gateway/Network` and the portable HTTP
adapter is in `Gateway/Core/gateway_http.c`. Read `Gateway/NETWORK.md` and
`Gateway/NETWORK_VALIDATION.md` for the current interfaces, evidence and limits.
Earlier milestone-1/demo descriptions below are historical.

- The configured board address is `192.168.40.128/24:80`, no default gateway.
  The validated host route is `enp44s0`, `192.168.40.1/24`; do not change host
  addresses/routes as part of routine tests. Board MAC: `02:80:e1:1c:67:11`.
- HTTP uses `Authorization: Bearer` with hard-coded `pg-lab-operator`,
  `pg-lab-admin`, and `pg-lab-limited` fixtures. No arbitrary role/scope headers.
  Policy updates are binary, exactly 65 bytes, transactional and RAM-only.
- One gateway task owns the connection and buffers; lwIP uses `NO_SYS=0` and
  netconn APIs. TCP/IP, RX input and PHY/link tasks have distinct ownership.
- Both firmware configurations build without warnings. Host sanitizer validation
  passes 226 checks, or 193 with lab authentication disabled. Current on-target
  startup and network results, final ELF hashes and remaining manual hardware
  tests are recorded in `Gateway/NETWORK_VALIDATION.md`.
- All imported generated algorithms and vendored lwIP/PHY sources remain unchanged.
  The maintained CMSIS adapter is separate from the vendor copy; its diff and
  the ST Ethernet reference are in `Gateway/Provenance`.
- Upper 64 KiB RAM is reserved for Ethernet. General RAM/MSP ends at `0x20070000`.
  Descriptor and payload MPU attributes, alignment and linker bounds are checked.
  FreeRTOS heap is 65536 bytes; lwIP heap is separate at 16384 bytes.
- Five task stacks: gateway 8192, diagnostics 2048, TCP/IP 4096, Ethernet RX 4096,
  link monitor 2048 bytes. CPU clocks remain 96 MHz and caches remain disabled.
- Build/configure/check scripts remain under `Gateway/tools`. `board_test.py`
  explicitly flashes/resets the board; `test_network.py` changes and restores
  RAM policy. Use only one serial reader. Do not build while deploying an ELF.
- Before milestone 2, the entire workspace and milestone-1 firmware were saved to
  `/tmp/policy-gate-ethernet-lxhh7vnq/before.tar.gz`. Current maintained evidence is
  `Gateway/Validation/milestone2-2026-09-10`.
- Next milestone is TLS, hardware entropy, real token lifecycle and stateful rate
  semantics. Hard-coded Bearer checking does not establish production security.

## Milestone 1 baseline — 2026-09-10 (historical)

Milestone 1 is implemented in `Gateway/` and was run on the connected STM32.
Read `Gateway/README.md` and `Gateway/VALIDATION.md` before continuing. The sections
below describing the original demo/assessment are historical, unless superseded
by this status section and the maintained source.

- Both Debug and Release build with STM32 GCC 13.3.1 without warnings and pass
  191/191 tests on the NUCLEO-F767ZI; the same host vectors pass ASan/UBSan.
- The final Debug image is programmed and running. Final measured unused task
  stacks: 6276/8192 bytes core, 948/2048 bytes diagnostics; no dropped UART logs.
- Generated algorithms are preserved, with hashes/specifications/adaptation diffs
  in `Gateway/Provenance`. No new F* proof run was performed.
- The scheduler demo/default tasks were replaced by static core-test and heartbeat
  tasks. One context owns request/security/auth/app/response buffers and policy.
- Identity and rate values are synthetic fixtures. No actual authentication,
  stateful rate limiter, Ethernet server or TLS integration is present yet.
- Generated C always uses `-Os`, including Debug. A maintained post-link check
  rejects extractor recursion; its negative O0 scanner test also passed.
- UART logging is serialized. Allocation/stack/assert/fault diagnostics are
  configured. Heap_4 remains 15360 bytes; startup probes lazy heap initialization.
  Core/diagnostics stacks are 8192/2048 bytes, with a 4096-byte MSP reservation.
- Sources, `policy_gate.ioc` and `.cproject` are consistent. Use the scripts in
  `Gateway/tools`; do not maintain integration through generated makefiles.
- Pre-core workspace backup: `/tmp/policy-gate-core-kn_2uc2z/before.tar.gz`.
  Original board flash: `/tmp/policy-gate-core-kn_2uc2z/target-before.bin`.
  Maintained evidence and tested ELF hashes: `Gateway/Validation/2026-09-10`.
- Next work is milestone 2: lwIP RTOS integration and a bounded single-connection
  transport, after establishing F767 Ethernet DMA/cache placement and ownership.

## Agreed objective

Port the gateway logic from the existing HTTP gateway research project to the
**NUCLEO-F767ZI, using this project's existing FreeRTOS scheduler**. Organize the
application as C modules and tasks suitable for the MCU.

- Do not port seL4, CAmkES, their component runtime, or the x86 system image.
- An earlier bare-metal plan was explicitly superseded by the user: **FreeRTOS is
  now the target**.
- Reuse this `policy_gate` workspace; another CubeIDE scaffold is unnecessary.
- Preserve the generated F*/EverParse core where possible and redesign platform
  integration, request ownership, and scheduling around STM32/FreeRTOS.
- The user requested this context handoff and will continue from this workspace.
  The production integration has not yet been implemented here.

## Locations

Target workspace:
`/home/iamfo470/stm32-projects/policy_gate`

Original gateway source (keep available as the reference implementation):
`/home/iamfo470/phd/camkes-vm-examples/projects/http_gateway_x86`

Installed Cube firmware package:
`/home/iamfo470/STM32Cube/Repository/STM32Cube_FW_F7_V1.17.4`

STM32CubeIDE:
`/opt/st/stm32cubeide_2.0.0`

Matching compiler directory:
`/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin`

The target workspace was not a Git repository at handoff. No source changes were
made here before this AGENTS.md; all compilation experiments used temporary copies.


The workspace directory and CubeIDE logical project name are `policy_gate`.
The CubeMX configuration is `policy_gate.ioc`; the debug launch configuration is
`policy_gate Debug.launch`. Debug and Release builds produce `policy_gate.elf`
in their respective build directories. The maintained build and launch metadata
use the same project name. Historical `hello_uart` audit paths below remain
unchanged. If CubeIDE still points to the previous directory, reopen/import the
project here.

Before the naming migration, the complete demo workspace was backed up to:
`/tmp/policy-gate-rename-hwpqm9e7/before.tar.gz`.
This rename changes project metadata only; it does not integrate the gateway or
establish any additional target-side test results.

## Hardware and tools observed

- User identifies the connected board as NUCLEO-F767ZI, MCU STM32F767ZIT6.
- USB enumeration showed ST-LINK/V2.1, VID:PID `0483:374b`.
- Virtual serial port was `/dev/ttyACM1`. Prefer the stable device link:
  `/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02`.
  Recheck enumeration if disconnected or reconnected.
- USART3 uses PD8 TX / PD9 RX, 115200 baud, 8-N-1, no flow control.
- ARM GCC, OpenOCD, st-info, and CubeIDE-bundled STM32CubeProgrammer and ST-LINK
  GDB server are installed.
- The system compiler is ARM GCC 13.2.1; the existing CubeIDE project was rebuilt
  with its matching bundled STM32 GCC 13.3.1. Prefer the latter for this project.
- CubeIDE 2.0.0 uses standalone CubeMX for peripheral configuration/code generation.
  The `.ioc` records CubeMX 6.16.0 and STM32CubeF7 1.17.4.
- No firmware was flashed, the MCU was not reset, and no target-side tests were
  performed during the assessment. USB enumeration alone did not verify MCU execution.

## Existing target project

Key files:

- `policy_gate.ioc`: NUCLEO-F767ZI, FreeRTOS/CMSIS-RTOS v2, ETH RMII, USART3.
- `Core/Src/main.c`: initialization, diagnostics, UART printf redirection,
  default task, and three scheduling demonstration tasks.
- `Core/Inc/FreeRTOSConfig.h`: scheduler and memory configuration.
- `Core/Src/stm32f7xx_hal_timebase_tim.c`: HAL tick on TIM6.
- `Core/Src/stm32f7xx_it.c`: exception/peripheral handlers.
- `Core/Src/stm32f7xx_hal_msp.c`: UART and Ethernet GPIO/peripheral setup.
- `STM32F767ZITX_FLASH.ld`: 2 MB flash and 512 KB RAM memory regions.
- `.cproject`, `.project`, `Debug/makefile`: CubeIDE project/build metadata.

Current configuration and implications:

- HSE bypass at 8 MHz with PLL provides 96 MHz SYSCLK. Adequate for initial tests;
  there is no requirement to switch immediately to 216 MHz.
- Preemptive scheduler, 1000 Hz tick. SysTick belongs to FreeRTOS; HAL uses TIM6.
- Both static and dynamic FreeRTOS allocation are enabled; `heap_4` is selected.
- `configTOTAL_HEAP_SIZE` is 15360 bytes. Networking/TLS require a new memory budget.
- Default task stack is `256 * 4` bytes. Native demo tasks use `xTaskCreate(...,
  256, ...)`, i.e. 256 32-bit words / 1 KB on this port.
- CMSIS task stack sizes are in bytes; native FreeRTOS stack depths are in words.
- The default task uses CMSIS `osPriorityNormal`; demo tasks use native priorities
  1/2/3. Do not assume these are the same priority scale.
- `INCLUDE_uxTaskGetStackHighWaterMark` is enabled. Stack-overflow and allocation
  failure hooks still need explicit configuration/implementation for the port.
- Demo tasks deliberately busy-wait and print to UART. Replace these workloads
  with useful tasks that block on events/delays. Serialize logging.
- `__io_putchar` uses blocking `HAL_UART_Transmit` per character. Newlib reentrancy
  does not itself serialize the UART or entire log messages.
- ETH RMII/LAN8742 configuration exists, but no lwIP networking stack is integrated.
- Ethernet descriptor arrays use `.RxDecripSection` and `.TxDecripSection`, but
  the GCC linker script does not explicitly place those sections. The existing
  map placed RX descriptors at `0x2000006c`. Review actual F767 DMA accessibility,
  alignment, cache attributes and section initialization before networking.
  Do not apply STM32H7 memory restrictions to F767 without checking its manual.
- Linker minimum stack reservation is only `0x400`; this is distinct from task
  stacks and is not a proven worst-case stack bound.
- Debug uses `-O0`; Release uses `-Os`. See generated recursion below.

## Original gateway: what to reuse

Read current source and CMakeLists.txt before relying on architecture documents.
Several documents describe obsolete stages, including claims that the F* extractor
has not been implemented. It is implemented in the current code.

The active original architecture has eight components:
E1000Driver -> TlsValidator -> LwipProxy -> FStarExtractor -> PolicyGate -> ProtectedApp,
with Authenticator and RateLimiter called by FStarExtractor.
TlsValidator is a passthrough; LwipProxy terminates TLS using mbedTLS.

Relevant paths relative to the original gateway root:

| Source | Purpose |
| --- | --- |
| `verified/HTTP.Extract.*.fst` | F*/Low* HTTP extraction source |
| `verified/IPC.Extract.fst` | Verified auth/rate field population |
| `verified/Makefile` | Verification and KaRaMeL extraction commands |
| `verified/extracted/` | Generated C reference copies |
| `components/FStarExtractor/HTTP_Extract_*.c` and `.h` | Seven active extractor modules |
| `components/FStarExtractor/IPC_Extract.c` and `.h` | Active field-population module |
| `components/FStarExtractor/krml_include/` | Generated-code runtime headers |
| `components/include/security_params_wire.h` | Flat request/security wire layout |
| `components/include/{extract,path_hashes,auth_wire,app_wire,gate_response_wire}.h` | Shared interfaces/constants |
| `specs/RbacPolicy.3d` | Policy validator specification |
| `components/PolicyGate/everparse_generated/` | Active EverParse validator and wrapper |
| `components/PolicyGate/control_pipeline.c` and `.h` | Handwritten policy buffer construction and dispatch |
| `components/Authenticator/` | Credential/token implementation and HACL* primitives |
| `components/RateLimiter/RateLimiter.c` | Stateful per-subject counters |
| `components/ProtectedApp/ProtectedApp.c` | Original application behavior |
| `components/LwipProxy/` | Original networking/TLS behavior; platform-specific |
| `verified/test_*.c` | Six existing extractor test harnesses |

The active extracted C matches `verified/extracted` in executable content. Some
file generation comments differ. Preserve provenance; do not silently hand-edit
verified algorithm bodies and continue describing them as freshly verified output.

### Extractor contract and limits

```c
uint8_t extract_security_params(uint8_t *http_buf, uint32_t http_len,
                                uint8_t *out_buf, uint32_t *out_len);
```

- Input has at least `http_len` accessible initialized bytes.
- Output buffer has at least 1536 bytes.
- Input, output, and output-length storage are valid and mutually non-overlapping.
- Input remains stable during extraction; no other task or DMA may overwrite it.
- Output layout: 175-byte header plus at most 1361 body bytes; no embedded pointers.
- The original component assembles requests in a 4096-byte buffer.
- Extracted routines use caller-owned buffers, with no OS calls or heap allocation.
- Supported methods are GET/POST/PUT and paths are a fixed supported set, with
  sentinel identifiers rather than arbitrary path hashes. This is a restricted
  security extractor, not a general complete HTTP implementation.
- `populate_auth_fields` requires a separate auth buffer of at least 37 bytes and
  output of at least 42 bytes. Validate response length and initialize the buffer
  before using it. Its bounded role/subject writes do not authenticate the sender.

### Verification boundaries

The F* contracts cover memory-safety/frame properties under caller preconditions,
termination measures, and selected field bounds. The main extractor postcondition
does not establish complete HTTP semantic correctness. EverParse checks the
predicates expressed in the policy specification, using attributes supplied by
handwritten integration code. HACL* supplies verified cryptographic primitives;
that does not verify the entire credential/token protocol.

Running these routines in a preemptible task is compatible with their sequential
use when buffer ownership and preconditions are maintained. Task communication,
networking, synchronization and application integration are additional handwritten
code, not automatically covered by those proofs.

Fresh F* proof checking/extraction was NOT performed in this assessment. Tools were
missing at the configured default path under `/home/iamfo470/phd/everparse`.
Generated files also contain unknown tool-version markers. Reestablish pinned
verification/extraction tools before changing the F* sources or claiming a fresh proof run.

## Evidence already collected

### Host and Cortex-M7 checks

- All 119 existing extractor tests passed on the host against active component C:
  scan 13, method 17, path 30, header 22, complete extractor 24, IPC population 13.
- All eight extracted C modules compiled unchanged for Cortex-M7 with ARM GCC
  13.2.1, `-mcpu=cortex-m7 -mthumb -Os`.
- EverParse's shipped `EverParseEndianness.h` rejects bare-metal ARM as unsupported.
  A temporary little-endian platform branch allowed its validator, wrapper and
  handwritten control pipeline to cross-compile.
- HACL* hash/HMAC files and handwritten credential/token helper files compiled.
  `Lib_Memzero0.c` raised an unsupported secure-clearing warning under `-Werror`;
  a suitable secure-clear implementation/configuration remains necessary.
- Approximate unlinked object code: 1830 bytes for extraction; 9642 bytes for the
  full policy validator plus wrapper. These exclude final runtime/buffers/firmware.

### Critical recursion finding

Generated routines include recursion. At `-O0`, `scan_loop` consumes 32 bytes per
recursive step with the tested GCC 13.2.1 compiler; a roughly 4 KB unterminated
header can therefore use around 128 KB stack. This cannot use a 1 KB task stack.

The tested `-Os` extractor objects had no recursive self-calls. For the actual
firmware, set and inspect suitable optimization for these modules in Debug as
well as Release, or change the F* implementation to extract loops and reverify.
Do not assume tail-call optimization is a language guarantee or that per-function
`.su` values alone establish whole-call-chain stack bounds.

### Existing FreeRTOS project and temporary integration

Using CubeIDE's STM32 GCC 13.3.1:

1. Rebuilt a clean temporary copy of the existing demo successfully, with no
   compiler warnings/errors. Sections: text 34304, data 428, bss 22820 bytes.
2. Added all extractor sources, the adapted policy validator and a small probe
   called once from `StartDefaultTask`; build and link succeeded without warnings.
3. Confirmed `StartDefaultTask`, `gateway_compile_probe`,
   `extract_security_params`, and `RbacPolicyValidateAccessRequest` in the ELF.
4. Integration ELF sections: text 40872, data 508, bss 24436 bytes. Link-time GC
   removes unused code. This is a probe, not the full gateway/TLS memory cost.
5. Including both generated runtime header families in one translation unit caused
   macro redefinition errors. Separate C adapters resolved this cleanly.
6. Probe is NOT authenticated end-to-end: it uses synthetic auth attributes and
   exercises extraction plus an allow/rate-deny policy setup. It was compiled and
   linked, NOT run. Its inherited 1 KB task stack has not been validated for execution.

Temporary artifacts (may disappear; not the maintained port):

- `/tmp/stm32-audit-91fhq1ot/`: host tests, initial ARM objects, policy adaptation,
  stack reports and disassembly.
- `/tmp/gateway-freertos-check-shzizuz4/baseline-build.log`
- `/tmp/gateway-freertos-check-shzizuz4/integration-build.log`
- `/tmp/gateway-freertos-check-shzizuz4/hello_uart/GatewayProbe/`: temporary probe,
  generated C/runtime copies and separate policy adapter.
- `/tmp/gateway-freertos-check-shzizuz4/hello_uart/Debug/hello_uart.elf`

The temporary project modifications were not copied into this workspace. Use
these artifacts as evidence/examples, not as a completed implementation.

## Agreed implementation direction

Start with one gateway task owning the connection, HTTP assembly buffer, security
parameter buffer, authentication/rate state, policy and dispatch. Keep extraction,
authentication and policy as C modules invoked synchronously within that task.
Additional tasks should have a concrete scheduling/ownership purpose.

For network integration:

- Use lwIP RTOS mode (`NO_SYS=0`) with its TCP/IP thread and STM32 Ethernet input
  integration. Use netconn or sockets from the gateway task.
- The x86 application's `NO_SYS=1` raw-API polling loop cannot simply be called
  from arbitrary FreeRTOS tasks. Respect lwIP thread rules.
- Start with one active connection and bounded buffers. Handle fragmentation,
  incomplete/oversized requests, connection close, timeouts and backpressure.
- Use a low-priority diagnostics/heartbeat task and serialize UART output.
- Prefer statically allocated long-lived buffers/stacks where practical. Track
  FreeRTOS heap, libc/TLS allocation and lwIP pools as distinct memory consumers.
- Do not reproduce busy polling and large shared-data rings solely to mirror the
  original component layout.

### Milestones

1. **On-target core validation under FreeRTOS**
   - Preserve board startup, clocks, UART, scheduler and HAL timebase.
   - Replace scheduling demo workloads with core-test and heartbeat tasks.
   - Integrate generated extraction and policy modules through narrow C adapters.
   - Run existing meaningful vectors, including incomplete/maximum-size requests
     and policy allow/deny cases. Report results over UART.
   - Configure stack-overflow/allocation failure diagnostics, check task creation
     return values, measure stack high-water marks, and inspect optimized code.
   - Build a reviewable firmware before hardware deployment; distinguish build
     results from actual observed board results.
2. **HTTP over Ethernet**
   - Integrate lwIP/FreeRTOS and STM32 Ethernet/PHY handling.
   - Establish DMA section placement/cache handling and buffer ownership.
   - Route bounded requests through extraction and policy-controlled application
     dispatch; initially one connection.
3. **Authenticated HTTPS**
   - Integrate credential/token handling, TLS and MCU hardware entropy.
   - Replace x86 `rdtsc`/`rdrand` and demo entropy fallback.
   - Address demo hardcoded secrets, token lifecycle and rate-window/reset semantics.
   - Measure complete flash/RAM/stack usage, responsiveness and failure behavior.

## Working practices

- Keep CubeMX `.ioc`, CubeIDE metadata and sources consistent so regeneration does
  not undo integration. Generated `Debug/*.mk` files are not the maintained source
  of build configuration.
- Use CubeMX user-code regions or separate application modules where appropriate.
- Preserve the existing demo as a reference before substantial restructuring;
  this workspace currently has no Git history.
- Do not silently remove the F*/EverParse properties by rewriting algorithms in C.
- Keep shared-buffer ownership explicit and mutable state serialized.
- Do not claim the STM32 firmware is fully verified or hardware-tested based on
  the host tests, cross-compilation or temporary link experiment.
- This handoff supplies context; it does not imply that firmware has already been
  deployed, that Ethernet works, or that the temporary probe is production-ready.

## Reference documentation

- STM32F767 datasheet:
  https://www.st.com/resource/en/datasheet/stm32f767zi.pdf
- ST NUCLEO-F767ZI UART example:
  https://github.com/STMicroelectronics/STM32CubeF7/blob/master/Projects/STM32F767ZI-Nucleo/Examples_MIX/UART/UART_HyperTerminal_IT/readme.txt
- lwIP threading rules:
  https://www.nongnu.org/lwip/2_1_x/multithreading.html
- KaRaMeL extraction model:
  https://github.com/FStarLang/karamel
