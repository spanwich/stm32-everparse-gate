# Core-port validation — 2026-09-10

The milestone-1 self-test firmware was built, programmed and run on the connected
NUCLEO-F767ZI. **Debug and Release each passed all 191 checks on the MCU.** The
final Debug image is left running. This is core validation with synthetic identity
and rate attributes; it does not establish Ethernet, TLS or authentication support.

## Observed results

| Check | Debug | Release |
| --- | ---: | ---: |
| Compiler errors / warnings | 0 / 0 | 0 / 0 |
| MCU self-test | 191 / 191 | 191 / 191 |
| Core stack unused at measured high-water point, of 8192 bytes | 6276 | 6640 |
| Diagnostics stack unused at measured high-water point, of 2048 bytes | 948 | 1012 |
| FreeRTOS heap free, bytes | 15352 | 15352 |
| FreeRTOS heap minimum free, bytes | 15336 | 15336 |
| Dropped log messages | 0 | 0 |
| GNU size `text`, bytes | 81768 | 60792 |
| GNU size `data`, bytes | 416 | 416 |
| GNU size `bss`, bytes | 51128 | 51120 |

Each accepted UART run starts with a fresh boot marker, reports SYSCLK/HCLK
96000000, UART3 115200 and FreeRTOS V10.2.0, and includes at least five post-test
PASS heartbeats with `margin=OK`. Prior-image serial output was excluded. Release
was captured after a separate reset of its programmed image. Debug's final run
was captured during its final program/verify/reset sequence.

GNU size categories include the inherited Ethernet descriptor sections in `data`
and the 4608-byte linker heap/stack reservation in `bss`; they are not a complete
runtime allocation budget. The new main-stack reservation is 4096 bytes, and the
libc minimum heap reservation is 512 bytes. FreeRTOS heap_4 is separately reserved
at 15360 bytes. A temporary one-byte startup allocation initializes heap_4 and
accounts for its 16-byte measured minimum-free decrement.

The initial all-static run reported zero heap counters because heap_4 had not
initialized yet. The maintained startup probe fixes that telemetry; the table
and retained final UART logs describe the corrected images.

The host build passed the same **191 checks**, including all **119 original
vectors**, under AddressSanitizer and UndefinedBehaviorSanitizer. Warnings are
errors, UBSan failures are fatal, and no sanitizer diagnostics were observed.
These checks cover incomplete/oversized/max-body input, malformed paths/methods,
identity clearing, policy/rate/role/scope decisions, invalid and valid updates,
inactive slots, truncated validator input and guarded single-use dispatch.

## Generated code and stack checks

The matching compiler was STM32 GCC 13.3.1
(`GNU Tools for STM32 13.3.rel1.20250523-0900`). Both builds use `-Os` for all
imported generated C; handwritten Debug code retains `-O0`.

Post-link checks found the expected strong fault handlers and no recursive calls
or unresolved indirect calls within linked extractor functions. A negative test
recompiled only `HTTP_Extract_Scan.c` with `-O0` and linked an isolated image while
leaving its copied compile recipe at `-Os`. The check rejected the actual linked
recursion with `recursive extractor call cycle at scan_loop`. That unsafe image
was never flashed. This demonstrates that the check inspects executable calls,
not just configuration text.

Known-frame call-chain sums from `.su` files and ELF call edges were:

| Entry | Debug bytes | Release bytes |
| --- | ---: | ---: |
| Core task | 1976 | 1472 |
| Diagnostics task | 1128 | 1024 |
| Extractor | 112 | 112 |
| Policy evaluation | 1200 | 1192 |

These sums omit unmeasured library/assembly/indirect-call and interrupt costs.
They are conservative over some alternative paths and incomplete over others;
they are not complete worst-case stack bounds. The task high-water measurements
cover the executed vectors. MSP high-water use and worst-case interrupt nesting
were not measured. Allocation/overflow/assert/CPU-fault handlers were compiled and
linked as strong functions, but fault injection was not performed. The optional
`GATEWAY_FAULT_INJECT` branches are untested hooks for future debugger exercises.

## Hardware and retained evidence

STM32CubeProgrammer v2.21.0 identified ST-LINK serial
`066FFF555567894967085545`, target device ID `0x451`, revision Z, Cortex-M7,
2 MiB flash and approximately 3.25 V. Connection under reset at requested 1000 kHz
(actual 950 kHz) succeeded after hot-plug connection failed. Both image downloads
reported successful verification. No option bytes, readout protection settings or
ST-LINK firmware were changed.

[Validation/2026-09-10](Validation/2026-09-10) contains the final host log, firmware
build log, fresh-boot UART logs, stack reports, negative recursion-check output,
and SHA-256 hashes of both tested ELFs and the original flash backup. The retained
Debug programmer log includes download/verification; the retained Release
programmer log records the separate reset used for its accepted UART capture.

The full pre-change workspace is preserved at:
`/tmp/policy-gate-core-kn_2uc2z/before.tar.gz`.
The board's original full 2 MiB flash image is:
`/tmp/policy-gate-core-kn_2uc2z/target-before.bin`.
These backups and the original capture script are outside the project and may
be removed by temporary-directory cleanup. The maintained test evidence is in
`Gateway/Validation`; the firmware ELF/map/disassembly outputs remain in Debug
and Release. Hashes identify the tested binaries if later builds replace them.

Generated algorithm hashes still match the original reference source. No fresh
F* proofs, extraction, credential protocol validation, networking tests, TLS
memory measurements, power-cycle tests or endurance testing were performed.
