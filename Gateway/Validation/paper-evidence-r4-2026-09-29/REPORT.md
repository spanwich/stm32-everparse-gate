# R4: MPU boundary, cost floor, real-time interference, availability

This report covers the dated R4 firmware variants. Every hardware capture
retains the board's raw serial output beside decoded data. These are measured
results on one NUCLEO-F767ZI, not WCET guarantees. The unmodified verified
extractor, original serializer and EverParse validator remain the reference
algorithm bodies. The new field serializer was proved and extracted separately.
The compact receipts and summaries are versioned; the roughly 494 MiB raw
ELFs, UART captures and per-sample/per-request CSVs remain in this local dated
directory and are deliberately omitted from the Git commit.

## Isolation boundary (R4.1)

The FreeRTOS ARM_CM7_MPU port boots with eight MPU regions. The privileged gate
task owns policy and validator buffers in the lower 48 KiB SRAM bank. The
unprivileged network-facing task copies complete HTTP requests through a
depth-one queue. A separately unprivileged application task receives another
bounded byte-copy job. The Ethernet descriptor and payload region is
`0x20070000..0x2007ffff`, outside gate and app memory. The full writer-by-asset
table, including trusted privileged tasks, DMA, queue wrappers and readable lab
keys, is in [R4_BOUNDARY.md](../../R4_BOUNDARY.md).

The primary 96 MHz MPU image `mpu96-app-final` (ELF SHA-256
`bb03f9d504f3d4db63296b8d33f9da7bd0dff29fd581955626efe08765371962`)
reported both network and app tasks unprivileged, passed 301/301 startup
self-tests, the 34-group HTTP network suite with 1,000 sequential requests, and
200/200 adversarial HTTP requests with zero oracle disagreement, fail-open or
effect-audit mismatch. Its serial logs and request records are retained under
`mpu96-app-final/` and `mpu96-nolog-close/`.

Five separate `fault-*-final-layout` images injected direct unprivileged
stores into policy, validator input and application input; a direct call to a
privileged function; and an attempt to raise privilege followed by a policy
store. All five ended in MemManage reason 6 before the intended operation
could return. Each has its own ELF hash, build, verified flash, raw UART and
SWD register log. The exact final-layout readbacks were:

| Probe | Injection | CFSR | Fault address / result |
|---|---|---:|---|
| 1 | Network → policy | `0x82` | `0x20002250` |
| 2 | Network → validator input between serialization/check | `0x82` | `0x20007234`; trigger request timed out, no response |
| 3 | Network → app input | `0x82` | `0x2000c048` |
| 4 | Network → privileged function | `0x01` | Instruction access violation |
| 5 | Network attempts privilege raise, then policy store | `0x82` | `0x20002250`; privilege was not raised |

The sixth `fault-6-app-to-gate` image tested app → policy and similarly
reported MemManage `CFSR=0x82`, address `0x20002250`. These stops establish
the tested direct-write/call boundary; no live handler response was observed
before the faults. Effect-counter readback was not instrumented in these
images, so zero effects is also supported by the injected source position
before dispatch, rather than an independent counter measurement.

**Boundary verdict:** the tested direct CPU-write cells are MPU-enforced.
Privileged TCP/IP, Ethernet and diagnostic code, ISRs, DMA descriptor setup,
FreeRTOS queue wrappers and the app's own input use remain trusted. This is
less isolation than seL4 capability mediation; it does not prove complete
mediation under compromised privileged code or a guessed queue handle.

## Availability (R4.5)

With per-request UART logging disabled and `conn->linger=2`, the observed
1,000-request soak stopped at request 16. The retained UART trace showed the
single gateway task in `netconn_close` (`phase=3`) with 16 accepts but only 15
closes, while diagnostics continued. lwIP's positive-linger close waits for
unacknowledged data; the blocking close path was the observed point of lost
progress. The gateway now uses `linger=-1`, so it does not enter that
positive-linger wait. With logging still disabled, the same board passed the
34-group network suite including 1,000 requests, another 1,000-request
`http.client` soak, and the 200-case attack corpus. The final primary image
`primary96-final` (ELF SHA-256
`baffd149cbaead067bfc907701ee1ea73fae1e8daf78529a29c7f3746cbbd90d`)
passed 301/301 startup self-tests, the 34-group network suite with 1,000
sequential requests, the 200-case attacks with zero disagreements/fail-open/
audit mismatches, and a separate 5,000/5,000 `http.client` soak with no
per-request UART logging. In the 5,000-request soak, median/p99/max host
response latency was 16.076/16.738/17.208 ms. A 216 MHz, cached V1 image
also passed 1,000/1,000 live requests. The exact reason its positive-linger
wait did not complete is not established from these traces; the earlier
600/1,000 stall is consistent with this failure mode but was not reproduced
on its exact historical ELF.

## Cost floor (R4.2)

Each completed DWT variant below has five fresh boots and 10,000 samples per
case for seven cases at every measured stage; its `dwt/summary.json` and raw
`boot-*.cycles.csv` and `boot-*.uart.bin` are retained. These primary captures
left interrupts enabled. Clock/cache/optimisation differ as labelled; the
primary Debug image uses `-Os` for generated C and the pre-existing Debug
setting for handwritten code. V2 builds all code with `-O2`.

| Variant | Clock/cache | First-rule validator median | Original serializer median | Proved field serializer median | Full in-task request median |
|---|---|---:|---:|---:|---:|
| V0 `v0-96-off-os-field` | 96 MHz, caches off | 2,272 cycles | 15,045 | 907 | 161,324 |
| V1 `v1-216-cache-os-fixed` | 216 MHz, caches on | 1,232 | 8,647 | 872 | 129,490 |
| V2 `v2-216-cache-o2` | 216 MHz, caches on | 764 | 5,202 | 822 | 94,306.5 |

Against R1's 96 MHz, five-boot no-MPU image, first-rule validator median rose
from 2,191 to 2,272 cycles (+3.7%) and serializer+validator from 16,979 to
17,240 (+1.5%). The measured full in-task HTTP path rose from 114,392 to
161,324 cycles (+41.0%). That larger difference is **not** an isolated MPU
cost: R4 also split network/gate/app ownership and changed the adapter path.
The extractor median fell from 11,327 to 8,831 cycles, illustrating that
build/layout effects also changed between images. The exact R1 distributions
are in `../paper-evidence-r1-2026-09-29/m2/five-boots/summary.json`.

The stage-7 board experiment checks all 106 output bytes against the original
serializer before sampling. `Mediation.Field.fst` also has a fresh F*/KaRaMeL
proof/extraction receipt that its output equals `Mediation.Format.expected`
for all access envelopes under the stated buffer preconditions. The runtime
gateway still calls the original serializer: stage 7 is a labelled research
variant, not a deployed substitution. The field design improves the V0
serializer median by 16.6× in the same image.

Static disassembly of `RbacPolicyValidateAccessRequest` finds 134/1,351
instructions matching 64-bit load/store or carry-chain signatures in V0/V1
(9.9%), and 141/1,061 in V2 (13.3%). The generated source has 231 `uint64_t`
uses; the signatures are a static instruction footprint, **not** an executed
cycle share. The intra-function control-flow analysis found no reachable
cycle, recursion or unknown transfer; its longest static path estimate is
662 instructions in V0/V1 and 658 in V2, excluding callees and memory timing.
Neither this estimate nor observed DWT maxima establishes WCET.

The first V1 cached boot faulted at scheduler entry because D-cache was
enabled before the MPU map had been installed. The corrected V1 enables it
after `prvSetupMPU`; the failed ELF and SWD registers are retained in
`v1-216-cache-os/`. ETH SRAM remains non-cacheable in the corrected variant.

## Real-time interference (R4.3)

The V0 interrupts-masked image `v0-96-off-os-field-masked` completed five
boots with the same 10,000 samples per case. Across all 50,000 first-rule
samples, the validator ranged from 2,274 to 2,276 cycles (max/min 1.0009);
the last-rule case ranged from 2,298 to 2,300 (1.0009). The first-rule
serializer+validator ranged from 17,225 to 17,232 (1.0004), extractor from
8,808 to 8,828 (1.0023), original serializer from 14,977 to 15,139
(1.0108), field serializer from 900 to 961 (1.0678), and full in-task
processing from 174,543 to 174,558 cycles (1.0001). The handwritten
baseline ranged from 270 to 438 cycles (1.6222); the source's simple loop
does not itself explain the entire microarchitectural spread. Exact minima,
maxima and ratios for all seven cases at every stage are in the JSON and raw
CSVs. The seven cases exercise two allow-rule positions and five deny reasons,
not every possible policy or microarchitectural state.

The [72-row control matrix](control-matrix.csv) covers V0/V1/V2, all three
frequencies, both priorities and all four load classes. Every selected run
retains 10,000 individual DWT samples, exact jitter percentiles, a request
CSV, raw UART, runtime counters and an image manifest: **720,000 retained
release-to-run samples**. The table below shows the valid-request flood; the
CSV/JSON retain idle, denied and malformed results. Rates are single-client
sequential completed HTTP requests during the timer window, so they are
observed lower bounds on sustainable throughput, not a capacity search.

| Variant | Control rate / priority | Valid requests/s | Deadline misses / 10,000 | p99 / max release-to-run | Longest measured task critical section |
|---|---|---:|---:|---:|---:|
| V0 | 1 kHz above | 89.0 | 0 | 466 / 515 µs | 98 µs |
| V0 | 1 kHz below | 91.0 | 4,709 | 6,019 / 9,788 µs | 98 µs |
| V0 | 4 kHz above / below | 72.0 / 84.0 | 1,439 / 7,931 | 603 / 947 µs above | 98 µs |
| V0 | 10 kHz above / below | 38.0 / 70.0 | 1,621 / 8,946 | 570 / 958 µs above | 98 µs |
| V1 | 1 kHz above / below | 288.5 / 290.8 | 0 / 109 | 146 / 246 µs above | 43 µs |
| V1 | 4 kHz above / below | 285.2 / 286.0 | 3 / 5,953 | 171 / 264 µs above | 43 µs |
| V1 | 10 kHz above / below | 257.0 / 286.0 | 1,663 / 8,119 | 214 / 272 µs above | 43 µs |
| V2 | 1 kHz above / below | 469.1 / 457.1 | 0 / 0 | 11 / 96 µs above | 40 µs |
| V2 | 4 kHz above / below | 419.2 / 437.2 | 0 / 3,546 | 94 / 117 µs above | 40 µs |
| V2 | 10 kHz above / below | 385.0 / 419.0 | 219 / 6,058 | 118 / 134 µs above | 40 µs |

The task shares in the CSV are FreeRTOS runtime-counter deltas across the
sample window. At V1 1 kHz above-gate valid load, the gate task used 20.2%,
TCP/IP 43.6% and Ethernet input 8.1% of measured task cycles. The isolated
serializer+validator median (9,806 cycles) multiplied by the observed 288.5
requests/s is about 1.31% of a 216 MHz core; this is an estimate of decision
share, not a directly profiled task counter. The gate task also parses HTTP,
authenticates, copies and dispatches. The generated gate itself does not call
`taskENTER_CRITICAL`, but FreeRTOS queue operations and network code do; the
reported longest `vPortEnterCritical` interval is system-wide and does not
cover all ISR mask primitives. At V0 it approaches one entire 10 kHz period.

One V1 cached, 1 kHz below-gate valid-load boot faulted after 236 releases
and about three requests. The saved SWD record reports HardFault reason 5,
`CFSR=0x8200` (precise bus fault with valid BFAR) and `BFAR=0x7e792384`.
Two subsequent identical-image valid-load boots completed, with 894 and 109
misses; the table selects the latter and retains all three records. This is a
real intermittent failure of the cached research variant, and its root cause
is unresolved. It does not affect the primary 96 MHz cache-off final image.

A TIM7 interrupt releases the control task at 1, 4 or 10 kHz, above or below
the privileged gate task. A deadline miss means release-to-run latency at
least one period; this deliberately omits control-task execution time, so it
is a weaker test than release-to-completion. Each scenario lasts 10 s, 2.5 s
or 1 s respectively. The positive-linger fix is present in every matrix image.

## Application fit (R4.4)

IEC 61850-5:2013+A1:2022 defines Type 1A
trip transfer classes of 3 ms (P1) and 10 ms (P2), Type 1B P3 of 20 ms,
operator action Type 3 of 500/1,000 ms, and Type 4 Sampled Values P7/P8 of
3/10 ms in its [official excerpt](https://www.normsplash.com/Samples/IEC/171656784/IEC-61850-5-2013-AMD1-2022-CSV-en-2.pdf).
Its Type 6 access-controlled operator command class P10 allows 500 ms; this
is an **analogy** for HTTP management, not an HTTP standard deadline. The
[Modbus Messaging Implementation Guide](https://www.modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf)
does not set a universal response-time requirement. This firmware only
implements HTTP; no Modbus, GOOSE or Sampled Values protocol path has been
implemented or timed. The table separates timing feasibility from protocol
support and uses the largest observed primary masked full-request cost
(174,558 cycles = 1.82 ms at 96 MHz) only for the implemented HTTP path.

| Application class | Source budget or period | Measured comparison and interference | Verdict for this firmware |
|---|---|---|---|
| HTTP management | No universal HTTP deadline; IEC P10 500 ms is an operator-command analogy | Primary final 5,000/5,000 responses; median/p99/max 16.076/16.738/17.208 ms; 1 kHz above-gate V0 zero misses at 89 requests/s | **Supported** for measured best-effort management traffic; no hard deadline guarantee |
| MODBUS/TCP authorization | Modbus leaves transaction response time application-specific | No Modbus parser or endpoint measured | **Not supported** |
| IEC 61850 GOOSE in-line | Type 1A P1 ≤3 ms, P2 ≤10 ms; Type 1B P3 ≤20 ms | No GOOSE path; V0 HTTP processing alone reached 1.82 ms with interrupts masked, excluding Ethernet and GOOSE work | **Not supported** |
| IEC 61850 Sampled Values | Type 4 P7 ≤3 ms, P8 ≤10 ms, with continuous streams | No Sampled Values path; 10 kHz shared-control tests missed deadlines under load | **Not supported** |
| Shared 1 kHz control loop | 1 ms period | V0 above-gate valid load: 0/10,000 misses, max 515 µs; V0 below-gate: 4,709 misses | **Supported** only for the tested above-gate priority/load setting |
| Shared 4 kHz control loop | 250 µs period | V0 and V1 miss under valid load; V2 above-gate 0/10,000, max 117 µs, but cached variant is research-only | **Not supported** by the primary configuration |
| Shared 10 kHz control loop | 100 µs period | Even V2 above-gate valid load misses 219/10,000 | **Not supported** |

## Hypothesis verdicts

| Hypothesis | R4 verdict | Practical meaning |
|---|---|---|
| H1 fit/no decision allocation | **Supported within tested scope** | Final Debug text/data/bss is 226,144/120/246,456 bytes; static queues and task stacks fit. The original decision code and R1 zero-allocation evidence carry forward; final attack instrumentation reports zero decision allocations but its allocation counter was unavailable, so this image alone does not re-prove that counter claim. |
| H2 bounded cheap decision and spare real-time CPU | **Partial** | Fixed eight-slot path and tight masked observations support bounded structure, but there is no WCET proof; 4/10 kHz deadlines fail in most configurations and V1 cached control faulted. |
| H3 complete mediation by construction | **Partial** | Normal network→gate→app byte-copy flow and R1 effect audit support the intended path. This FreeRTOS port has no per-task queue-handle ACL, and a full post-link indirect-call/effect audit was not redone after task splitting. |
| H4 memory integrity without seL4 | **Partial** | Tested unprivileged direct stores fault. Privileged TCP/IP/ETH/diagnostics, ISRs, DMA configuration, queue wrappers and the app's own input remain trusted. |
| H5 device decisions match oracle/fail closed | **Supported for tested corpus** | Final image passed 301/301 self-tests, including the 12,527-case reference corpus, 34 HTTP groups and 200 attacks with zero disagreements, fail-open or effect-audit mismatches. |

## Evidence classification

| Claim | Status and boundary |
|---|---|
| Field-serializer byte equality and frame | Proved by fresh F*/KaRaMeL check under stated Low* preconditions. |
| Original EverParse/F* mediation behavior | Generated algorithms unchanged; existing proofs and R1 oracle campaign carried forward. |
| MPU region integrity | Tested by selected fault injections and linker/address audit; trusted privileged code and DMA configuration remain. |
| Functional agreement | On-board startup, HTTP and 200-case attack tests; R1's 12,527-case and 100,000-effect audit are prior evidence, not repeated on every R4 image. |
| Decision time and deadlines | Observed DWT samples on one board; no WCET method. |
| Positive-linger stall mechanism | Observed close-path stall and successful `linger=-1` intervention; precise lwIP wait condition remains an inference. |
