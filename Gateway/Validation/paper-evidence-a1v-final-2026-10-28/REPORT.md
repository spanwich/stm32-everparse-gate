# A1v primary image: functional and network evidence (2026-10-28)

The paper's F767 baseline is A1v: `memcpy`/`memset` on the Low*-verified loops,
32-byte aligned (`d712980`, `d5acc61`; timing evidence in
`paper-evidence-timing-2026-10-21/REPORT.md` §4). This directory repeats the
Phase A functional and network evidence of the A0 primary image
`v11-verified-gate-final2` (`paper-evidence-d1-blob-2026-10-11`) on an A1v
primary image.

**Image.**
- Source: `a4fbff0` (`research/verified-mediation`), which makes
  `GATEWAY_FAST_MEMOPS = 1` the default in `Gateway/Inc/paper_experiment.h`.
  The tree was clean, and the image was built with default flags.
- It contains the PA0 target-reset feature (`a2a34a8`), as every A1v evidence
  image does.
- Configuration: 96 MHz, caches off, Debug board image, generated C at `-Os`.

**How it was run.**
- The Phase A commands of the 2026-10-11 `COMMANDS.md`, in the same order and
  with the same arguments.
- Tools ran from a scratch copy of `Gateway/tools` whose only changes are paths
  (`provenance/tool-path-rewrite.diff`, 30 files, the same rewrite as 2026-10-11).
  Nothing was written into older evidence directories.
- Exact commands: `COMMANDS.md`. Per-stage times and exit codes:
  `run-status.log`. Machine summary of both images: `summary.json`.
  Hashes: `SHA256SUMS`.
- Skipped as instructed: the gdb update-cost measurement, and Phase B (variants,
  probes, control matrix). The timing, control-matrix and isolation-probe
  evidence for A1v is in the timing report §4.

**Constraints.**
- The F767 was reached only through `/dev/serial/by-id/...STLink_066FFF555567894967085545-if02`
  (`ttyACM2`) and its ST-LINK. `/dev/ttyACM0` (STM32MP255) was not touched.
- Every serial reader opened the port read-only. Nothing was sent over the
  serial port: the captures contain no `[TRESET]` lines.
- Host network unchanged (board `192.168.40.128` via `enp44s0`). The only
  network traffic was what these tools send.

**Final state.** The board was left running the A1v primary image; a 4 s
read-only capture after the run shows the heartbeat continuing with no reboot.

| ELF | SHA-256 |
|---|---|
| A1v primary, Debug (flashed, tested) | `8dcac2d65eaaab0f912659a7ad7f5fc55e04b804ad1b28da301c4fa4b0f8710a` |
| A1v primary, Release (built, not flashed) | `581827dc4faf5b4ebc110289868c2817fb5eacf422fad69f1c31428409e16798` |
| A0 reference at `a4fbff0`, Debug / Release (host build only, never flashed; used to split the differences below) | `a80c393c…d806` / `be2accdd…a2ee` |
| final2 (A0, `76879e2`), Debug | `931f9b7b9ae1fb1b43331dadabf6c5423fbffca9383bb61b976dea0971b8a600` |

Rebuilding the default image after the run reproduced both A1v ELFs byte for
byte (`run-status.log`, 15:22:13).

## Stage times (2026-10-28, +13:00)

| Stage | Start | End | Result |
|---|---|---|---|
| preflight (`provenance/preflight.txt`) | 14:46:13 | | tree clean at `a4fbff0` |
| build (`build_firmware.py`) | 14:47:19 | 14:47:37 | rc 0; Debug and Release, 0 warnings, post-link checks pass |
| stage (`d1_stage_variant.py`) | 14:47:37 | 14:47:37 | rc 0 |
| board_test (flash, 301 self-tests) | 14:47:37 | 14:48:15 | rc 0 |
| network-suite (`test_network --count 200`, UART capture) | 14:48:15 | 14:48:26 | rc 0 |
| live_policy-suite | 14:48:26 | 14:48:27 | rc 0 |
| dashboard-suite | 14:48:27 | 14:48:29 | rc 0 |
| attacks-r1 | 14:48:29 | 14:48:37 | rc 0 |
| soak 5000 | 14:48:37 | 14:50:02 | rc 0 |
| e-p1-audit-100000 (load + `d1_hang_watch`) | 14:50:02 | 15:19:31 | rc 0 / rc 0 |
| socket-check-after-audit (30 s) | 15:19:31 | 15:20:05 | rc 0 |
| `d1_privileged_inventory.py` | 15:20:05 | 15:20:06 | rc 0 |
| A0 reference build + A1v rebuild (host only) | 15:21:49 | 15:22:13 | rc 0 / rc 0 |

## Results: final2 (A0) vs A1v

Δ marks a difference. Every Δ is explained in the next section (item numbers
in brackets).

| Metric | final2 (A0), 2026-10-11 | A1v, 2026-10-28 | |
|---|---|---|---|
| Startup self-tests | 301/301 | 301/301 | = |
| `[PAPER CORPUS]` line | `comparisons=12527 failures=0` | `comparisons=12527 failures=0` | = |
| Network suite (`test_network --count 200`) | 34/34, 0 FAIL, suite rc 0 | 34/34, 0 FAIL, suite rc 0 | = |
| … its 200 sequential mixed requests | 3.340 s | 3.173 s | Δ −5.0 % [5] |
| … UART during the suite | 0 faults, 0 `[TRESET]` | 0 faults, 0 `[TRESET]` | = |
| Live policy | 43/43 (`Live policy acceptance PASS 43`) | 43/43 | = |
| Dashboard | 129/129 | 129/129 | = |
| … 100 authenticated requests | 1.938 s | 1.832 s | Δ −5.5 % [5] |
| Attacks R1: requests / disagreements / **fail-open** / audit mismatches | 200 / 0 / **0** / 0 | 200 / 0 / **0** / 0 | = |
| … policy preserved / restored; corpus SHA-256 | yes / yes; `75cd5910…` | yes / yes; `75cd5910…` | = |
| Soak 5,000 (`r4_http_client_soak`): OK / errors | 5,000 / 0 | 5,000 / 0 | = |
| … median / p99 / max (min) ms | 18.00 / 19.01 / 19.36 (13.03) | 16.91 / 17.90 / 18.75 (12.01) | Δ −1.10 / −1.11 / −0.61 ms [5] |
| Audit E-P1, 100,000 requests: completed / matched / unmatched / transport errors | 100,000 / 100,000 / 0 / 0 | 100,000 / 100,000 / 0 / 0 | = |
| … **protected effects vs acceptances** | **59,901 = 59,901** | **59,901 = 59,901** | = |
| … rows with `x-pg-audit-violations` ≠ 0; unique audit IDs; concurrent pairs | 0; 100,000; 99 | 0; 100,000; 99 | = |
| … policy restored; hang watch | yes; no hang, 0 STALE, 105,872 firmware requests | yes; no hang, 0 STALE, 105,872 | = |
| … elapsed | 1,868.7 s | 1,769.2 s | Δ −5.3 % [5] |
| Socket check after the audit (30 s) | 29 probes, all `403`; NETCONN err 0, ≤ 1/32 used; TCP_PCB err 0, 12/12 used (all TIME_WAIT), 0 active | identical | = |
| **Privileged tasks** | **9** | **10** | Δ +1 [2] |
| **Interrupt handlers (vector-table ISR roots)** | **12** | **13** | Δ +1 [2] |
| **Unresolved register-indirect call sites** | **81** | **85** | Δ +4 [2] |
| **Privileged code (union of closures)** | 633 functions, **132,414 B** | 655 functions, **135,950 B** | Δ +22, +3,536 B [2] |
| Kernel privileged-functions section | 65,536 B | 65,536 B | = |
| `.privileged_data` | 120,952 B | 123,104 B | Δ +2,152 B [3] |
| Release text / data / bss | 209,272 / 400 / 339,720 | 211,820 / 400 / 341,872 | Δ +2,548 / 0 / +2,152 [3] |
| Debug text / data / bss | 268,796 / 400 / 329,176 | 273,536 / 400 / 331,328 | Δ +4,740 / 0 / +2,152 [3] |
| Heartbeat after boot: core/diag stack free; heap free (min) | 3,448 / 812; 65,048 (64,960) | 3,448 / 812; 65,040 (64,952) | Δ heap −8 B [4] |
| Ethernet RX task stack free: boot window / after suite / after audit | 3,832 / 3,756 / 3,756 | 3,772 / 3,756 / 3,752 | Δ [6] |
| TCP/IP and link task stack free (after audit) | 5,296 / 1,884 | 5,296 / 1,884 | = |
| After audit: heap min; `log_drops`; lwIP heap peak / errors | 64,664; 4; 6,160 / 0 | 64,656; 3; 6,160 / 0 | Δ [4], [7] |
| Frame counters (`[NET] rx/tx`) at end of capture | network suite 256/178, audit 640,051/438,007 | 261/166, 641,686/436,700 | Δ [8] |

## Differences explained

**1. New image.** final2 is `76879e2`. This image is `a4fbff0`, which adds:
- the PA0 target reset (`a2a34a8`);
- the verified memops (`d712980`, `d5acc61`), now on by default;
- several flag-gated experiments, all off by default (`7d24cf3`, `2782477`,
  `932617f`, `7e5ccd4`, `e223750`).

The A0 reference build at `a4fbff0` (memops off) differs from final2 only in
PA0's symbols, in both configurations. So the flag-gated commits leave the
default image unchanged.

`a2a34a8` also rewrote four Core files (`main.c`, `main.h`, `stm32f7xx_it.c`,
`stm32f7xx_hal_msp.c`) from CRLF to LF. Ignoring line endings, the diff is the
45 lines of PA0 code. This has no effect on the code: the symbols are
identical.

**2. Privileged inventory.**

| | final2 | A0 at `a4fbff0` (= final2 + PA0) | A1v (+ verified memops) |
|---|---|---|---|
| Privileged tasks | 9 | 10 | 10 |
| ISRs | 12 | 13 | 13 |
| Indirect call sites | 81 | 85 | 85 |
| Functions / code bytes | 633 / 132,414 | 650 / 135,694 | 655 / 135,950 |

`inventory-diff.json` has the function-level difference.

*What PA0 adds:*
- **Task:** `run_target_reset`. The tool's task count comes from its list of
  `portPRIVILEGE_BIT` creation sites, which `a2a34a8` extended.
- **ISR:** `USART3_IRQHandler`, read from the vector table. In final2 that slot
  was the startup file's weak alias of the default handler, which neither
  inventory counts as a root.
- **Indirect call sites:** all 4 new ones are in the vendor
  `HAL_UART_IRQHandler`: `huart->RxISR` (×2), `huart->TxISR` and
  `hdmarx->XferAbortCallback`. HAL callback registration is off
  (`USE_HAL_UART_REGISTER_CALLBACKS 0`), so the callbacks themselves are direct
  calls.
- **Code:** 17 functions, +3,280 B, mostly the HAL UART interrupt/receive path,
  `HAL_DMA_Abort`/`HAL_DMA_Abort_IT`, `MPU_xQueueGenericReset` and the module's
  own code.

*What the verified memops add:* 0 tasks, 0 ISRs and 0 indirect sites. They add
the five `Memops_Low_*` loops (+164 B), and the shim `memcpy`/`memset` grows
from 28/16 B (newlib-nano) to 68/68 B. Total +5 functions, +256 B.

*For the paper* (it currently says 9 / 12 / 81): **the A1v primary image has 10
privileged tasks and 13 interrupt handlers, with 85 unresolved
register-indirect call sites (655 functions, 135,950 B of privileged code).**
All +1/+1/+4 come from the PA0 serial reset. Without PA0, A1v would be 9 / 12 / 81
with 638 functions and 132,670 B. That figure is derived (final2 plus the
memops' functions); no such image was built. The inventory method is unchanged: direct-branch
closures only, indirect targets listed but not resolved.

**3. Size.** final2 → A0 at `a4fbff0` → A1v:

| | PA0 | Verified memops |
|---|---|---|
| Release text | +2,184 B | +364 B |
| Debug text | +4,336 B | +404 B |
| rodata | +148 B Debug / +132 B Release (PA0's strings), included in text above | +0 B |
| bss | +2,152 B: the PA0 objects in `.privileged_data` (2,153 B by symbol: 1,024 B stack, 1,008 B TCB, 80 + 32 B queue, 9 B variables) | +0 B |

- **Memops text:** named code is 256 B Debug / 244 B Release; the remainder is
  padding from the 32-byte function alignment.
- **Comparison with the timing report:** §4.3 there quotes +376 B for A1v over
  A0, measured on its timing images. The primary Release image here gives
  +364 B.

**4. FreeRTOS heap 8 B smaller.** PA0's 2,153 B of privileged objects are
linked before `ucHeap`. That moves `ucHeap` from `0x2000d858` (8-aligned) to
`0x2000e0c4` (4 mod 8). heap_4 aligns the start of the heap up, which costs one
8-byte block. The difference is there before any allocation: free is 65,528 vs
65,520 at the first heartbeat. It stays exactly 8 B in heap free and heap
minimum throughout. It is a constant offset, not a leak.

**5. About 5–6 % faster per request.** Four independent host-side measures moved
the same way by similar amounts:

| Measure | final2 | A1v | Change |
|---|---|---|---|
| Soak median (min) | 18.00 (13.03) ms | 16.91 (12.01) ms | −1.10 (−1.02) ms |
| Network suite, 200 sequential requests | 3.340 s | 3.173 s | −5.0 % |
| Dashboard, 100 authenticated requests | 1.938 s | 1.832 s | −5.5 % |
| Audit, 100,000 requests | 1,868.7 s | 1,769.2 s | −99.5 s (−1.0 ms per request) |

- **Why it is attributed to A1v's `memcpy`/`memset`:** PA0 code does not run
  during the measurements. Nothing was sent, so its receive interrupt never
  fired, and its task stays blocked.
- **Consistency with the timing report:** about 1 ms is about 96k cycles at
  96 MHz. That equals the saving of roughly ten of the ~1.5 KB queue copies
  measured in §4.2 there (copy critical section 13.1–13.7k → ~4k cycles).
- **What was not measured:** that breakdown per request, and A0 at `a4fbff0` on
  the board. Host conditions on the two dates were not controlled.
- **Not timing evidence:** these are host-measured wall-clock figures. The
  paper's timing claims stay with the timing report.

**6. Ethernet RX task stack.**
- **Boot window:** 3,832 vs 3,772 B free. During its 25 s boot capture, A1v's
  board received 20 frames from the LAN and final2's received 0 (`[NET] rx`). So
  only A1v ran its receive path during that window.
- **End of the network suite:** both 3,756 B.
- **After the audit:** 3,756 vs 3,752 B, so 4 B deeper on A1v. A plausible
  cause: A1v's `memcpy` calls the verified loops, while newlib's is a leaf. This
  is not shown directly.
- The margin stays OK (≥ 1,024 B). The other task stacks are identical.

**7. `log_drops` 4 vs 3** after the audit. A log line is counted as dropped
when the log queue, log mutex or UART transmit times out (100 ms / 1 s), or
when the line is truncated. Under load these timeouts depend on timing, so the
count does too. No result depends on log lines; the audit uses HTTP headers.

**8. Frame counters.**
- The network-suite figure is the last 1 s `[NET]` snapshot before the capture
  stopped, not an end-of-test total.
- The audit's Ethernet frame counts depend on how the host's TCP stack spaces
  its acknowledgements.
- Request counts agree: 104,871 in the last `[NET]` line and 105,872 in the
  hang watch, on both images.

## Not done / notes

- **Not rerun, as instructed:** the gdb update-cost measurement and all of
  Phase B (OPNsense/SCALANCE gate-cycle variants, monolithic and `a578eb5`
  builds, isolation probes, control matrix). The A1v timing, control and probe
  results are in the timing report §4.
- **Not rerun, as on 2026-10-11:** the host 1M-envelope equivalence test.
- **A0 reference image:** built only to attribute the differences above. It was
  never flashed, so no runtime result here separates PA0 from the memops.
- **Tool copy:** it lived in this session's scratch directory, like
  `/tmp/pgtools` on 2026-10-11. `provenance/rewrite_tools.py` and
  `provenance/tool-path-rewrite.diff` recreate it exactly from `a4fbff0`.
- **Build side effect:** the build rewrote `.settings/language.settings.xml`.
  It was restored after each build and is not part of any image.
