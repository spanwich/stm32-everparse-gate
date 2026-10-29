# opn64 experiment: control task beside the 64-partition gate with the OPNsense policy live (2026-10-30)

Branch `glue/opn64-primary` (local, not pushed). Images: A1v norank control images built on the n=64 primary
(`../opn64-timing-2026-10-29/a1v-norank-control-<hz>-bucket<b>`), 96 MHz, caches off, 354 self-tests, Debug.
**Rate window = 500 ms (`GATEWAY_RATE_WINDOW_MS`), N_max = 50 (at most 49 admitted per window).** Live decision path: wire check,
rate test (refusal costs no scan), then `GateLowGateDecide` over 64 partitions. OPNsense 19.1.7 (420 rules, 53 partitions) is
installed into partitions 2..54 at run time by 53 `PUT /api/policy?part=J` requests through the verified update gate; partition 1 =
gateway routes (operator /api/status allowed). "Worst-case deny" = an authenticated operator `GET /api/policy`: it matches the
path in partition 1 but fails the role check, then misses in every other partition, so each decision scans all 512 slots.
Control window = 10,000 releases per capture. Tool: `Gateway/tools/opn64_control_capture.py`; driver `run_opn64_experiment.sh`.

## Provisioning time
53 PUT requests (420 rules / 424 slots) through the verified update gate: **1.054-1.057 s** over 4 distinct
measurements (every capture re-provisions after a reset; all 53 requests returned 200).

## 1. Deadline matrix with the OPNsense policy live (network clients, as fast as the client can)
| control | bucket | scenario | misses | max latency (cycles) | req/s in window | 200 / 403 / 429 / conn-err |
|---|---|---|---|---|---|---|
| 1000 Hz | 0 | idle | 0 | 6425 | 0.0 | 0 / 0 / 0 / 0 |
| 1000 Hz | 0 | valid (early match) | 0 | 11308 | 55.2 | 819 / 0 / 0 / 0 |
| 1000 Hz | 0 | worst-case deny, 1 client | 0 | 12035 | 60.4 | 0 / 897 / 0 / 0 |
| 1000 Hz | 0 | worst-case deny, 4 clients unpaced | 0 | 10963 | 59.4 | 0 / 882 / 0 / 9 |
| 1000 Hz | 1 | idle | 0 | 4176 | 0.0 | 0 / 0 / 0 / 0 |
| 1000 Hz | 1 | valid (early match) | 0 | 11929 | 55.3 | 819 / 0 / 0 / 0 |
| 1000 Hz | 1 | worst-case deny, 1 client | 0 | 10409 | 60.3 | 0 / 893 / 0 / 0 |
| 1000 Hz | 1 | worst-case deny, 4 clients unpaced | 0 | 12073 | 60.6 | 0 / 891 / 0 / 9 |
| 4000 Hz | 0 | idle | 0 | 6322 | 0.0 | 0 / 0 / 0 / 0 |
| 4000 Hz | 0 | valid (early match) | 0 | 9238 | 44.4 | 378 / 0 / 0 / 0 |
| 4000 Hz | 0 | worst-case deny, 1 client | 0 | 10719 | 48.4 | 0 / 413 / 0 / 0 |
| 4000 Hz | 0 | worst-case deny, 4 clients unpaced | 0 | 9686 | 44.4 | 0 / 376 / 0 / 5 |
| 4000 Hz | 1 | idle | 0 | 6327 | 0.0 | 0 / 0 / 0 / 0 |
| 4000 Hz | 1 | valid (early match) | 0 | 10056 | 44.0 | 376 / 0 / 0 / 0 |
| 4000 Hz | 1 | worst-case deny, 1 client | 0 | 9459 | 48.0 | 0 / 411 / 0 / 0 |
| 4000 Hz | 1 | worst-case deny, 4 clients unpaced | 0 | 9743 | 47.6 | 0 / 409 / 0 / 5 |
| 10000 Hz | 0 | idle | 0 | 6162 | 0.0 | 0 / 0 / 0 / 0 |
| 10000 Hz | 0 | valid (early match) | 0 | 8729 | 22.0 | 289 / 0 / 0 / 0 |
| 10000 Hz | 0 | worst-case deny, 1 client | 0 | 8807 | 24.0 | 0 / 317 / 0 / 0 |
| 10000 Hz | 0 | worst-case deny, 4 clients unpaced | 0 | 7791 | 25.0 | 0 / 317 / 0 / 4 |
| 10000 Hz | 1 | idle | 0 | 6784 | 0.0 | 0 / 0 / 0 / 0 |
| 10000 Hz | 1 | valid (early match) | 0 | 7840 | 23.0 | 289 / 0 / 0 / 0 |
| 10000 Hz | 1 | worst-case deny, 1 client | 1 | 10663 | 24.0 | 0 / 315 / 0 / 0 |
| 10000 Hz | 1 | worst-case deny, 4 clients unpaced | 0 | 8154 | 25.0 | 0 / 301 / 0 / 6 |

Control misses (late + collapsed releases): 0 in every run except one late release at 10 kHz bucket 1 `wcdeny` (1 of 10,000).
No 429 appeared anywhere. Multi-client runs show a few connection errors (status 0): the listener serves one connection at a time.
Request rate in the window falls with the control rate (about 60 req/s at 1 kHz, 48 at 4 kHz, 24 at 10 kHz): the control task
at 10 kHz consumes the CPU the network path would use.

## 2. Paced sweep (worst-case deny, 2 clients, 1 kHz bucket 1; one 10 s control window = 20 rate windows per step)
| target req/s (2 clients) | achieved in control window | admitted | refused (429) | conn-errors | misses | max latency |
|---|---|---|---|---|---|---|
| 50 | 50.0 | 723 | 0 | 1 | 0 | 7647 |
| 80 | 59.2 | 806 | 0 | 2 | 0 | 11695 |
| 90 | 57.8 | 781 | 0 | 0 | 0 | 10148 |
| 95 | 56.9 | 831 | 0 | 2 | 0 | 10391 |
| 98 | 58.2 | 804 | 0 | 1 | 0 | 11482 |
| 100 | 60.4 | 879 | 0 | 2 | 0 | 11974 |
| 110 | 57.9 | 848 | 0 | 1 | 0 | 10281 |
| 150 | 60.5 | 894 | 0 | 2 | 0 | 12066 |

**Result: transport-limited at about 60 req/s.** The achieved rate saturates near 60 req/s (it never reaches the 98 req/s at which
the counter engages), no request was refused (0 x 429 in every step and every other capture), and control misses stayed 0.
The highest rate with zero refusals is therefore the transport ceiling, ~60 req/s sustained; the refusal fraction above it is 0
because it cannot be exceeded over the network. The rate counter's engagement is shown on board (section 3) and by the
synthetic-clock self-test (50th-69th request in a window refused), not by network traffic.

## 3. On-board flood (counter engaged, no network): measured CPU bound
Labelled build flag `GATEWAY_PAPER_FLOOD` (off in the primary): a privileged, lowest-priority task calls the same
`gateway_glue_set_identity` + `gateway_glue_mediate` path with worst-case-deny requests as fast as it can (25k+ requests/s), beside
the control task, after the boot self-tests finish, with OPNsense in partitions 2..54. Per rate-counter window it logs requests
scanned, refused, and DWT cycles inside scans and refusals. Clean windows are exactly 500 ms (the window the counter holds); windows
disturbed by the control task's UART record dump are excluded (1 per run).
| control | clean 500 ms windows | scanned per window | refused per window (mean) | cycles per scanned request (wall) | cycles per refusal | CPU share of scans, mean / max | scans + refusals, mean / max | control misses | control max latency |
|---|---|---|---|---|---|---|---|---|---|
| 1000 Hz | 27 (of 28) | 49..49 | 12492 | 191943 | 515 | 19.59 % / 20.07 % | 33.0 % / 33.87 % | 0 | 3699 |
| 4000 Hz | 12 (of 13) | 49..49 | 11255 | 205489 | 561 | 20.98 % / 25.82 % | 33.82 % / 38.44 % | 0 | 5999 |
| 10000 Hz | 9 (of 10) | 49..49 | 10784 | 227120 | 659 | 23.19 % / 59.82 % | 35.36 % / 65.79 % | 0 | 6433 |

- **Exactly 49 requests were admitted (scanned) in every clean 500 ms window** (min = max = 49), at all three control rates; the
  rest were refused at about 515-660 cycles each. This is N_max x C_max enforced on the board.
- CPU share of the scans alone: **19.6 % mean (20.1 % max) at 1 kHz**, vs the derived 49 x 210,427 / 48 M = 21.5 % (the derived
  figure uses the constructed all-slots-full C_max; the flood's installed-OPNsense deny scan is ~192k cycles). At 4 and 10 kHz the
  wall-clock cycles per scan include preemption by the higher-priority control task (205k-227k), hence higher shares (21-23 % mean).
- Refusals add ~13 % only because the flood hammers 25k req/s; the network cannot generate that rate.
- Control task beside the flood: **0 misses at 1, 4 and 10 kHz**, max release-to-run latency 3,699 / 5,999 / 6,433 cycles.
Per-window raw lines: `flood-<hz>/uart.bin` (`[FLOOD] win=...`), aggregate `flood-summary.json`.

## Record of the aborted first functional run (as requested)
On 2026-10-29 ~21:46 the first opn64 functional campaign ran on image commit `c012233` (353 self-tests, branch tip then). It exposed two
defects: (1) the partition selector was first reset in `gateway_begin_request`, which also runs in the NET task; on target that write
faulted (MemManage, `mmfar` = the selector, reproduced in `../opn64-campaign-2026-10-29/discarded-aborted-run/`), found on the first board smoke
test (HTTP hung) and fixed by `a3700d7`; (2) the target boot path leaves zero-filled tail slots in the partition-1 view, which inflated
`GET /api/policy` to 8 rules and failed the network, live-policy, dashboard and soak suites at their first assertion; fixed by `7f7f716`
(all-zero slots inactive, regression test, 354 self-tests). The campaign was redone from a clean reflash
(`../opn64-campaign-2026-10-29/`, commit `24eafe9`). Remnants are archived under `discarded-aborted-run/`; its own stdout/CSV files were
deleted before the archive rule was stated (see that README).

## Caveats
- Nothing here is a WCET bound; observed distributions. Control window = 10,000 releases.
- Network-client scenarios cannot reach the counter's limit; the engaged-counter results come from the on-board flood.
- The flood task and its `gateway_platform_tests_complete()` accessor exist only in labelled builds / are trivial in the primary.
- The sweep used a 10 s control window per step (20 rate windows), not 20 s: the control task records 10,000 releases per boot.
