# MCU access-control paper evidence — working report, 2026-09-29

This bundle follows `PAPER_EVIDENCE_REQUIREMENTS.md`. Verdicts are deliberately
incomplete until all required measurements are collected. A passing host test,
cross-build or direct-call check is not a proof of whole-firmware mediation.

## Firmware identities

| Image | Source state | Debug ELF SHA-256 | Use |
|---|---|---|---|
| M0 mediation baseline | commit `5a6409465b012b473e33fae464c103b3bf6bb937`; firmware-source diff empty | `76606d3b3d69dbacc319eb40c31abd2f36253b79805998950348374695e0fa7b` | fresh proof replay, on-board baseline and the failed attack case |
| Query-target fix | changes to the handwritten HTTP adapter and three self-tests over M0 | `545223490a9c9da5070809dd4949ba66871f9b6d400c5d02b3fffb8ea7bd979d` | corrected attack and regression tests |
| M4 audit experiment | query fix plus trusted C snapshot instrumentation and HTTP audit headers; source copy and hashes in `m4/audit-source/` | `31cea8839524d21a84141878353a614ff1e1a75453c0d95804cdc60f9f0d7433` | request/effect observations; do not use its overhead as uninstrumented gate cost |

All observed boots report 96 MHz. The primary images have caches disabled. The
board is the NUCLEO-F767ZI with ST-LINK serial `066FFF555567894967085545` on
`/dev/ttyACM1`; `/dev/ttyACM0` was not used. `m0/provenance.json` records the
baseline commit, toolchain, dirty-tree hashes, proof receipts, ELF/map hashes and
build configuration. The flash logs record programmer verification.

## Current hypothesis verdicts

| Hypothesis | Current verdict | Evidence and remaining work |
|---|---|---|
| H1 fit, fixed footprint, no decision-path heap | **Partial** | Both baseline ARM configurations fit; `m1/*-footprint.json` attributes allocated linker-map sections by component. An offline `cargo build --target thumbv7em-none-eabihf --no-default-features --lib --locked` of Cedar 4.12.0 failed on `memchr` requiring `std` (`m1/cedar-thumb-build.log` and `m1/cedar-thumb-build-result.json`). The baseline UART boot sample reported at least 3,376 bytes unused gateway stack; the instrumented 100,000-request run reported at least 3,368 bytes, but its stack usage is not the baseline's. Decision-path allocation counters are still absent. |
| H2 bounded decision cost and spare CPU time | **Not measured** | No DWT per-case samples, five-boot distribution, handwritten baseline or periodic control-task load result yet. No WCET claim follows from the existing static stack report. |
| H3 complete mediation | **Partial** | The linked-image audit finds no *direct* network-to-effect call path around `Mediation_Wrapper_run`. It inventories 125 register-indirect call sites; not all targets are resolved, so the required static criterion is open. The audit-image campaign matched 100,000/100,000 HTTP responses with unique IDs, 49,901 matching acceptances/effects, zero snapshot violations, zero transport errors and 99 concurrent connection pairs. The original RAM policy was restored. `m4/campaign-100000/requests.csv` and its UART log retain the raw observations. Trusted C instrumentation cannot prove absence of unmodeled writes or effects outside the observed bridge. |
| H4 MPU memory integrity | **Not supported in current image** | `configENABLE_MPU` is 0. The HAL MPU attributes only Ethernet memory; task isolation and the five fault injections have not been implemented. The current global gateway context is shared between startup self-tests and network operation. |
| H5 on-device equivalence and attacks | **Partial; baseline attack failure retained** | The original M0 image returned 200 for `/api/status?api/policy` with an operator token under a strict exact-target attack expectation; see `m5/baseline-failure.json` and `m5/attacks-baseline/`. The fixed image denied all 31 labelled attack requests, preserved and restored policy, and passed 300/300 startup, 34/34 HTTP groups on repeat, 129/129 dashboard, and 43/43 live-policy checks. On the audit image, all 31 attack requests were denied with zero gate acceptances, effects or audit violations, and policy was preserved/restored (`m5/attacks-audit-image/`). A separately written Python oracle agreed with 12,527/12,527 adapted on-board cases, including their audit effect counts, with zero transport errors and restored policy (`m5/differential-12527/`). One first HTTP soak timed out after 600 of 1,000 requests; a repeat passed 1,000/1,000. The adapted corpus does not exercise HTTP fixtures for rate 49/255 or authenticated role 0. |

The seL4 12,527-case corpus cannot be copied unchanged: its rule methods are
bit masks and one compatibility case deliberately evaluates an inactive slot,
while this firmware uses method IDs 1–3 and neutralizes inactive slots. The
12,527 comparisons here are a newly generated, deterministic STM32 corpus,
not a replay of those seL4 inputs. The source, seed and every rule/input/outcome
are retained. Rate 49/255 and authenticated role 0 are excluded because the
current HTTP credentials do not supply those fields; they need a separately
labelled firmware fixture or direct on-board validator harness.

## Evidence classes and limits

| Class | What this bundle currently establishes |
|---|---|
| Proved | Fresh F* replay of eight retained extractor/IPC modules and the three new mediation modules on the M0 source. Proof receipts and tool hashes are under `m0/proof/`. The C audit experiment adds no Low* theorem. |
| Model-checked | The committed `Verification/` TLC baseline and mutation counterexamples remain a finite lifecycle model; there is no refinement proof to this firmware. |
| Tested | M0 and query-fix startup/network suites, 31 labelled attacks before and after the fix, 31 attacks with audit counters, the 2,002-request pilot, the completed 100,000-request mixed campaign, and 12,527 adapted differential cases. Per-image hashes distinguish results. |
| Trusted | FreeRTOS/HAL/lwIP, handwritten HTTP classification and identity preparation, C validator bridge and handler semantics, the audit instrumentation, task ownership, linker/MPU behavior, and unresolved indirect calls. |

The three-rule experiment policy fills eight slots, with five inactive slots.
Each attack and M4 script restores the original RAM policy in a `finally`
block. The baseline project default still has four active rules; M0 regression
suites deliberately exercised that existing default and are labelled separately
from paper-policy experiments.

## Next implementation, in dependency order

1. Add build-selectable allocation hooks around `pvPortMalloc`, libc `malloc`
   and any decision-path allocator; bracket the synchronous mediation call and
   export the counter after the full on-board suite. Keep the exact
   uninstrumented Release footprint and instrumented measurement separate.
2. Resolve each linked-image indirect-call site from its source registration
   and finite target set, beginning with the eight sites reachable from
   `serve` before the wrapper. Re-run the post-link reachability check against
   all task, ISR, callback and timer entries. H3 remains partial until every
   indirect edge has a justified target set or the architecture removes it.
3. Add DWT cycle collection for the seven M2 cases on five fresh boots, with
   raw per-sample output and a separately checked handwritten predicate.
   Include empty-measurement overhead and label observed maxima as measurements,
   not WCET. Then add the periodic control task and M3 load runs.
4. Extend the on-board oracle harness for rate 49/255, role 0, path 0 and
   inactive-slot semantics without changing generated algorithms. Keep those
   fixture images distinct from the primary network image.
5. Implement the M6 MPU variant only after splitting the global context and
   reconciling FreeRTOS regions 0–4 with Ethernet's current regions 1–2.
   Run the five fault injections on separate builds and repeat M2/M3 on the
   exact MPU image. Until then the go criterion is not met.
