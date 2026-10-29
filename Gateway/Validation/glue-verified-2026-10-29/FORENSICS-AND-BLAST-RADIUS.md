# Glue/verified — Part A (reset-helper forensics) and Part B (blast radius)

Branch `glue/verified`, HEAD `0c413fc`. Off-board analysis; no board access.
Part A and Part B are independent of the Low* windowed rate counter still being
written in verified-glue; the functional/timing campaigns re-run after that lands.

## Part A — the image that answered RESET before `a376553`

### What that image was
- Reset feature first added in `a2a34a8` (2026-10-14, "Add serial-commanded
  external target reset on PA0"). It stayed on PA0 and at a 1 KB task stack through
  the parent of the pin fix, `1bd99f5` (runtime-53 evidence, 2026-10-28). The
  image flashed for the first on-bench reset test on 2026-10-29 (~09:52–10:01) was
  built from that pre-`a376553` tree by the prior session's `board_test.py`
  (the reset line had, per `a376553`'s own message, "never been board-tested").
- Reset-helper build at `1bd99f5`:
  - `Core/Inc/main.h`: `TGT_NRST_Pin = GPIO_PIN_0`, port `GPIOA` (PA0).
  - `Gateway/Platform/gateway_target_reset.c`: `treset_stack[256]` (1 KB),
    `treset_tcb` immediately after it, both in `.gateway_privileged`.
  - USART3 RX: single-byte `HAL_UART_Receive_IT` re-armed in the RX-complete
    callback (ISR → 32-byte queue), USART3 IRQ at NVIC priority ≥ syscall level;
    line parser in the privileged `gateway_treset` task. (These were introduced
    with the feature and are unchanged on `glue/verified`.)
  - Replies for both STATUS and RESET go through `gateway_log`, which puts a
    256-byte line buffer on the stack and calls newlib `vsnprintf`.

### Why RESET "worked" but the target never rebooted
`a376553`'s message states it: the helper drove **PA0**, but the wire to the
external board's NRST is on the Nucleo header pin labelled Arduino **A0 = PA3**.
So the task ran, logged `[TRESET] pulse 100ms`, and pulsed PA0 — a pin connected
to nothing — and the target never reset. The pin fix (`a376553`, PA3; unused:
SWO is PB3, no PA3 signal in the `.ioc`/HAL) corrected the wiring mismatch;
`gateway_target_reset.c` logic was untouched (it uses the `TGT_NRST_*` macros).

### Why the board later hung (the 1 KB stack, not a RESET/STATUS asymmetry)
`bf9c6b5` changed **only** `treset_stack[256]`→`[512]` — one line; it did **not**
change the reply code. RESET and STATUS therefore share the exact same reply path
(`gateway_log` → 256-byte buffer + `vsnprintf` + HAL UART + the log mutex). The
`.su` named frames of that path (`run_target_reset` 56 B + `gateway_log` 272 B +
`gateway_log_write` 552 B = 880 B named, before `vsnprintf`/HAL/mutex callees)
are marginal against 1 KB and go over reliably at `-O0`. So:
- There is **no** RESET-vs-STATUS stack difference; both exceed 1 KB under load.
- The first RESET replies happened to fit (marginal survival — at `-Os` the frames
  are smaller, which is likely why the early `[TRESET] pulse 100ms` logged); a
  later command hit the overflow.
- The overflow runs off the end of `treset_stack` into the **immediately adjacent
  `treset_tcb`** in `.gateway_privileged`, corrupting the task's own TCB → silent
  hang (no clean fault record for that task thereafter).

### The `previous_fault = 4` ASSERT, `task = 0x2000cfe8`
`GATEWAY_FAULT` 4 = ASSERT. The fault record's `task` is the TCB pointer. In the
current 2 KB glue ELF the privileged objects preceding the reset stack are
unchanged (`log_tcb`, `watchdog_stack`, `watchdog_tcb`), so `treset_stack` still
begins at `0x2000cbe8`. In the **old 1 KB build** `treset_tcb` therefore sat at
`0x2000cbe8 + 0x400 (1024) = 0x2000cfe8` — exactly the fault record's task
address. The faulting task was `gateway_treset` itself, consistent with its 1 KB
stack overrunning its adjacent TCB. (In the 2 KB build the stack base is the same
but `treset_tcb` moves to `0x2000d3e8` = base + 0x800, leaving 2 KB of stack.)

### Diff old image → `a376553` → `bf9c6b5` (reset helper)
| Commit | File(s) | Change |
|---|---|---|
| (pre) `1bd99f5` | — | PA0, `treset_stack[256]` (1 KB); PA0 unwired; 1 KB marginal |
| `a376553` | `main.h`, `gateway_target_reset.h`, `policy_gate.ioc`, `target_reset.py`, `README.md` | `TGT_NRST` PA0 → PA3 (matches the A0 header wire); logic unchanged |
| `bf9c6b5` | `gateway_target_reset.c` | `treset_stack` 256 → 512 words (1 KB → 2 KB); reply path unchanged |

On-bench after both fixes (this campaign, image `995cd5ec`): STATUS →
`[TRESET] line=released rx_drops=0`, no hang, across the suites and the socket
check. (RESET is not exercised by this session — it would pulse the MP255.)

## Part B — blast radius of the glue integration

Every identifier the integration added / changed / removed, where it is now
referenced, and the action taken. Verified by repo grep (excluding `Debug/` and
`Release/` build trees).

| Item | Kind | Where referenced | Action |
|---|---|---|---|
| `GlueLowMediate` | added (verified, `Generated/Glue/Glue.c`) | `gateway_glue_adapter.c`; required by `check_firmware.py`; reachability-anchored from `gateway_mediate_decide` | verified module, do not edit; provenance in `PROVENANCE.txt` |
| `GlueFrontSetIdentity`/`Classify`/`Credential`/`WireCheck` | added (verified, `Generated/Glue/GlueFront.c`) | `gateway_glue_adapter.c`; `GlueFrontSetIdentity` required by `check_firmware.py` | verified module, do not edit |
| `gateway_live_pi[8]` (`.gateway_gate`) | added, file-static store | `gateway_glue_adapter.c` only | single owner; trusted writers listed below |
| `gateway_policy_store_init` | added | `gateway_glue_adapter.c` (def), `gateway_glue.h` (decl), `gateway_r4_boundary.c` (gate_task, after `policy_init_restrictive`) | kept |
| `gateway_policy_store_load` | added | adapter (def), `gateway_glue.h`, self-tests `test_http.c`/`test_live_policy.c`/`test_login.c`/`test_mediation.c` | kept; self-tests load the live store per the single-store design |
| `gateway_glue_set_identity` | added | adapter (def), `gateway_glue.h`, `extractor_adapter.c` (`gateway_set_identity`) | replaces the live-path `populate_auth_fields`/`populate_rate_field` |
| `gateway_glue_mediate` | added | adapter (def), `gateway_glue.h`, `gateway_mediation.c` (`gateway_mediate_decide`) | kept |
| `gateway_glue_store_to_policy` | added | adapter (def), `gateway_glue.h`, `gateway_mediation.c` (refresh the view after an accepted update) | kept |
| `gateway_mediate_decide` | added (trusted gate) | `gateway_mediation.c` (def, `noinline`), `check_firmware.py` (barrier + required strong fn + must reach `GlueLowMediate`) | kept |
| `gateway_policy_update` | **removed** | no `.c`/`.h`/`.py` references remain | deleted from `gateway_mediation_validator.c`; forward decl removed; `#include Blob.h` there removed |
| `Mediation_Extern_invoke` access/update branches | removed (dead) | `gateway_mediation.c` returns 500 for access/update with a comment (glue handles them) | kept wrapper for public/login only |
| `populate_auth_fields` / `populate_rate_field` | unchanged (generated IPC, `Generated/Extractor`) | still unit-tested by `test_ipc_extract.c`; required-present by `check_firmware.py` | **off the live identity path** (GlueFrontSetIdentity replaces them); retained generated + tested for provenance |
| `Mediation.Field.build_access`, `Mediation.Format.build` | unchanged | retained for the proof + generated-C provenance; off the live access/update path | kept |

### Finding (c): role clamp
The old `populate_auth_fields` clamped an out-of-range role to admin (2). On the
live path that is now moot: `gateway_set_identity` (`extractor_adapter.c`) rejects
`id->role > ROLE_ADMIN` **before** calling `gateway_glue_set_identity`, so an
out-of-range role is refused, not clamped up. Comment at `extractor_adapter.c:40`.

### Trusted writers of `gateway_live_pi` (the live gate store)
All in `gateway_glue_adapter.c` (the single TU that declares it):
1. `gateway_policy_store_init` — one-time restrictive default (called from
   `gate_task` in `gateway_r4_boundary.c` after `policy_init_restrictive`).
2. `gateway_policy_store_load` — copies a caller `Policy` view into the store
   (self-tests only, to set up a per-request store).
3. The verified update gate inside `gateway_glue_mediate` — on `GlueLowMediate`
   result 4 (accepted update), `BlobLowUpdateDecide` writes the decoded rules into
   the partition; no handwritten path writes the store on update.
`c->policy` is a **read-only view** refreshed from the store via
`gateway_glue_store_to_policy` after an accepted update — never the reverse.

### Comments in touched files
Reviewed. `gateway_mediation.c` top comment and `gateway_mediate_decide` comments
describe the current access/update-through-glue, public/login-through-wrapper
split; the `Mediation_Extern_invoke` access/update comment explains the 500. The
`README.md`/`REPORT.md` "Interfaces and ownership" note (2026-10-29) states the
same split and the `check_firmware` two-barrier admission. No stale
`gateway_policy_update` or "all kinds through the wrapper" wording remains.

## Appendix — pre-rate-counter campaign snapshot (to be superseded)

Image `995cd5ec` (Debug, HEAD `0c413fc`). These numbers will be re-measured after
the windowed rate counter lands; recorded here for continuity only.

- 301/301 self-tests (corpus 12527/0); network 34/34; live-policy 43/43;
  dashboard 129/129; 200 attacks (0 disagreements, 0 fail-open, 0 audit
  mismatches); 5,000 soak (median 16.9 ms); 5,000 audit (effects 2996 ==
  acceptances 2996, 0 unmatched); socket-check clean (403, NETCONN err 0, pools
  healthy); privileged inventory 664 fns / 137078 B / 85 indirect sites,
  gate/app/auth unprivileged.
- 100,000 audit: **not completed** — aborted at request 2550 on a transport-level
  `TimeoutError` on a policy-update (empty status), not a decision disagreement;
  every decision through 2549 matched; board stayed alive (403); hang_watch
  "load finished without hang". Likely lwIP TIME_WAIT pressure (12 TCP PCBs) under
  sustained sequential load, independent of the glue. Re-run (paced / transient-
  timeout-tolerant) deferred to the post-rate-counter board campaign.
- MPU injection probes: deferred to the post-rate-counter board campaign. The glue
  does not change `port.c`, the MPU regions, or the compartment section placement
  (`.gateway_gate`/`.gateway_app`/`.gateway_auth`/`.privileged_data`), so the D1
  isolation structure is unchanged; the probes will be re-run on the final image.
