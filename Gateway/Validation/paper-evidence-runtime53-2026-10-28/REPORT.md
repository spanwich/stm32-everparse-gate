# Runtime-loaded 420-rule policy over HTTP (2026-10-28)

This supports the paper's "policy is runtime data" claim at scale. The full
OPNsense 19.1.7 policy (420 rules, n = 53 partitions × 8 slots) is loaded at run
time, over HTTP, through the **unchanged** verified PolicyBlob update gate, one
partition per request, into a live store in the GATE compartment's RAM.
Decisions use the **unchanged** composed gate (`GateLowGateDecide`) over that
store. Before this, only one 8-rule partition could be updated at run time, and
the n = 53 policy existed only as flash data in the GATE_N32 variant.

## Variant

- Flag `GATEWAY_PAPER_RUNTIME53` (default 0), on the A1v base
  (`GATEWAY_FAST_MEMOPS = 1`, `GATEWAY_VERIFIED_GATE = 1`). The primary A1v image
  is unchanged: with the flag at 0 the loadable image is byte-identical to the
  committed A1v primary (only flag-gated source is added).
- Source `6ad5bd2` (`research/verified-mediation`). Clean tree.
- Image `v11-verified-gate-runtime53`:
  - Debug (flashed, tested) `155719f946dff783c5c393f7b4e65818243c0466250103bdad39d87fa3828009`
  - Release (built, not flashed) `01280c733cddd1c6e6308cb714b3638673b5fd4715123deee2282b0864727485`
- Config: 96 MHz, caches off, Debug board image, generated C at `-Os`.

## Design

**Live store.** `static GATE_SPEC_RULE live_store[8 × 53]` in the GATE
compartment's RAM (`.gateway_gate`, 0x20050000). It boots with every slot the
inactive sentinel (`path = 0xDEADDEAD`), i.e. the restrictive deny-all default.

**Update path.** A labelled endpoint carries the identical 65-byte PolicyBlob
body and an admin `Authorization: Bearer`, extended with a partition index `j`.
The handwritten adapter is minimal:

```c
static uint8_t gateway_runtime53_update(uint8_t role, uint8_t count, uint8_t *body, uint32_t j)
{
    if (j >= RT_PARTS) return 3u;                 /* bounds-check before any gate call */
    BLOB_SPEC_SESSION s = { role, count };
    uint8_t nr = 0u, ctxt = 0u;
    return BlobLowUpdateDecide(s, body, (BLOB_SPEC_RULE *)&live_store[8u * j], &nr, &ctxt);
}
```

- **Size and location:** `Gateway/Paper/paper_runtime53.c`,
  `gateway_runtime53_update` — **88 bytes** in the flashed Debug image
  (`0x0802f4e4`); inlined into the endpoint in Release. It bounds-checks `j < 53`
  and rejects out-of-range values before the update-gate call, then calls the
  unchanged `BlobLowUpdateDecide` with `pol = &partition[j]` (the decode
  destination). `GATE_SPEC_RULE` and `BLOB_SPEC_RULE` are the same 8-byte
  layout, asserted at compile time.
- **Admin-only / rate / 1 ≤ count ≤ 8 / field ranges** are enforced by the
  unchanged verified validator (`RbacPolicy.3d`: `_auth_ok`, `_rate_ok`,
  `_rules_ok`), not by handwritten code. The adapter receives the role from the
  authenticated bearer (the same `gateway_bearer_check` the primary GATE uses)
  and passes it to the gate, which rejects any role below admin.

**Decision path.** `GateLowGateDecide(53, live_store, q, s, &ctxt)` — the same
composed gate as the GATE_N32 variant, reading the runtime-loaded store.

**Inactive slots.** Only partition 52 has inactive slots (4 of 8). The flash
policy's sentinel row carries `min_role = 255`, which the blob validator rejects
(`min_role ≤ 2`). The host tool therefore writes inactive slots with
`min_role = 0` in the wire blob; the gate never consults a sentinel slot's
`min_role` (the sentinel path matches no request), so no decision changes. This
is the only wire difference from the flash policy, and `op=verifyload` confirms
the loaded store equals the intended policy (active slots identical; inactive
slots differ only in the ignored `min_role`).

**Transport.** A labelled `/gate53` endpoint (update / decide / equiv /
verifyload / timing / status), handled in the GATE task before the verified
extractor (it carries raw rule-path integers the extractor does not know). It is
present only in this variant; the primary routes are unchanged.

**What is verified vs handwritten.**
- *Verified, unchanged:* `BlobLowUpdateDecide` + `RbacPolicyValidatePolicyBlob`
  (admit/decode a policy update), `GateLowGateDecide` (the access decision). The
  3D spec, the F* and Low* proofs and the generated C are untouched.
- *Handwritten (trusted):* the 88-byte update adapter above; the live store and
  its deny-all init; the `/gate53` request parsing, bearer extraction and JSON
  responses (built by hand with `memcpy`/integer formatting, because the GATE
  compartment cannot reach newlib `_impure_ptr` and so cannot call `printf`); and
  the privileged timing worker (below).

## Results — all pass

Driver `runtime53_load.py`, HTTP only; UART captured read-only; nothing sent
over the serial port. `runtime53/results.json` is the machine record.

| Item | Result |
|---|---|
| 1. Load 53 partitions through the verified update gate | **53/53 applied**, store digest `2409631190`, 1.09 s |
| `op=verifyload` (store == intended policy) | 424 slots, 420 active, **0 mismatch** |
| 2a. Operator-role update rejected | HTTP 403, `code=0` (verified `_auth_ok`), digest unchanged |
| 2b. Out-of-range partition (`p=53`) rejected | HTTP 403, `code=3` (adapter bounds-check, no gate call), digest unchanged |
| 2c. Oversized blob (100 B) rejected | HTTP 403 `bad_body`, digest unchanged |
| 2d. Malformed blob (`min_role=9`) rejected | HTTP 403, `code=0` (verified field check), digest unchanged |
| 2e. Rule count 0 rejected | HTTP 403 (verified `_rules_ok`), digest unchanged |
| 2f. Rule count 9 rejected | HTTP 403 (verified `_rules_ok`), digest unchanged |
| 3. Equivalence: 20,256 OPNsense oracle vectors on the board vs the runtime-loaded store | **20,256/20,256**, accepts 5,040, **mismatches 0, fail-closed 0**, 12.67 s |
| 4. End-to-end HTTP sample over the 420 paths | **200/200** HTTP statuses match the oracle |

The store digest stayed `2409631190` through load, all six negative cases, the
equivalence sweep, the e2e sample and the update-cost timing; it changes only
after the constructed-worst timing (run last), which overwrites the store by
design.

## Timing (item 6)

DWT cycles, interrupts masked per sample. On this part an unprivileged read of
`DWT->CYCCNT` bus-faults (the MPU does not govern the PPB; DWT is privileged), so
the DWT-instrumented timing runs in a small **privileged worker task**
(`rt_timing_task`) that times the **same** verified routines over the **same**
runtime-loaded `live_store`. Privilege changes neither the code nor the data
(caches off), so the counts are representative; the GATE task still makes every
real decision unprivileged.

| Case | This variant (runtime-loaded store) | Committed `a1v-timing-dist-opnsense53` |
|---|---|---|
| Update applied, partition j = 0 / 26 / 52 (min/mean/max, 2000 samples) | 4,540 / **4,604** / 4,630 — identical across j | update applied **4,573** |
| n = 53 constructed-worst decision (min/mean/max, 512 samples) | 169,112 / **169,231** / 169,260 | n = 53 worst **168,519** |
| n = 53 full-scan absent (loaded policy) | 147,277 / 147,396 / 147,442 | — |
| n = 53 last-rule match (loaded policy) | 147,074 / 147,173 / 147,195 | — |

- **Update cost is independent of j** (first/middle/last give the same figures),
  as expected: `BlobLowUpdateDecide` validates a fixed 70-byte blob and decodes
  8 rules; `j` only selects the destination pointer.
- **Update 4,604 vs 4,573 (+0.7 %)** and **worst 169,231 vs 168,519 (+0.4 %)**
  are within the code-placement variation the timing report documents (it notes
  swings up to ~30 % from placement). **Loading the policy over HTTP at run time
  does not change the decision or update cost** — same code, same RAM data.

## Privileged inventory (`d1_privileged_inventory.py`, extended)

The tool gained the variant's worker (`rt_timing_task`) and now skips tasks
absent from an image, so the A1v numbers are unchanged.

| | A1v primary | runtime53 | Δ |
|---|---|---|---|
| Privileged tasks | 10 | **11** | +1 (`rt_timing_task`, the DWT-timing worker) |
| Interrupt handlers (ISR roots) | 13 | 13 | 0 |
| Unresolved register-indirect call sites | 85 | 85 | 0 |
| Privileged code (union) | 655 funcs / 135,950 B | 675 funcs / 143,430 B | +20 funcs / +7,480 B |

- The one new privileged task is the timing worker. Its closure is 32 functions
  / 11,168 B, but most of it (the gate and blob validators) was already in the
  privileged union, because `run_core` runs the 301 self-tests and the
  12,527-case corpus through those same validators at startup. The net union
  growth is the worker's own code plus the runtime53 init/start reached from
  `run_core` → `gateway_r4_boundary_start`.
- No new ISR and no new unresolved indirect call site. The access decision for
  real traffic still runs in the unprivileged GATE task.

## Size (vs A1v primary)

| Section | Δ Debug | Δ Release | What |
|---|---|---|---|
| `.text` (flash code) | +7,488 B | +3,680 B | the runtime53 endpoint, adapter, decision, timing worker, JSON builder |
| `.rodata` (flash data) | +247,296 B | +247,104 B | the 20,256-vector oracle corpus + 424-rule policy compiled in for the on-board sweep (data, not code; same corpus as the GATE_N32 variant) |
| `.gateway_gate` (RAM) | +15,512 B | +15,504 B | `live_store` (3,392) + timing sample buffer (8,000) + worker stack (4,096) |
| `.privileged_data` (RAM) | +4,096 B | +0 B | timing worker TCB + two queue control blocks/storage |
| `.bss` | 0 | 0 | — |

## Constraints honoured

- F767 only via `/dev/serial/by-id/...STLink_066FFF555567894967085545-if02`
  (ttyACM2); `/dev/ttyACM0` (STM32MP255) untouched.
- Board `192.168.40.128` via `enp44s0`; no host network change; the only traffic
  is what the driver sends. UART opened read-only; nothing sent over serial, so
  the measurement timing is undisturbed.
- The board was left running the committed A1v primary image
  (`8dcac2d65eaaab0f912659a7ad7f5fc55e04b804ad1b28da301c4fa4b0f8710a`, re-flashed
  after the run, 301/301 self-tests).

## Files

- `v11-verified-gate-runtime53/` — the variant image, `board/` boot acceptance,
  `runtime53/results.json` + `runtime53-uart/` capture, `e-map/` privileged
  inventory, `source-manifest.json`, `build.log`.
- `reflash-a1v/` — the A1v re-flash acceptance that left the board on primary.
- `COMMANDS.md`, `provenance/` (preflight, run.sh), `SHA256SUMS`.

## Notes / limits

- The DWT timing runs privileged only because DWT is privileged on this part;
  the decision code it times is the unchanged `GateLowGateDecide`, and all real
  decisions (load, equiv sweep, e2e) run unprivileged in the GATE task.
- The equivalence sweep is chunked (1,000 vectors/request) to stay inside the
  GATE→NET 2 s reply window; the firmware accumulates the totals.
- No WCET claim; the "constructed worst" is the structurally longest decision
  path, and the figures are observed, not bounds.
