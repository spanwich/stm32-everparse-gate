# Live policy dashboard validation — 2026-09-12

**Debug firmware is installed and running at http://192.168.40.128/.** Admin can
toggle operator access to GET `/demo` and `/api/status`. Demo serves plain text
only after authentication and policy approval. Operator cannot edit policy.
Default state was restored after testing: operator demo denied, status allowed;
admin access remains enabled. Policy remains RAM-only. TLS is still deferred.

## Observed acceptance

- Host ASan/UBSan: **287/287**; authentication disabled: **208/208**.
- Debug and Release: warning-free build and post-link checks passed. Generated
  F*/EverParse/HACL algorithms are unchanged. Release was not flashed this turn.
- Debug programming and flash verification succeeded. Clean startup UART:
  **287/287 tests**, HTTP ready, Ethernet link up, healthy heartbeat acceptance.
- Board live-policy suite: **43/43**. Immediate allow/deny, actual readback,
  preservation of unrelated rules, operator update rejection, and rejection even
  when an uploaded rule attempts to allow operator PUT policy were exercised.
- Dashboard/login suite: **129/129**, including exact served HTML and JavaScript.
  The 4386-byte script exercises streaming beyond the 4096-byte request buffer.
- Existing HTTP suite: **34/34** groups and **1,000** mixed requests (13.054 seconds).
- Two actual browser tabs, independently logged in as admin/operator: operator
  demo response **403 → 200 plain text → 403** as admin toggled access. Admin
  retained 200; operator controls were hidden. Status toggle and refresh worked.
  Mobile viewport 390x844 had no horizontal overflow. No JavaScript exceptions.
- Exact default binary policy was restored and read back after browser tests.

## Resource measurements

| Configuration | text | data | bss |
| --- | ---: | ---: | ---: |
| Debug | 184548 | 112 | 175272 |
| Release | 128412 | 116 | 175256 |

HTML is 2935 bytes; JavaScript is 4386 bytes. Static assets live in flash and
are bounded at 16 KiB each. Header and flash body share a two-second absolute
send deadline. No task-stack, heap, request-buffer or DMA reservation was enlarged.

Minimum observed free stack bytes under the recorded workload:
gateway **5268**, diagnostics **876**, TCP/IP **3180**, Ethernet input **3740**,
link monitor **932**. All margins OK. FreeRTOS free/minimum heap: **60768/60384**;
lwIP returned to zero heap used, peak **6412**. No reported log drops, network
drops, TX errors or lwIP allocation errors. These are observations, not
worst-case stack or interrupt bounds.

- Installed Debug ELF SHA-256:
  `ffecb57c8750390ba68376ef477cfbb29422d77c70bbba58d72a37fbbdd4b026`
- Build-only Release ELF SHA-256:
  `30dcbce15061835c93c1777d1059f18a2e73e2676991c00d0d836d8cb99342ed`

Evidence: `Gateway/Validation/live-policy-2026-09-12/`. Backup before this change:
`/tmp/pg-live-policy-geyexvx_/before.tar.gz`. Staged installed ELF:
`/tmp/pg-live-policy-debug-boot/policy_gate.elf`.

## Boundaries

See `DASHBOARD.md` for the exact handwritten `/demo` route adapter, policy wire
format and proof boundary. The UI edits operator permissions on two GET paths;
it does not add arbitrary runtime routes. Full-policy PUT is atomic but
last-write-wins between concurrent admin editors. No revision precondition,
persistent policy storage, TLS, token expiry/revocation, hardware entropy,
stateful rate windows, fresh formal proof run, or physical cable-recovery test
was added or claimed.
