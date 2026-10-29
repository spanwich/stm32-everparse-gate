# Discarded: first opn64 functional run (aborted) and the first on-board smoke images

Kept, not deleted. What exists here:
- `smoke-and-first-hang-images/`: the first runtime-53 (n=64) and primary images flashed on 2026-10-29 ~21:36-21:40
  (commit 87d57dc, before a3700d7). HTTP hung on target; `uart-hang-capture-mpu-fault.log` shows
  `[RESET] previous_fault=6 cfsr=0x00000082 mmfar=0x200516e8`, i.e. a MemManage fault on the new request-scoped
  partition selector (`gateway_req_part`), written from `gateway_begin_request` in the NET task which has no MPU access
  to GATE memory. Host tests passed; only the target exposes this.
- build outputs/logs from that smoke work.

NOT preserved (honest note): the stdout/CSV/UART files of the first aborted functional campaign (started ~21:46 on image
commit c012233, 353 self-tests) were deleted by me during clean-up before the "archive, don't delete" rule was stated to me.
What that run showed (from the console output at the time): the network, live-policy, dashboard and soak suites failed at
their first assertion because `GET /api/policy` returned 8 rules (the target boot path leaves zero-filled tail slots in the
partition-1 display view, and the new derived rule count treated them as active) instead of the 3 restrictive-default
rules; the attack corpus (rc=0), inventory (rc=0) and the start of the 100k audit ran but were stopped. A second launch hit
a stale board state and an orphaned `openocd` (from the killed hang-watch) holding the ST-LINK (DEV_CONNECT_ERR) and was
also discarded. Fixes: a3700d7 (selector reset in GATE context), 7f7f716 (all-zero slots inactive + regression test,
354 self-tests). The functional campaign was then redone from a clean reflash: `../` (opn64-campaign-2026-10-29).
