# M3 instrumentation variants and excluded runs

The requirement forbids tuning away a failed hypothesis. These variants are
kept separately because the observer can change scheduling and network timing.
Every deployed image has its own verified flash log, UART capture, ELF hash,
build log and source-content manifest where noted.

| Image | ELF SHA-256 prefix | Observation |
|---|---|---|
| First fixed control+allocation sampler (`variant-fixed/`) | `c9f9fbd1` | 301/301 board tests. A 600-second idle run recorded 844 missed 1 ms deadlines. `uxTaskGetSystemState` scans unused stacks while scheduling is suspended; this observer ran each second. |
| Nonintrusive runtime sampler (`variant-nonintrusive/`) | `b9c946ab` | Per-task `vTaskGetInfo(..., pdFALSE, ...)` avoided the scan. A 600-second idle diagnostic comparison recorded zero misses under the startup four-rule policy. With continuous valid requests the low-priority diagnostics task was starved, so periodic samples were missing. This image retains per-request UART logging. |
| Raised diagnostics priority, per-request logging suppressed (`variant-observable/`) | `3de06d33` | Control observations continued, but repeated valid requests stalled after 7–14 successes in the 60-second pilots. The host saw 8-second timeouts while network RX continued; an HTTP probe after the stall could not connect. |
| Low diagnostics priority, per-request logging suppressed (`board-lowdiag-nolog/`) | `0f1d959a` | A paced 15-second pilot also stalled after four successes. This weakens diagnostics priority as an explanation of the stall. |
| Raised diagnostics priority **and** per-request UART logging (`variant-highdiag-log/`) | `4fae52cd` | Selected for the fixed-duration M3 runs. A 15-second 10 ms-cadence pilot completed 1,224 requests without error, with full one-second task observations. |

The no-log stall is reproducible and timing-sensitive. The available data do
not identify a specific lwIP state transition or prove that this is the cause
of the historical one-off 600/1,000 soak timeout. The no-log attempts are
availability failures; they are not evidence of a policy fail-open.

The first valid-load attempt was stopped because the driver had not installed
the three-rule paper policy (`valid-aborted-default-policy/`). The next was
stopped because its low-priority observer had no samples under load
(`valid-aborted-diagnostics-starvation/`). The 60-second and 15-second pilot
directories remain as raw evidence and are excluded from ten-minute summaries.

The allocation wrappers in `variant-highdiag-log/` count *all* tasks while the
gateway decision window is open; 673 such calls overlapped the 48,902-request
valid run. That does not mean the gateway task allocated. A later separately
labelled variant filters by the owning task for H1. The selected M3 CPU and
deadline results remain tied to the original `4fae52cd` ELF.
