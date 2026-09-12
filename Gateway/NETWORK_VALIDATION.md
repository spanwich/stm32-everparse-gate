# Milestone-2 validation — 2026-09-10

The final **Debug and Release images each passed 226 on-board startup tests and
34 network acceptance scenarios, including 1000 sequential mixed HTTP requests**.
Both were programmed and verified with STM32CubeProgrammer. Final Debug is left
running at **192.168.40.128:80**, with the default RAM policy restored by the suite.
Physical cable unplug/replug acceptance remains unverified: no such event was
observed during the requested capture window.

## Results

| Measurement | Debug | Release |
| --- | ---: | ---: |
| Build errors / warnings | 0 / 0 | 0 / 0 |
| MCU startup checks | 226 / 226 | 226 / 226 |
| Network acceptance scenarios | 34 / 34 | 34 / 34 |
| Sequential mixed requests, no retries | 1000 | 1000 |
| Sequential-workload duration, seconds | 13.00 | 14.68 |
| Gateway unused stack, of 8192 bytes | 6276 | 6392 |
| Diagnostics unused stack, of 2048 bytes | 876 | 932 |
| TCP/IP unused stack, of 4096 bytes | 3180 | 3600 |
| Ethernet input unused stack, of 4096 bytes | 3772 | 3892 |
| Link monitor unused stack, of 2048 bytes | 932 | 976 |
| FreeRTOS idle free / minimum free heap, bytes | 60760 / 60376 | 60760 / 60376 |
| lwIP final used / maximum used heap, bytes | 0 / 244 | 0 / 244 |
| Dropped UART logs / RX queue drops / TX errors | 0 / 0 / 0 | 0 / 0 / 0 |
| GNU size `text`, bytes | 156684 | 104836 |
| GNU size `data`, bytes | 112 | 116 |
| GNU size `bss`, bytes | 173096 | 173080 |

These are observed test-workload high-water values, not whole-program worst-case
stack bounds. Every task retained more than 25% unused stack. FreeRTOS returned to
the same idle allocation level after the load, and lwIP heap use returned to zero.
GNU `bss` includes NOLOAD DMA storage and linker reservations; it does not mean all
reserved bank space is usable by libc or the FreeRTOS allocator.

The host ASan/UBSan build passed the same 226 tests without sanitizer findings.
With `GATEWAY_LAB_AUTH=0`, the alternative host suite passed 193 tests, including
known-token rejection and HTTP 401. The disabled-auth configuration was tested on
the host, not flashed. All 191 milestone-1 checks and 119 original extractor/IPC
vectors remain in the default suite.

## Exercised behavior

The network tests verify operator/admin access, 401 challenges, invalid and
case-altered tokens, exact-token comparison, 403 policy decisions and the fixed
rate-denied token's 429 response. They cover bytewise fragmentation, the full
4096-byte request limit, a 1361-byte binary body, oversized requests, header
normalization, duplicate headers, transfer-encoding rejection and pipelining
rejection when extra bytes arrive in the same assembled input.

Admin binary policy updates change subsequent decisions; malformed updates leave
the previous policy intact. The suite restores defaults afterward. The five-second
receive deadline was exercised while a client continued sending trickle bytes.
A queued client survives an active-client disconnect. Tests reset TCP connections
during receive/response and require recovery within three seconds. The one-slot
backlog may reject attempts overlapping cleanup; those fault-recovery checks use
a bounded retry interval. The 1000-request sequential workload uses no retries.

The first live request exposed lwIP's requirement for `netconn_write_partly` when
a send timeout is enabled; the maintained implementation uses this API and tracks
partial writes within an absolute deadline. The final acceptance runs use that
corrected firmware. Clients consume responses by Content-Length because rejecting
unread oversized input may end the connection with TCP reset.

## Hardware, builds and provenance

The ST-LINK serial is `066FFF555567894967085545`; STM32CubeProgrammer identified
MCU device ID `0x451`, revision Z, Cortex-M7 and 2 MiB flash. Under-reset SWD at
requested 1000 kHz (actual 950 kHz) was used. Each final download was verified before
reset/run. UART reports SYSCLK/HCLK 96 MHz and FreeRTOS V10.2.0. LAN8742 negotiated
100 Mbps full duplex, ARP resolved to `02:80:e1:1c:67:11`, and ping succeeded.
The host used its existing `enp44s0` / `192.168.40.1/24` route. No host interface,
route, MCU option byte or ST-LINK firmware changes were made. The exact physical
cable/switch topology was not confirmed separately.

Builds use the installed STM32 GCC 13.3.1. Generated code is `-Os` in both
configurations. Post-link checks verify generated call safety, strong hooks,
Ethernet section bounds/alignment and the MSP boundary at `0x20070000`. An isolated
ELF with its descriptor section moved to `0x20060000` was correctly rejected by the
placement check; that image was never flashed. The prior milestone's negative O0
recursion experiment remains documented separately.

All imported generated algorithms and vendored lwIP 2.1.2/LAN8742 files match their
provenance hashes. The CMSIS adaptation is separate from the vendor copy and has
an explicit patch. The ST Ethernet reference and original notice are retained.
No new F* proof checking or extraction was performed.

[Validation/milestone2-2026-09-10](Validation/milestone2-2026-09-10) contains final
build/host logs, both fresh-boot and load UART captures, programmer verification
logs, network results, stack reports, source fingerprints and tested ELF hashes.
Deployment stages an immutable ELF under its audit directory before programming.
The current Debug and Release build artifacts match those staged-image hashes.

The pre-milestone workspace and working milestone-1 firmware are backed up at
`/tmp/policy-gate-ethernet-lxhh7vnq/before.tar.gz`. Staged final images and detailed
intermediate diagnostics are also in that audit directory; `/tmp` may be cleaned.
The maintained acceptance logs and hashes are inside the workspace.

## Outstanding limits

Physical cable disconnect/reconnect, forced DMA timeout, deliberate RX-pool
exhaustion, cold power-cycle behavior and worst-case MSP/interrupt stack usage were
not tested. Link recovery and DMA ownership cleanup are implemented, but startup
link negotiation and TCP reset recovery do not substitute for those fault tests.
No TLS, entropy integration, token lifecycle, persistent policy or real rate-window
counter is implemented. The hard-coded Bearer table remains a lab-only provider.
