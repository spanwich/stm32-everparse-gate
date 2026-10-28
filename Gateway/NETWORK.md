# Milestone 2: FreeRTOS HTTP policy gate

The STM32 runs an IPv4 HTTP server at **192.168.40.128/24, port 80** with no default
gateway, DHCP or DNS. The host route used for validation is `enp44s0`, address
`192.168.40.1/24`. Host addresses and routes are not changed by the project tools.
The board uses a locally administered MAC derived from its MCU UID; the tested
board reports `02:80:e1:1c:67:11` through ARP.

The dashboard, username/password login, and live admin policy toggles are available; see
[DASHBOARD.md](DASHBOARD.md) for accounts, token format and logout semantics.
TLS remains deferred. The earlier static Bearer fixtures below still work.

## Try the lab API

```sh
curl --noproxy '*' -H 'Authorization: Bearer pg-lab-operator' http://192.168.40.128/api/status
curl --noproxy '*' -H 'Authorization: Bearer pg-lab-admin' http://192.168.40.128/api/policy
```

| Token | Subject | Role | Scope |
| --- | --- | --- | --- |
| `pg-lab-operator` | `lab-operator` | Operator | `0x0001` |
| `pg-lab-admin` | `lab-admin` | Admin | `0x0007` |

The request rate is no longer a per-token fixture: it is a verified windowed
counter (`Gateway/Generated/Glue/GlueRate`, one state for the whole interface, a
49 ms window, limit `N_max = 50` enforced by the gate as `count < 50`), stepped
once per authenticated API request in `gateway_set_identity`. The former
`pg-lab-limited` fixture (a constant rate 50) has been removed.

These are public hard-coded lab fixtures, checked by exact token length and bytes.
The header field and Bearer scheme are case-insensitive; token values are
case-sensitive. Tokens are not logged. Missing/unknown credentials return 401 and
`WWW-Authenticate: Bearer`. Insufficient policy permissions return 403; the limited
fixture returns 429. The original static fixtures have no token issuance step. The dashboard login
now issues lab HMAC tokens; neither mechanism provides token expiry, persistent
sessions or a stateful rate limiter. HTTP uses the standard Bearer header syntax;
TLS/OAuth transport requirements are not implemented in this lab milestone.

`GATEWAY_LAB_AUTH` defaults to 1 in `gateway_http.h`; compile with
`-DGATEWAY_LAB_AUTH=0` to disable every hard-coded credential. The host runner's
`--lab-auth-off` option verifies fail-closed behavior. This setting leaves the
listener available after appropriate self-tests, but all authentication fails.
A future real authentication provider replaces this boundary rather than trusting
client-provided role/scope values.

Default policy permits operator status reads and POST logout, and admin policy
reads. `PUT /api/policy` accepts a 65-byte binary body:
`[number_of_rules:1][eight rules, each <uint32 path, uint8 method, uint8 role, uint16 scope>]`.
Integers are little-endian. The reference path constants are in `Shared/path_hashes.h`.
Updates require the admin fixture, commit transactionally in RAM and restore to
defaults on reset. Inactive rule slots cannot grant access. Logout retains the
reference response behavior; it does not revoke these static tokens.

## Ownership and protocol boundaries

One gateway task owns the accepted connection, `GatewayContext`, HTTP assembly
buffer and live policy. Its 226 startup checks finish before network startup;
the context is then reinitialized to the default policy. The same core remains
available to host tests without lwIP or FreeRTOS.

`gateway_http_feed` accepts arbitrary TCP fragments and distinguishes incomplete,
complete and rejected requests. It limits both raw and canonical requests to
4096 bytes and bodies to 1361 bytes. Header names/spacing are canonicalized into
the separate core request buffer before calling the unchanged generated extractor.
The raw buffer becomes response scratch space only after core calls return.
No pbuf/netbuf pointer is retained after the incoming network buffer is released.

The transport supports HTTP/1.0 and HTTP/1.1, a single request per connection,
GET without a body and POST/PUT with Content-Length. HTTP/1.1 requires one nonempty
Host field. Duplicate Authorization/Content-Length/Host fields, folded headers,
transfer encodings, malformed lengths and extra pipelined bytes already received
are rejected. Later requests on that connection are never executed. Unsupported
Expect receives 417. The exact `GET /` dashboard is a public static route after framing validation.
There is no chunked encoding, keep-alive, general URL routing
or full HTTP standard implementation. The core's restricted methods and paths
still apply.

An absolute five-second receive deadline survives trickle input. Response writes
use `netconn_write_partly`, copied data and a two-second absolute budget; lwIP
requires this API when send timeouts are enabled. Closing has a two-second linger
budget. Early malformed/oversized rejection can reset a connection with unread
input; clients consume the framed response by Content-Length. One connection is
processed and one may wait in the accept mailbox. Additional attempts may be
rejected while cleanup/queueing is in progress.

## Scheduler, Ethernet and memory

The pinned CubeF7 1.17.4 lwIP 2.1.2 and LAN8742 sources remain unchanged under
`Network/lwip` and `Network/lan8742`. `Network/sys_arch.c` adapts the supplied CMSIS
port, including recursive protection, nullable mailbox results and 1000 Hz clock
hooks. Network control changes use netifapi/TCP-IP callbacks. Network source
selection, include paths and exclusions are maintained by `configure_project.py`.

| Task | Stack bytes | CMSIS priority |
| --- | ---: | --- |
| Gateway/core | 8192 | Normal |
| UART diagnostics | 2048 | Low |
| TCP/IP | 4096 | High |
| Ethernet input | 4096 | AboveNormal |
| PHY/link monitor | 2048 | BelowNormal |

Application/input/link tasks use static storage. TCP/IP and OS synchronization
objects use bounded startup allocations; accepted netconns allocate their OS
objects from FreeRTOS. FreeRTOS heap_4 is 65536 bytes. lwIP has a separate 16384-byte
heap and statically bounded pools (including 12 TCP PCBs, 3 netconns and 10 custom
DMA RX buffers). Idle/TIM6/SysTick behavior and 96 MHz clocks are preserved.
CPU caches retain their existing disabled state.

General RAM ends at `0x20070000`, including the top-of-stack boundary. The upper
64 KiB is reserved exclusively for Ethernet: a 1 KiB Device MPU region for aligned
RX/TX descriptors and a non-cacheable payload region for the custom RX buffers and
1536-byte TX copy buffer. Both linker scripts and post-link checks enforce bounds
and 32-byte alignment. NOLOAD DMA storage is explicitly initialized by the HAL or
application. This design does not depend on STM32H7 memory restrictions.

RX pbuf storage belongs to the DMA/HAL until linked, then remains allocated until
lwIP releases it. TX always copies into a mutex-serialized DMA buffer and waits
for completion through an IRQ semaphore. Timeout/reset stops DMA before buffer
reuse and clears HAL descriptor-wrapper state. Ethernet IRQ priority is 7, below
the FreeRTOS syscall threshold. Software checksums are explicitly selected in
both lwIP and HAL TX/MAC configuration.

The link monitor checks the PHY every 250 ms and retains the ST example's F767
RMII startup workaround. Link transitions invalidate an in-progress gateway
connection by epoch, update netif state through TCP/IP APIs and rebuild DMA
ownership. Diagnostics report packet/error counts, task stack margins, FreeRTOS
free/minimum heap and lwIP heap usage/peak. Stack margins under 25% light LD3.

## Repeat validation

```sh
python3 Gateway/tools/check_project.py
python3 Gateway/tools/test_host.py --sanitize
python3 Gateway/tools/test_host.py --sanitize --lab-auth-off
python3 Gateway/tools/build_firmware.py
python3 Gateway/tools/board_test.py --config Debug --flash --output /tmp/pg-debug-boot
python3 Gateway/tools/test_network.py --count 1000 --output /tmp/pg-debug-network
```

`board_test.py --flash` explicitly programs/verifies/resets the named ST-LINK
board; `--reset` resets without programming. Close CubeIDE before editing its
metadata or running a headless build. Open only one serial reader at a time.
`capture_uart.py --seconds 60 --output /tmp/pg-uart.log` records telemetry during
network tests without resetting the target. Test scripts intentionally use and
restore RAM policy; do not run them concurrently with another policy writer.

The network suite covers identities, header normalization, every-byte
fragmentation, maximum binary body and complete 4096-byte request, malformed
framing, exact policy updates/rollback, trickle deadlines, queued clients,
reset recovery and a 1000-request no-retry mixed workload. Physical cable tests
require a person to disconnect/reconnect the board while capture runs. Report
physical observations separately from software connection-reset tests.

After CubeMX regeneration, review changes and rerun `configure_project.py`,
`check_project.py`, and the full firmware build. Application hooks are in user-code
regions. The linker reservations are maintained custom changes: restore them if
regeneration replaces the scripts; the consistency checker fails if missing.
Do not fix integration by editing generated makefiles. `.ioc` keeps the FreeRTOS
heap/hook settings; lwIP is application-managed rather than generated by CubeMX.

See `NETWORK_VALIDATION.md` for tested ELF hashes, observed resource margins and
remaining hardware acceptance limits. Milestone 3 adds TLS, MCU entropy, real
credentials/token lifecycle and stateful rate semantics. Generated proof boundaries
remain as documented in `README.md` and `Provenance/manifest.json`.
