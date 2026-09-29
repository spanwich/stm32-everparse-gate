# R4 MPU boundary

The F767 uses the FreeRTOS ARM_CM7_MPU port. The network-facing task drops to
unprivileged mode after privileged netif setup; the application task starts
unprivileged. The gate, TCP/IP, Ethernet input/link, diagnostics, startup and
ISRs remain privileged. Each request is copied through depth-one queues; the
gate re-parses its own copy before mediation. Direct CPU writes into gate state
or the app's dedicated input region fault from the opposite unprivileged task.

The table describes **write integrity**, not confidentiality. `M` means the
CPU MPU blocks a direct store by that unprivileged task. `T` means the actor is
trusted or the protection depends on trusted software or device configuration.
`N` means the actor is the intended writer or has no relevant write path.

| Asset | Network task | TCP/IP task | ETH driver / DMA | App task | Diagnostics | ISRs |
|---|---|---|---|---|---|---|
| Gate policy store, lower 48 KiB | M | T | T | M | T | T |
| Validator envelope, gate stack in lower 48 KiB | M | T | T | M | T | T |
| Gate-to-app queue storage | T¹ | T | T | T¹ | T | T |
| App job/input, upper 16 KiB of privileged bank | M | T | T | T³ | T | T |
| Lab credentials and HMAC key in flash | T² | T | T | T² | T | T |
| MPU/privilege configuration registers | M | T | T | M | T | T |

¹ FreeRTOS 10.2 MPU queue wrappers raise privilege for queue operations but
do not enforce per-task queue-handle access control. A task that obtains or
guesses a queue handle may invoke the wrapper. Queue storage is protected from
direct CPU writes, but channel authenticity is **not** established by this MPU
port. The gate still validates copied HTTP input; this is a residual kernel/API
trust boundary, not a seL4-style capability boundary.

² The fixtures and token key are compiled into readable flash. The MPU and
flash controller prevent ordinary writes, but the MPU does **not** protect
their confidentiality from the unprivileged network or app task. They remain
lab-only credentials.

³ The application stack, job and result share its 16 KiB writable region. The
app can change its own job after queue delivery, so the app's use of that input
and its response remain trusted. A read-only job region would need another MPU
region or a different memory layout.

Ethernet DMA is not subject to the CPU MPU. The deployed descriptor section is
`0x20070000..0x200703ff` and payload region is `0x20070400..0x2007ffff`,
disjoint from the gate's lower 48 KiB and the app's upper 16 KiB. That mapping
depends on trusted ETH driver/descriptor setup. Privileged tasks and interrupts
can write every asset and therefore remain in the trusted computing base.

The relevant direct-store experiments and their exact ELF hashes, UART logs,
programmer verification and SWD fault readbacks are in
`Validation/paper-evidence-r4-2026-09-29/`. The five M6 probes test network
policy, validator and app-input writes, an unprivileged privileged-function
call, and an attempted privilege change. A sixth probe tests app-to-policy.
These tests demonstrate the configured direct-write boundary for the tested
addresses; they are not a proof against all confused-deputy paths through the
FreeRTOS API or compromised privileged code.
