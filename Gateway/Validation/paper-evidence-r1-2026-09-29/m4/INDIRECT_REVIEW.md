# Linked-image indirect-call review (R1 final primary image)

`entrypoints-final-primary.json` records 125 register-indirect sites in the R1 Debug
ELF. No direct network-input call path around `Mediation_Wrapper_run` reaches a
protected effect. Eight indirect sites are reachable from `serve` before that
wrapper. This review does not turn the direct-edge audit into complete static
mediation proof.

| Sites | Source/register value | Current resolution |
|---|---|---|
| `netconn_recv_data` and `netconn_recv_data_tcp` | `struct netconn.callback` | The application creates its listener with `netconn_new(NETCONN_TCP)`, a macro passing `NULL` as callback. lwIP's `accept_function` allocates accepted connections with the listener's callback. Under intact lwIP state, these two `blx` instructions are skipped. |
| `pbuf_free` | `struct pbuf_custom.custom_free_function` | The linked image contains `rx_free` (installed by `ethernetif.c`) and `ipfrag_free_pbuf_custom` (IPv4 fragmentation). Both release pbuf storage; neither is a protected handler. Their pointer integrity remains trusted without MPU isolation. |
| `_printf_common` ×3 and `_printf_i` ×2 | newlib-nano formatting callbacks | They are reachable through response/log formatting. Exact target sets have not been enumerated in the linked image, so these five sites remain unresolved. |

The other 117 sites include generated EverParse validator dispatch, lwIP TCP and
timer callbacks, PHY driver function pointers, C runtime initialization and
FreeRTOS callbacks. They remain in the machine-readable inventory. The current
static criterion requires every one of them to be resolved or eliminated and
therefore **does not pass**. Dynamic audit counters cannot close this static gap.
