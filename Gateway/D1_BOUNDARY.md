# D1 compartment boundary — work in progress

The D1 target is `PAPER_EVIDENCE_REQUIREMENTS.md` §§12–13; §13 overrides §12.
The current operational image reaches D1.7 step 3. See
`Validation/paper-evidence-d1-2026-09-30/REPORT.md` for its measured limits.

| Compartment | Target assets | Current stage-one access |
|---|---|---|
| SHIM, privileged | ETH MAC/DMA registers, descriptor ring, frame-copy buffers | Not split from the privileged Ethernet driver. |
| NET, unprivileged | lwIP state, raw HTTP framing, only NET queues | Network task excludes GATE/AUTH RAM, but still has broad general RAM and DMA-backed pbuf access; Ethernet input and TCP/IP tasks remain privileged. |
| GATE, unprivileged | Validated request, policy store, extractor/validator scratch, GATE queues | Runs unprivileged in 64 KiB at `0x20050000`, with the audit state and generated mutable globals in that region. |
| AUTH, unprivileged | Credential table, HMAC key, token oracle, AUTH queues | Runs unprivileged in 16 KiB at `0x20060000`; private `IDENTIFY` and `LOGIN` queues carry bounded copies. Key/credential seed is copied from privileged flash. |
| APP, unprivileged | Protected handler state, accepted job queue | APP has its 16 KiB region, but the full target queue/region separation is not yet complete. |
| Kernel/logger/initialiser, privileged | Scheduler, queue storage, fault record, initial key copy | Kernel/logger and key copy are privileged; fault-reset path is pending. A temporary registered-object cleanup worker is also privileged. |

The final boundary must include the actual linker/MPU map, every task ACL,
entry-point and indirect-call inventory, and measured SHIM/privileged sizes.
It must show that NET can neither write gate/identity/APP assets nor program
ETH DMA. The current table is a gap register, not an integrity claim.
