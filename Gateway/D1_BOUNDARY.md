# D1 compartment boundary — work in progress

The D1 target is `PAPER_EVIDENCE_REQUIREMENTS.md` §§12–13; §13 overrides §12.
The current operational image reaches a working D1.7 step-four checkpoint. See
`Validation/paper-evidence-d1-2026-09-30/REPORT.md` for its measured limits.

| Compartment | Target assets | Current access |
|---|---|---|
| SHIM, privileged | ETH MAC/DMA registers, descriptor ring, frame-copy buffers | Owns HAL/PHY, DMA descriptors and buffers, frame copies and transmit worker. Link logic and HAL ISR handling are still broader than the minimal final target. |
| NET, unprivileged | lwIP state, raw HTTP framing, only NET queues | Core, input and TCP/IP tasks run unprivileged after setup; they receive bounded frame copies and cannot map DMA, GATE or AUTH RAM. TCP/IP uses a bounded kernel-object creation service, with exact ACL review pending. |
| GATE, unprivileged | Validated request, policy store, extractor/validator scratch, GATE queues | Runs unprivileged in 64 KiB at `0x20050000`, with the audit state and generated mutable globals in that region. |
| AUTH, unprivileged | Credential table, HMAC key, token oracle, AUTH queues | Runs unprivileged in 16 KiB at `0x20060000`; private `IDENTIFY` and `LOGIN` queues carry bounded copies. Key/credential seed is copied from privileged flash. |
| APP, unprivileged | Protected handler state, accepted job queue | APP has its 16 KiB region, but the full target queue/region separation is not yet complete. |
| Kernel/logger/initialiser, privileged | Scheduler, queue storage, fault record, initial key copy | MMIO and task stacks for trusted workers are privileged-only; UART logging uses a copied queue. Restrictive fault-reset path is pending. A bounded NET kernel-object worker is privileged. |

The final boundary must include the actual linker/MPU map, every task ACL,
entry-point and indirect-call inventory, and measured SHIM/privileged sizes.
It must show that NET can neither write gate/identity/APP assets nor program
ETH DMA. The current table is a gap register, not an integrity claim.
