# D1 compartment boundary — work in progress

The D1 target is `PAPER_EVIDENCE_REQUIREMENTS.md` §§12–13; §13 overrides §12.
The current operational image is only D1.7 step 1. See
`Validation/paper-evidence-d1-2026-09-30/REPORT.md` for its measured limits.

| Compartment | Target assets | Current stage-one access |
|---|---|---|
| SHIM, privileged | ETH MAC/DMA registers, descriptor ring, frame-copy buffers | Not split from the privileged Ethernet driver. |
| NET, unprivileged | lwIP state, raw HTTP framing, only NET queues | Network task has a broad general-RAM region; Ethernet input and TCP/IP tasks remain privileged. |
| GATE, unprivileged | Validated request, policy store, extractor/validator scratch, GATE queues | Gate task and policy store remain privileged. |
| AUTH, unprivileged | Credential table, HMAC key, token oracle, AUTH queues | Credentials and token code still execute in GATE; no private AUTH task or RAM. |
| APP, unprivileged | Protected handler state, accepted job queue | APP has its 16 KiB region, but the full target queue/region separation is not yet complete. |
| Kernel/logger/initialiser, privileged | Scheduler, queue storage, fault record, initial key copy | Kernel and logger are privileged; key copy and fault-reset path are pending. |

The final boundary must include the actual linker/MPU map, every task ACL,
entry-point and indirect-call inventory, and measured SHIM/privileged sizes.
It must show that NET can neither write gate/identity/APP assets nor program
ETH DMA. The current table is a gap register, not an integrity claim.
