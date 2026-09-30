# Mandatory gateway mediation: reuse audit and experiment

**Historical scope:** this report records the original verified-mediation
experiment based on `1069e4b`, before board deployment and the paper-reference
R1 validator migration. The current firmware results, including on-board tests,
timing, complete-mediation limits and MPU feasibility, are in
[the R1 evidence report](../Gateway/Validation/paper-evidence-r1-2026-09-29/REPORT.md).

## Result and scope

The existing generated core is reusable. This branch adds a **proved Low*
serializer and conditional admission wrapper**, extracts them to C, and puts the
HTTP application path through that wrapper. Public assets and login now have
explicit admission checks, alongside protected APIs and policy updates.

This is a bow-tie-style reduction of the security boundary: the unwanted event is
an application action without the required admission. The preventive barrier is
**validator plus mandatory wrapper and its integration assumptions**, not the
validator in isolation. The result is not whole-firmware verification or a proof
of confidentiality/noninterference for every byte, timing signal, or log.

The baseline is commit `1069e4b` on `main`. All implementation work is on
`research/verified-mediation`. No board reset, serial capture, network test, or
flash was performed for this experiment. The old installed image is unchanged.

## Reuse audit

| Component | Audit and reuse result | What it does not establish |
|---|---|---|
| Seven HTTP extractor modules | Original C unchanged; all seven retained F* sources freshly verify | Complete HTTP semantic correctness or mandatory mediation |
| IPC extraction module | Original C unchanged; retained F* source freshly verifies | Authenticity of identity/rate attributes or full field-equality postconditions |
| EverParse access validator | Reused unchanged for protected and explicit public access | That attributes came from this request, or that a caller obeys rejection |
| EverParse policy validator | Reused unchanged for exact 70-byte input | That the application commits the same candidate |
| EverParse login validator | Previously unused in HTTP admission; now reused | Credential checking, token issuance correctness, or token lifecycle |
| HACL* primitives | Unchanged provenance checks pass | Correctness of the handwritten authentication protocol |

The main extractor contract establishes live/disjoint buffer obligations and
modification bounds. Helper contracts include selected range guarantees; they do
not collectively imply exact HTTP interpretation. Fresh verification of those
contracts is stronger evidence than source hashes alone, but does not strengthen
the contracts. We did **not** re-extract and compare the old extractor C or replay
EverParse's own generation/proofs in this experiment.

The old HTTP adapter returned assets and invoked login before policy evaluation.
Those were intentional public routes, but did not satisfy the new requirement
that every application handler have explicit admission. They now use the same
wrapper entry point. Errors and authentication failures may terminate without a
handler or a gate call.

## Established properties and trusted boundary

`Mediation.Format` proves bounds, termination, input preservation and exact
per-byte equality to its `expected` function for all 106 scratch bytes. The
executable layout selects role/rate/scope/path/method from the supplied request,
active rules from the supplied policy, and candidate bytes from that request's
body. Inactive slots have method zero, which cannot match supported methods 1–3.
Public rules are fixed GET rules for two distinct asset IDs and cannot be widened
by an uploaded application policy. The byte mapping is reviewed against the
retained `.3d` specification and independently tested; equivalence of that mapping
to the `.3d` specification is not itself a proved theorem.

R4 added `Mediation.Field.build_access` as an access-kind serializer.
Its Low* postcondition proves all 106 output bytes equal to the **same**
`Mediation.Format.expected` specification and confines writes to the output
buffer. It copies the 64-byte policy field in a dedicated loop and writes the
fixed header, request fields and zero tail separately. It is extracted into a
separate generated C module; the D1 production wrapper calls it for access kind 2
and retains `Mediation.Format.build` for the other kinds. This proof covers access kind 2 only, and does not
expand the trusted C/FFI boundary or establish machine-code timing properties.

`Mediation.Wrapper.run` discharges the handler's admission precondition for the
**same immutable request, policy and login snapshots** supplied to the validator
bridge. Its postcondition establishes admission when `invoked=true`, and unchanged
handler context when `invoked=false`. The scratch buffer may change on denial.
The outer C adapter can still write an error response after denial; “no effect”
in this theorem refers to the handler context during the generated call.

| Trusted item | Exact assumption |
|---|---|
| Platform | FreeRTOS, CubeIDE startup/HAL, lwIP, hardware memory behavior and exclusive gateway-task ownership work as specified |
| Formal toolchain | F*, Z3, standard proof libraries, KaRaMeL, generated runtime headers, ARM GCC and linking preserve the intended contracts/semantics |
| Own preparation code | HTTP classification, authentication, JSON decoding and policy snapshot serialization bind the correct current request/identity/policy; an aligned complete context (8,860 bytes on ARM, 8,864 on the host) and live initialized disjoint buffers satisfy the explicit `input_valid` bounds |
| `Mediation.Extern.check` | Calls the corresponding real EverParse validator on the generated input, does not modify inputs/context, and returns true only on acceptance; its `authorized` predicate is an explicit abstract contract |
| `Mediation.Extern.invoke` | Acts only on the supplied snapshots and context, performs the selected leaf operation, retains no pointers, and obeys its frame contract |
| Integration | No unmodeled task, DMA writer, memory corruption, indirect handler reference or direct client entry point bypasses the intended C call graph |

The external `.fsti` is type-checked as an interface; its C implementation is
**trusted, not proved by checking that interface**. Policy unpack/commit and
response construction remain in this leaf boundary. The login leaf reparses the
same immutable JSON body with the same trusted decoder. These are our own
unverified modules, listed separately from trusted platform code.

The post-link direct-call graph check rejects an HTTP-to-handler path that avoids
`Mediation_Wrapper_run`, and a validator-bridge path reaching a handler. It includes
inter-function tail branches. It is integration evidence, not a machine-code
control-flow theorem or protection against arbitrary C writes. Legacy core APIs
remain for startup/self-tests; their direct calls are outside network ingress.
For public assets, the admitted leaf returns the successful HTTP status; the
existing trusted network sender selects and transmits the immutable asset from
the unchanged per-request route flags. That final serialization is outside the
Low* theorem.

## TLA+, Low* and testing comparison

The TLA+ model has one serialized owner, two requests, four operation classes,
three roles, two rate values, two payload/candidate values and two policy states.
It abstracts concrete paths, methods, scope bits, cryptography and buffer bytes.
Cancellation/error is modeled as rejection before an effect. Policy changes
occur between transactions. No fairness/liveness or unbounded-state theorem is
claimed, and there is no formal refinement proof connecting TLA+ to the C.

The baseline checks **4,715 distinct states** (9,275 generated), with no invariant
failure. Six deliberately faulty models produce counterexamples: bypass,
ignored denial, changed request, changed candidate, stale decision and replay.

| Property/fault | TLA+ experiment | Low* experiment | Implementation evidence |
|---|---|---|---|
| Handler requires admission | Baseline invariant; bypass/denial counterexamples | Ignoring denial and changing operation kind fail proof | Real-validator effect assertions; post-link call graph |
| Request/candidate binding | Mutated request/candidate counterexamples | Changing request or candidate bytes before invocation fails proof | Snapshot identity and immutability checks |
| Exact serialization and memory frame | Concrete bytes abstracted away | Byte equality/frame/bounds proved; replacing a copied byte with zero fails proof | Independent byte oracle and sanitizers |
| Rule/scope and login constraints | Simplified admission predicate only | Existing validator contract trusted | Real EverParse tests, including inactive slots and exact login framing |
| At most one invocation per transaction | Replay counterexample | **Not proved: duplicate invocation still type-checks** | Instrumented kernel permits one effect; HTTP/direct-adapter replay tests pass |
| Fresh decision across requests | Stale-decision counterexample | Wrapper has no stored decision; outer lifecycle is outside its theorem | Consumed HTTP/context state tests |
| Same candidate committed | Checked abstract event carries candidate | Admission is bound to candidate; C commit semantics trusted | Real policy replacement/readback and denied-policy preservation tests |

The duplicate-invocation mutation is intentionally retained as a passing proof in
`negative_proofs.py`. The runner explicitly reports this gap; it is not counted
as a successful proof rejection. This experiment demonstrates complementary
coverage, **not** a claim that TLA+ automatically fills a C proof gap. A future
one-use effect contract could strengthen Low* coverage; the current C executes a
single invocation and the tests check that behavior.

The model is 60 lines; Low* comprises 91 serializer lines, 32 wrapper lines and
47 trusted-interface lines. The new C integration/validator bridge is 151 lines,
plus login preparation and HTTP edits. Counts include comments/blank lines and
are scale indicators, not comparable measures of assurance. TLC finishes this
small model in about a second; proof authoring additionally required explicit
frames, bounded runtime arithmetic and a Z3 arithmetic-solver workaround. A compile-time assertion also exposed the
host/ARM enum-layout difference; both actual context sizes are now explicit in
the caller contract. No
controlled human-effort or target latency benchmark was performed.

## Validation, resources and conclusion

- Full application host ASan/UBSan: **297/297**.
- Lab authentication disabled: **218/218**.
- Kernel ASan/UBSan: **5,687 cases**, real EverParse validators, independent byte
  oracle, exact snapshot identity, preserved inputs and denial without effects.
- Fresh extractor/IPC proof replay: **8/8 modules**. New serializer and wrapper
  proofs pass; five negative mutations fail proof, duplicate invocation does not.
- Both final ARM configurations build without compiler warnings/errors and pass
  the extended post-link checks, including no recursion in the new generated C.

| Configuration | text | data | bss | text increase over baseline |
|---|---:|---:|---:|---:|
| Debug | 189992 | 112 | 175280 | 5444 |
| Release | 132336 | 116 | 175264 | 3924 |

These totals include ten additional firmware self-tests as well as the wrapper.
The gateway task remains 8 KiB. Known-frame sums for the HTTP path are about
3.1 KiB; they exclude some library/assembly costs and interrupt frames and are
**not a worst-case stack bound**. No new on-board stack margin or performance
measurement is claimed. Full build logs, stack reports, ELF hashes and source
hashes are recorded under `evidence/` and `summary.json`.

The pinned tools are F* `1cff8d796deed8834926389a986d015498780041`, KaRaMeL
`fb36fecb552c9fb202beb38a6c5a732c3f2cd49f`, Z3 4.13.3 and TLC's reported version
2.19. The cached jar filename says v1.7.4; its actual identity/version, rather
than that filename, is recorded. An initial Z3 assertion failure is retained in
the evidence. Final runs explicitly use arithmetic solver 2 and no lax/admitted
proofs. The local KaRaMeL checkout has pre-existing extra declarations in
`krmllib/dist/generic/FStar_UInt.h`; that header is not used in these builds,
which use the project's unchanged generated runtime headers.

**Recommendation:** retain the existing generated cores and this narrow mediation
kernel. Use TLA+ for lifecycle/state reasoning and Low* for executable byte/frame
and admission guarantees. Before claiming a stronger end-to-end theorem, reduce
or verify the listed C preparation/leaf assumptions and strengthen the one-use
contract. Platform verification is unnecessary for that next step; platform
behavior remains an explicit assumption. Deployment and target measurements are
a separate review step, not part of this experiment.

Primary references: [Low* documentation](https://fstarlang.github.io/lowstar/html/Introduction.html),
[KaRaMeL](https://github.com/FStarLang/karamel), and the
[TLC paper](https://www.microsoft.com/en-us/research/uploads/prod/2016/12/Model-Checking-TLA-Specifications.pdf).
