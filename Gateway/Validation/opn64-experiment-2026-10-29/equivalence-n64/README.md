# 20,256-vector OPNsense equivalence on the n=64 store (2026-10-30)

Image: labelled runtime-53 variant (`GATEWAY_PAPER_RUNTIME53=1`) built at tip c51a9d4+ on `glue/opn64-primary`; it is the
primary image plus the labelled `/gate53` diagnostic endpoint, working on the PRIMARY 8x64-slot live store (the endpoint does not
exist in the primary image). 354/354 self-tests. Store layout: partition 1 = gateway routes (3 restrictive-default rules),
partitions 2..54 = OPNsense 19.1.7 (420 rules, provisioned through `PUT /api/policy?part=J`, the live API, i.e. the verified
GlueLowMediate update branch), partitions 55..64 inactive sentinel.
Result (`runtime53/results.json`): load 53/53 in 0.98 s; verify-load 0 mismatches (423 active = 420 + 3 default);
**equivalence 20,256/20,256 vectors, 0 mismatches, 0 fail-closed (5,040 accepts)**; e2e HTTP sample 200/200;
7 negative updates (operator, part=65, part=0, oversized, malformed, rule count 0, rule count 9) all rejected with the digest unchanged.
The decision under test is `GateLowGateDecide` over the 64-partition store as reached through `GlueLowMediate`.
After this run the board was reflashed with the primary image (`../final-reflash-programmer.log`, sha 885973c3).
