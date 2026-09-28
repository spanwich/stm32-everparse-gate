> **Research branch:** this checkout contains the [verified mediation experiment](Verification/README.md).
> Its [report](Verification/REPORT.md) distinguishes proved, model-checked, tested,
> and trusted properties. These changes have not been flashed to the board.

# STM32 EverParse Policy Gate

An HTTP policy gateway running on the **NUCLEO-F767ZI with FreeRTOS**. It ports the
original gateway's generated F*/EverParse core and HACL* crypto to STM32, with
lwIP Ethernet, lab login, and a browser dashboard for live access-policy edits.
The seL4/CAmkES runtime is not part of this port.

## Open the dashboard

1. Power the board with the project firmware installed and connect its Ethernet
   port to a LAN on **192.168.40.0/24**.
2. Use a computer with an address on that subnet. The board has the static address
   **192.168.40.128**, with no DHCP or default gateway; avoid an address conflict.
3. Open **[http://192.168.40.128/](http://192.168.40.128/)** in a browser.
4. Log in using one of the lab accounts:

| Username | Password | Access |
| --- | --- | --- |
| `admin` | `admin456` | Edit policy and access the demo |
| `operator` | `oper789` | Access paths allowed by the current policy |

**Login** keeps the Bearer token in that tab's memory. **Check Status** requests
`/api/status`; **Open /demo** requests the protected plain-text demo. **Logout**
clears the tab's token. Reloading the page also clears it.

These are public hardcoded lab credentials and signing keys. **TLS is deferred**,
so HTTP carries credentials and tokens unencrypted. Issued tokens do not expire;
logout does not revoke a copied token on the server.

## Demonstrate live policy enforcement

Use two tabs so admin and operator remain logged in independently:

1. In the first tab, log in as **admin**. The **Live policy — operator access**
   table contains toggles for `/demo` and `/api/status`.
2. In the second tab, log in as **operator** and click **Open /demo**. With the
   default policy, the response is **403 Forbidden**.
3. In the admin tab, enable **Allow operator** for `/demo` and wait for the success
   message. The dashboard reads back the committed policy.
4. Click **Open /demo** again in the operator tab. It now returns **200 OK** with
   `Content-Type: text/plain` and this body:

   ```text
   Policy gate demo: access allowed.
   ```

5. Disable the admin toggle and repeat the operator request. It returns **403**
   again, without restarting the board or logging in again.

The `/api/status` toggle works the same way. These controls change **operator**
access; admin retains access. Operator has no edit controls, and direct operator
policy-update requests are rejected by the server too.

Operator demo access starts disabled; operator status access starts enabled.
Policy changes live in RAM and reset on board restart. Logout does not reset them.
Use **Open /demo** in the dashboard: typing `/demo` into the address bar does not
attach the Bearer token and therefore returns 401.

## Available routes

| Method | Route | Purpose |
| --- | --- | --- |
| GET | `/` | Public dashboard |
| GET | `/dashboard.js` | Public dashboard JavaScript |
| POST | `/api/login` | Exchange lab credentials for a Bearer token |
| GET | `/api/status` | Policy-controlled status and caller role |
| GET | `/demo` | Policy-controlled plain-text demonstration |
| GET | `/api/policy` | Admin-only live rule readback |
| PUT | `/api/policy` | Admin-only atomic replacement using a 65-byte binary policy |
| POST | `/api/logout` | Policy-controlled success response; browser clears its token |

The dashboard handles token headers and policy encoding. See the
[dashboard/API guide](Gateway/DASHBOARD.md) for the wire format and limits.

## What we proved and what we tested

### Formal guarantees inherited from the generated core

- **F*/Low* extraction:** the original contracts cover memory safety and frame
  properties under caller preconditions, termination measures, and selected field
  bounds. They do not establish complete HTTP semantic correctness.
- **EverParse policy validation:** the validator checks its specified predicates
  on the supplied policy/access buffers, including admin policy upload and
  access checks involving path, method, role, scope, and rate attributes.
- **HACL*:** provides verified cryptographic primitives used by the handwritten
  credential and token protocol; it does not verify that whole protocol.

The generated algorithms were preserved. **No fresh F*/EverParse proof run was
performed for this port, and the complete STM32 firmware is not formally verified.**
The caller must still provide valid, correctly sized, stable, non-overlapping
buffers and trustworthy authentication attributes. The gateway task owns those
buffers and serializes request processing.

The new `/demo` route is a handwritten integration adapter: it uses the existing
extractor for header/body extraction, then supplies a distinct demo policy ID
before authentication and policy evaluation. It does not inherit `/api/status`
permissions. This mapping, HTTP framing, FreeRTOS scheduling, Ethernet integration,
and the dashboard are outside the generated proof boundary. See
[source provenance](Gateway/Provenance/) and the [route explanation](Gateway/DASHBOARD.md).

### Behavior demonstrated on the port

Recorded validation on **2026-09-12** established the following for the tested
build and workloads:

| Check | Result |
| --- | --- |
| Host AddressSanitizer/UndefinedBehaviorSanitizer suite | **287/287 passed** |
| Host suite with lab authentication disabled | **208/208 passed** |
| Debug and Release builds and post-link checks | Passed without compiler warnings |
| Clean Debug startup on the NUCLEO-F767ZI | **287/287 passed**, Ethernet and HTTP ready |
| On-board live-policy checks | **43/43 passed** |
| On-board dashboard/login checks | **129/129 passed** |
| Existing HTTP regression | **34/34 groups**, including **1,000 mixed requests** |
| Separate admin/operator browser tabs | Operator `/demo`: **403 → 200 → 403** |

Tests also demonstrated that an operator cannot update policy **even when an
uploaded rule appears to allow operator PUT access to `/api/policy`**. Rejected
updates preserve the policy. Tests covered malformed requests, fragmentation,
size limits, token tampering, timeouts, policy readback, and connection recovery.

All observed task-stack margins were healthy. The recorded workload reported no
log drops, network drops, TX errors, or lwIP allocation errors. These measurements
are not worst-case stack or timing proofs. Debug was flashed and tested for this
milestone; Release was built but not flashed.

See the [validation report](Gateway/LIVE_POLICY_VALIDATION.md) for firmware hashes,
resource measurements, and limits, and the [saved evidence](Gateway/Validation/live-policy-2026-09-12/)
for logs, test results, and a dashboard screenshot.

## Build and repeat validation

The maintained project uses STM32CubeIDE 2.0.0, its bundled STM32 GCC 13.3.1, and
STM32CubeF7 1.17.4. Tool scripts currently reference the documented local Linux
installation paths; adjust them for another machine. Close CubeIDE before a
headless build. From the repository root:

```sh
python3 Gateway/tools/check_project.py
python3 Gateway/tools/test_host.py --sanitize
python3 Gateway/tools/test_host.py --sanitize --lab-auth-off
python3 Gateway/tools/build_firmware.py
```

To explicitly flash the connected board and capture startup acceptance:

```sh
python3 Gateway/tools/board_test.py --config Debug --flash --output /tmp/pg-boot
```

USART3 serial diagnostics use **115200 baud, 8-N-1**. Close Minicom or other serial
readers before automated capture; only one reader should own the port.

With Ethernet connected and the default policy active:

```sh
python3 Gateway/tools/test_live_policy_network.py --output /tmp/pg-live-policy
python3 Gateway/tools/test_dashboard_network.py --output /tmp/pg-dashboard
python3 Gateway/tools/test_network.py --count 1000 --output /tmp/pg-regression
```

Policy tests temporarily edit and restore policy. Run them without concurrent
admin edits. After changing HTML or JavaScript, run
`python3 Gateway/tools/embed_dashboard.py`; the consistency checker rejects stale
embedded assets. After CubeMX regeneration, follow the
[network/build integration guide](Gateway/NETWORK.md).

## Remaining work

TLS, provisioned credentials and keys, token expiry/revocation, persistent policy
storage, and stateful rate windows remain unimplemented. Concurrent admin edits
use full-policy last-write-wins replacement; there is no revision precondition.
Physical Ethernet unplug/reconnect recovery and worst-case resource bounds are
not established by the recorded tests.
