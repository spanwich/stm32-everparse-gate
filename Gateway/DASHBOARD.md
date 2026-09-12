# Dashboard and lab login port

Open **http://192.168.40.128/**. This page is adapted from the active original
`components/FStarExtractor/dashboard.html`, with inline CSS and board-hosted `/dashboard.js` (no third-party dependencies).
HTML (2935 bytes) and JavaScript (4386 bytes) are embedded in flash, served only
after complete HTTP framing validation, using the existing single-connection
server. Larger static responses stream from flash with a two-second absolute
send deadline; the 4096-byte request buffer is unchanged.

| Account | Password | Role | Scope |
| --- | --- | --- | --- |
| admin | admin456 | Admin | 0x003f |
| operator | oper789 | Operator | 0x0003 |

Click **Login**, then **Check Status**. **Logout** calls the policy-controlled
`POST /api/logout` endpoint and clears this page's token even if the request fails.
Reloading/closing the page also loses its in-memory token. There is no persistent
browser storage or cookie. The original server logout response does not revoke
an issued token: a copied token remains valid. This port preserves that behavior.

## Live admin policy editing

1. Log in as admin. The **Live policy — operator access** table shows the current
   policy for `GET /demo` and `GET /api/status`.
2. Toggle **Allow operator** on `/demo`; the change takes effect immediately.
3. In a second tab, log in as operator and click **Open /demo**. Allowed requests
   return `text/plain`: `Policy gate demo: access allowed.`
4. Turn the admin toggle off and repeat the operator request: it returns **403**.
   Admin keeps access to the route. Operator has no policy controls and receives
   403 if it attempts the policy API directly.

Operator demo access starts **disabled**; operator status access starts enabled.
Both settings reset on board restart. Logout does not reset policy.
The demo button sends the current Bearer token; entering `/demo` in the address
bar alone does not attach that token and returns 401.

`GET /api/policy` now returns the live `rules` array. Each rule has numeric `id`,
`method`, `min_role`, and `scope` fields. GET is restricted to admin at the HTTP
boundary as well as being checked by the live policy. PUT remains the original
65-byte binary upload, with admin authorization enforced by EverParse even if an
uploaded rule appears to grant operator access to PUT policy.

The UI reads current rules immediately before editing, replaces GET rules only
for the selected path, preserves unrelated rules, and uses minimum role 1 when
allowed or 2 when denied, with scope 1. It reads back the committed policy before
showing success. Uploads are atomic in the single owner task. Concurrent admin
editors still use last-write-wins full-policy replacement; there is no revision
precondition. Custom binary policies that remove admin policy-read permission
can prevent UI readback; an authorized binary PUT can restore the default rules.

`/demo` is an exact GET-only **handwritten integration route**, ID `0x55555555`
in `gateway_routes.h`. Its request line is normalized to `/api/status` solely
for the unchanged extractor's header/body extraction; the adapter then sets the
distinct demo ID before authentication and EverParse access evaluation. It never
uses the status rule to authorize demo access. Lookalikes, query suffixes and
non-GET demo requests are rejected. No generated path sentinel or algorithm was
edited; this route mapping is outside the generated extractor's proof boundary.

## API

`POST /api/login` accepts a JSON object containing exactly `username` and
`password`, in either order, with optional JSON whitespace. Decoded strings must
be nonempty printable ASCII; username <=32 bytes and password <=64 bytes.
Escaped quotes, backslashes, slashes and ASCII `\uXXXX` escapes are supported.
Unknown/duplicate fields, malformed/truncated JSON, trailing bytes, controls,
non-ASCII values and overlong fields return 400. Invalid credentials return 401.
Existing transport limits and Content-Length requirements still apply.

Success returns `{"status":"ok","token":"..."}`. Use that value in
`Authorization: Bearer <token>` for `/api/status`, `/api/policy`, and `/api/logout`.
The dashboard attaches the header automatically. Responses use Content-Length,
Connection: close and Cache-Control: no-store. Default policy allows both roles
to read status and log out; policy read/update requires admin.

Tokens retain the original HMAC-SHA256 claim layout, with **hyphens** instead of
colons between hex fields so the wire value passes the existing Bearer parser:
`subject_hex-role_hex-scope_le_hex-hmac_hex`. The HMAC input remains
`subject || role_byte || scope_little_endian`. Legacy colon-formatted tokens are
rejected. No generated HTTP extractor or EverParse algorithm was changed.

The three earlier `pg-lab-*` Bearer fixtures remain available for compatibility
and regression tests. `GATEWAY_LAB_AUTH=0` disables those fixtures, login, and
issued-token authentication; the public dashboard remains available.

## Scope and provenance

TLS is deliberately deferred. Accounts and signing key are public hardcoded lab
fixtures inherited from the reference. Tokens are deterministic, have no expiry
or revocation, and issued-token requests currently use rate value zero. This is
not credential provisioning or a stateful rate-limiter milestone.

`Gateway/Auth` contains adapted handwritten credential and token helpers. The
password bound is now enforced in the credential helper itself; digest comparison
visits all digest bytes. Login parsing uses explicit byte lengths. Local password
and hash buffers are cleared, and login request/security buffers are wiped after
processing. `Gateway/Core/gateway_clear.c` supplies the volatile-store HACL
secure-clear runtime hook.

`Gateway/Generated/Auth` preserves the reference HACL crypto and headers unchanged;
CubeIDE builds generated code with -Os in both configurations. Source hashes,
reference copies, and handwritten adaptation patches are in
`Gateway/Provenance/auth.json` and `auth-reference/`. No fresh formal proof run was
performed. Crypto primitives do not verify the surrounding authentication protocol.

## Build and validation

After editing the page, run `python3 Gateway/tools/embed_dashboard.py`; the
consistency check rejects stale embedded HTML or a static asset above the 16 KiB bound.
Run `configure_project.py` after CubeMX regeneration as before.

```sh
python3 Gateway/tools/check_project.py
python3 Gateway/tools/test_host.py --sanitize
python3 Gateway/tools/test_host.py --sanitize --lab-auth-off
python3 Gateway/tools/build_firmware.py
python3 Gateway/tools/board_test.py --config Debug --flash --output /tmp/pg-dashboard-boot
python3 Gateway/tools/test_dashboard_network.py --output /tmp/pg-dashboard-network
python3 Gateway/tools/test_live_policy_network.py --output /tmp/pg-live-policy-network
python3 Gateway/tools/test_network.py --count 1000 --output /tmp/pg-network-regression
```

Deployment explicitly flashes/resets the connected board. Network regression
changes and restores RAM policy; do not run concurrently with policy writers.
The dashboard suite does not change policy and assumes its default rules.
The live-policy suite snapshots and restores its initial policy.
See `LIVE_POLICY_VALIDATION.md` for current results and remaining limits;
`DASHBOARD_VALIDATION.md` retains the earlier login-port evidence.
