Historical login-port evidence. Current firmware: [LIVE_POLICY_VALIDATION.md](LIVE_POLICY_VALIDATION.md).

# Dashboard/login validation — 2026-09-12

The **Debug firmware is installed and serving http://192.168.40.128/** on the
NUCLEO-F767ZI. Release was built and checked, but was not flashed in this milestone.
TLS remains deferred. See `DASHBOARD.md` for account and logout semantics.

## Accepted checks

- Host ASan/UBSan: **265/265** checks, including all 119 original extractor vectors.
- Host ASan/UBSan with `GATEWAY_LAB_AUTH=0`: **203/203** checks. Valid issued tokens,
  static fixtures and username/password login are rejected; the page is public.
- Debug and Release: no compiler warnings/errors; post-link checks passed for
  generated `-Os`, extractor recursion, required authentication functions, strong
  hooks, and Ethernet DMA placement. HACL/extractor/EverParse algorithms unchanged.
- ST-LINK programming and verification of Debug succeeded.
- Board HTTP dashboard/login suite: **128/128** checks, including exact HTML bytes,
  independently computed HMAC tokens, both roles, malformed JSON/password bounds,
  tampered tokens, logout semantics and 100 authenticated requests (1.600 seconds).
- Existing board HTTP regression: **34/34** groups including **1,000** mixed requests
  (13.010 seconds), policy updates/rollback, fragmentation, size limits, timeouts,
  queueing and software connection reset recovery. Default RAM policy restored.
- Actual browser: admin login/status/logout, post-logout rejection by the UI,
  operator login/status, wrong-password rejection, reload clears token, password
  field cleared, localStorage/sessionStorage remain empty, no JavaScript exceptions.
  Mobile viewport 390x844 has no horizontal overflow. The browser requests an
  unimplemented favicon and receives 400; intentional failed-login tests return 401.

## Clean boot and under-load UART acceptance

After the user closed Minicom, the installed Debug firmware was reset without
reflashing. The clean UART capture passed **265/265 startup tests**, listener/link
startup and heartbeat acceptance. The dashboard/network suite then passed
**128/128** again while a single UART reader captured diagnostics.

| Task | Minimum observed free stack (bytes) |
| --- | ---: |
| Gateway | 5268 |
| Diagnostics | 876 |
| TCP/IP | 3180 |
| Ethernet input | 3772 |
| Link monitor | 932 |

All reported margins were OK. FreeRTOS heap returned to 60768 bytes free, with
60384 bytes minimum; lwIP heap returned to zero used with 4620 bytes peak.
No reported log drops, network drops, TX errors or lwIP allocation errors.
These are observed workload measurements, not worst-case stack bounds.

The earlier fragmented capture is retained as historical evidence; the serial
contention limitation is resolved. Reset-only tooling does not independently
verify flash contents; the prior successful programming/verification record and
installed-image hash remain the firmware provenance.

## Images and resources

| Configuration | text | data | bss |
| --- | ---: | ---: | ---: |
| Debug | 176832 | 112 | 175272 |
| Release | 121932 | 116 | 175256 |

Dashboard: **3600 bytes**, embedded read-only; full response fits the existing
4096-byte transport buffer. Existing task stack/heap/DMA budgets were retained.
Debug known-frame call sums: login 1096 bytes, token validation 896 bytes. These
exclude unknown library/assembly/interrupt costs and are not worst-case bounds.

- Installed Debug ELF SHA-256:
  `51ef7f1d7799a264e8f6b0201ccabf6db6d2577a0dc680d16775b240354e2673`
- Build-only Release ELF SHA-256:
  `3542f6c494fcdba131162edeae1c2a27c0b6bb1a143fa472c1fc52b4a5d9a1a7`
- Dashboard SHA-256:
  `d885ffbebfeb7303a83862088f63c80754d121b13787318bdc7fd5433a50cac7`

Evidence: `Gateway/Validation/dashboard-2026-09-12/`. The fragmented UART log is
named explicitly. Backup before implementation:
`/tmp/policy-gate-dashboard-5z6x_98e/before.tar.gz` (excludes generated build outputs).
The staged installed ELF remains `/tmp/pg-dashboard-debug-boot/policy_gate.elf`.
Compiler: CubeIDE STM32 GCC 13.3.1; the unchanged project still uses 96 MHz clocks.

No TLS, account provisioning, expiring/revocable tokens, hardware entropy,
stateful rate windows, physical cable-recovery test, or fresh formal verification
was added or claimed in this milestone.
