Kept, not deleted: development runs of the on-board flood task (paper_flood.c), superseded by ../flood-{1000,4000,10000}.
- flood-1000-lowprio-run1 / run2: flood task at osPriorityLow / BelowNormal while the boot self-tests were still running:
  the self-tests (synthetic clock, rate-counter resets) overlapped the flood (counts jumped, tick=100000), starving it.
  Fixed by waiting for gateway_platform_tests_complete().
- flood-1000-selftest-overlap: run2's directory after the diagnostic build.
- flood-first-attempts-window-log-bug: after the self-test fix, windows were not logged because the "previous count"
  sentinel (255) collided with the rate counter's capped value 255; fixed with a signed sentinel.
