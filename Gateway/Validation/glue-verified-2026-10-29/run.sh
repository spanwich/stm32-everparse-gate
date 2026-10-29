#!/bin/bash
# On-board validation of the verified-glue integration (0c413fc), Debug + 2 KB
# reset stack. The board already holds the flashed Debug image (board/). Runs the
# brief's suites. Never sends RESET (would reboot the MP255). UART captured
# read-only; LAN 192.168.40.128 via enp44s0; no host network changes.
set -u
R=/home/iamfo470/stm32-projects/policy_gate
V=$R/Gateway/Validation/glue-verified-2026-10-29
T=$R/Gateway/tools
cd $R || exit 1
LOG=$V/run-status.log
stamp(){ date -Iseconds; }
run(){ out=$1; shift; echo "[$(stamp)] start: $*" >>$LOG; "$@" >"$out" 2>&1; rc=$?; echo "[$(stamp)] rc=$rc: $*" >>$LOG; }
echo "[$(stamp)] CAMPAIGN START (board has Debug glue image)" >>$LOG

run $V/network-suite.stdout python3 $T/paper_capture_command.py --output $V/network-suite-uart -- \
  python3 $T/d1_demo_suite.py --output $V/network-suite -- python3 $T/test_network.py --count 200 --output $V/network-suite
run $V/live_policy-suite.stdout python3 $T/d1_demo_suite.py --output $V/live_policy-suite -- python3 $T/test_live_policy_network.py --output $V/live_policy-suite
run $V/dashboard-suite.stdout python3 $T/d1_demo_suite.py --output $V/dashboard-suite -- python3 $T/test_dashboard_network.py --output $V/dashboard-suite
run $V/attacks-r1.stdout python3 $T/paper_attack_r1_network.py --output $V/attacks-r1
run $V/soak-5000.stdout python3 $T/d1_demo_suite.py --output $V/soak -- python3 $T/r4_http_client_soak.py --count 5000 --output $V/soak/soak-5000.csv
mkdir -p $V/e-map
run $V/e-map/privileged-inventory.stdout python3 $T/d1_privileged_inventory.py $V/board/policy_gate.elf --output $V/e-map/privileged-inventory.json
# Short audit (5000) with hang watch; the 100k is a separate step if time allows.
A=$V/audit-5000; mkdir -p $A
echo "[$(stamp)] start: audit 5000 (paper_m4 + hang watch)" >>$LOG
python3 $T/paper_m4_network.py --count 5000 --output $A/load --elf-sha256-file $V/board/elf.sha256 >$A/load.stdout 2>&1 &
load=$!; echo $load >$A/load.pid
python3 $T/d1_hang_watch.py --elf $V/board/policy_gate.elf --output $A/watch --load-pid-file $A/load.pid >$A/watch.stdout 2>&1
wait $load; echo "[$(stamp)] rc=$? audit 5000" >>$LOG
run $V/socket-check.stdout python3 $T/d1_socket_check.py --output $V/socket-check --seconds 20 --elf $V/board/policy_gate.elf
echo "[$(stamp)] CAMPAIGN CORE DONE" >>$LOG
