#!/bin/bash
# Functional F767 campaign on the glue/opn64-primary Debug image (n=64 store, 500 ms window).
# Board already holds the flashed image (board/). Suites run sequentially (one
# serial/board user at a time). Never sends RESET. LAN 192.168.40.128 via enp44s0.
set -u
R=/home/iamfo470/stm32-projects/policy_gate
V=$R/Gateway/Validation/opn64-campaign-2026-10-29
T=$R/Gateway/tools
cd $R || exit 1
LOG=$V/run-status.log
stamp(){ date -Iseconds; }
run(){ out=$1; shift; echo "[$(stamp)] start: $*" >>$LOG; "$@" >"$out" 2>&1; rc=$?; echo "[$(stamp)] rc=$rc: $*" >>$LOG; }
echo "[$(stamp)] CAMPAIGN START (opn64-primary Debug, 354 self-tests)" >>$LOG

run $V/network-suite.stdout python3 $T/paper_capture_command.py --output $V/network-suite-uart -- \
  python3 $T/d1_demo_suite.py --output $V/network-suite -- python3 $T/test_network.py --count 200 --output $V/network-suite
run $V/live_policy-suite.stdout python3 $T/d1_demo_suite.py --output $V/live_policy-suite -- python3 $T/test_live_policy_network.py --output $V/live_policy-suite
run $V/dashboard-suite.stdout python3 $T/d1_demo_suite.py --output $V/dashboard-suite -- python3 $T/test_dashboard_network.py --output $V/dashboard-suite
run $V/attacks-r1.stdout python3 $T/paper_attack_r1_network.py --output $V/attacks-r1
run $V/soak-5000.stdout python3 $T/d1_demo_suite.py --output $V/soak -- python3 $T/r4_http_client_soak.py --count 5000 --output $V/soak/soak-5000.csv
mkdir -p $V/e-map
run $V/e-map/privileged-inventory.stdout python3 $T/d1_privileged_inventory.py $V/board/policy_gate.elf --output $V/e-map/privileged-inventory.json
A=$V/audit-100k; mkdir -p $A
echo "[$(stamp)] start: audit 100000 (transport-tolerant) + hang watch" >>$LOG
python3 $T/paper_m4_network.py --count 100000 --output $A/load --elf-sha256-file $V/board/elf.sha256 >$A/load.stdout 2>&1 &
load=$!; echo $load >$A/load.pid
python3 $T/d1_hang_watch.py --elf $V/board/policy_gate.elf --output $A/watch --load-pid-file $A/load.pid --max-hours 2 >$A/watch.stdout 2>&1
wait $load; echo "[$(stamp)] rc=$? audit 100000" >>$LOG
run $V/socket-check.stdout python3 $T/d1_socket_check.py --output $V/socket-check --seconds 20 --elf $V/board/policy_gate.elf
echo "[$(stamp)] CAMPAIGN FUNCTIONAL DONE" >>$LOG
