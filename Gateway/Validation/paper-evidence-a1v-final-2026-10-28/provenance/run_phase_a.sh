#!/bin/bash
# Phase A of paper-evidence-d1-blob-2026-10-11/COMMANDS.md on the A1v primary image
# (GATEWAY_FAST_MEMOPS=1 default, a4fbff0), same order and arguments. No gdb
# update-cost, no Phase B. Every command, with start/end time and exit code, goes
# to run-status.log; the command lines go to COMMANDS.md.
R=/home/iamfo470/stm32-projects/policy_gate
N=v11-verified-gate-a1v
V=Gateway/Validation/paper-evidence-a1v-final-2026-10-28
E=$V/$N
P=/tmp/claude-1001/-home-iamfo470-stm32-projects-policy-gate/4f0c6d1e-fde2-456d-a8ba-eebd2a83a05f/scratchpad/pgtools
B=/tmp/claude-1001/-home-iamfo470-stm32-projects-policy-gate/4f0c6d1e-fde2-456d-a8ba-eebd2a83a05f/scratchpad/a1v-primary-build
cd $R || exit 1
LOG=$V/run-status.log
CMD=$V/COMMANDS.md
stamp() { date -Iseconds; }
note() { echo "[$(stamp)] $*" >> $LOG; }
# run <stdout-file> <command...>
run() {
  out=$1; shift
  echo "$* > $out" >> $CMD
  note "start: $*"
  "$@" > $out 2>&1
  rc=$?
  note "rc=$rc: $*"
  return $rc
}
if [ ! -f $CMD ]; then
  cat > $CMD <<EOF
# Commands run (cwd = repo root; P = $P, Gateway/tools at a4fbff0 with paths rewritten, see provenance/tool-path-rewrite.diff)
# Order and arguments are Phase A of paper-evidence-d1-blob-2026-10-11/COMMANDS.md; stdout and stderr of each go to the named file.
EOF
fi
echo "## Phase A $(stamp)" >> $CMD
note "PHASE A START"
run $B.stdout python3 $P/build_firmware.py --output $B || { note "STOP build"; exit 1; }
run $V/stage.stdout python3 $P/d1_stage_variant.py $N --build-log $B/build.log || { note "STOP stage"; exit 1; }
mkdir -p $E/release
cp -p Debug/policy_gate.map $E/policy_gate.map
cp -p Release/policy_gate.elf Release/policy_gate.map $E/release/
echo "cp Debug/policy_gate.map $E/; cp Release/policy_gate.{elf,map} $E/release/   # as final2/policy_gate.map and final2/release" >> $CMD
git checkout -- .settings/language.settings.xml 2>/dev/null
note "build-dirtied .settings/language.settings.xml restored"
run $E/board.stdout python3 $P/board_test.py --flash --elf $E/policy_gate.elf --output $E/board --expected-selftests 301 || { note "STOP board_test"; exit 1; }
run $E/network-suite.stdout python3 $P/paper_capture_command.py --output $E/network-suite-uart -- python3 $P/d1_demo_suite.py --output $E/network-suite -- python3 $P/test_network.py --count 200 --output $E/network-suite
run $E/live_policy-suite.stdout python3 $P/d1_demo_suite.py --output $E/live_policy-suite -- python3 $P/test_live_policy_network.py --output $E/live_policy-suite
run $E/dashboard-suite.stdout python3 $P/d1_demo_suite.py --output $E/dashboard-suite -- python3 $P/test_dashboard_network.py --output $E/dashboard-suite
run $E/attacks-r1.stdout python3 $P/paper_attack_r1_network.py --output $E/attacks-r1
run $E/soak-5000.stdout python3 $P/d1_demo_suite.py --output $E/soak -- python3 $P/r4_http_client_soak.py --count 5000 --output $E/soak/soak-5000.csv
A=$E/e-p1-audit-100000
mkdir -p $A
echo "python3 $P/paper_m4_network.py --count 100000 --output $A/load --elf-sha256-file $E/board/elf.sha256 > $A/load.stdout & (pid -> $A/load.pid); python3 $P/d1_hang_watch.py --elf $E/policy_gate.elf --output $A/watch --load-pid-file $A/load.pid > $A/watch.stdout" >> $CMD
note "start: audit (paper_m4_network --count 100000 + d1_hang_watch)"
python3 $P/paper_m4_network.py --count 100000 --output $A/load --elf-sha256-file $E/board/elf.sha256 > $A/load.stdout 2>&1 &
load=$!
echo $load > $A/load.pid
python3 $P/d1_hang_watch.py --elf $E/policy_gate.elf --output $A/watch --load-pid-file $A/load.pid > $A/watch.stdout 2>&1
watch_rc=$?
wait $load
load_rc=$?
note "rc=$load_rc (load) rc=$watch_rc (watch): audit"
run $E/socket-check-after-audit.stdout python3 $P/d1_socket_check.py --output $E/socket-check-after-audit --seconds 30 --elf $E/policy_gate.elf
mkdir -p $E/e-map
run $E/e-map/privileged-inventory.stdout python3 $P/d1_privileged_inventory.py $E/policy_gate.elf --output $E/e-map/privileged-inventory.json
note "PHASE A DONE"
