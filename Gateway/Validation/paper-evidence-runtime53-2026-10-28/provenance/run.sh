#!/bin/bash
# Runtime-53 on-board campaign (2026-10-28). Flash the variant, confirm boot +
# 301 self-tests, run the HTTP load/equiv/e2e/timing driver (UART captured,
# read-only), take the privileged inventory, then re-flash the committed A1v
# primary image. F767 only via the stable ST-LINK path; nothing sent over serial.
set -u
R=/home/iamfo470/stm32-projects/policy_gate
V=Gateway/Validation/paper-evidence-runtime53-2026-10-28
N=v11-verified-gate-runtime53
E=$V/$N
T=Gateway/tools
A1V=Gateway/Validation/paper-evidence-a1v-final-2026-10-28/v11-verified-gate-a1v/policy_gate.elf
cd $R || exit 1
LOG=$V/run-status.log
CMD=$V/COMMANDS.md
stamp(){ date -Iseconds; }
note(){ echo "[$(stamp)] $*" >> $LOG; }
run(){ out=$1; shift; echo "$* > $out" >> $CMD; note "start: $*"; "$@" > "$out" 2>&1; rc=$?; note "rc=$rc: $*"; return $rc; }
if [ ! -f $CMD ]; then cat > $CMD <<EOF
# Commands run (cwd = repo root). Nothing is sent over the serial port; UART is captured read-only.
EOF
fi
echo "## Runtime-53 $(stamp)" >> $CMD
note "RUN START"

run $E/board.stdout python3 $T/board_test.py --flash --elf $E/policy_gate.elf --output $E/board --seconds 30 --expected-selftests 301 || note "WARN board_test rc nonzero"

# Wait for the HTTP listener, then run the driver under UART capture.
note "wait for /gate53 ready"
ready=0
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://192.168.40.128/gate53?op=status" 2>/dev/null)
  if [ "$code" = "200" ]; then ready=1; note "ready after ${i}s"; break; fi
  sleep 1
done
[ $ready = 1 ] || note "WARN endpoint not ready after 30s"

run $E/runtime53.stdout python3 $T/paper_capture_command.py --output $E/runtime53-uart -- \
  python3 $T/runtime53_load.py --output $E/runtime53 --host 192.168.40.128
RUN_RC=$?
note "runtime53_load rc=$RUN_RC"

mkdir -p $E/e-map
run $E/e-map/privileged-inventory.stdout python3 $T/d1_privileged_inventory.py $E/policy_gate.elf --output $E/e-map/privileged-inventory.json

note "re-flash committed A1v primary image"
run $V/reflash-a1v.stdout python3 $T/board_test.py --flash --elf $A1V --output $V/reflash-a1v --seconds 20 --expected-selftests 301 || note "WARN reflash rc nonzero"
note "RUN DONE"
