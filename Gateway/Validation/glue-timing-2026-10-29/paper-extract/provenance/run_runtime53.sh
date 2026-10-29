#!/bin/bash
# Runtime-53 re-run on glue/verified (GlueLowMediate n=53, 322 self-tests). Never RESET.
set -u
cd /home/iamfo470/stm32-projects/policy_gate
V=Gateway/Validation/glue-timing-2026-10-29/runtime53; N=v11-runtime53-glue; E=$V/$N; T=Gateway/tools
mkdir -p $V; LOG=$V/run-status.log; note(){ echo "[$(date -Iseconds)] $*" >>$LOG; }
note START
python3 $T/d1_build_runtime53.py --name $N --evidence Gateway/Validation/glue-timing-2026-10-29/runtime53 --build /tmp/runtime53-build-glue >$V/build.stdout 2>&1; note "build rc=$?"
git checkout -- Gateway/Inc/paper_experiment.h .settings/language.settings.xml 2>/dev/null
python3 $T/board_test.py --flash --elf $E/policy_gate.elf --output $E/board --seconds 30 --expected-selftests 322 >$E/board.stdout 2>&1; note "board rc=$?"
ready=0
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://192.168.40.128/gate53?op=status" 2>/dev/null)
  [ "$code" = "200" ] && { ready=1; note "ready after ${i}s"; break; }; sleep 1
done
[ $ready = 1 ] || note "WARN endpoint not ready"
python3 $T/paper_capture_command.py --output $E/runtime53-uart -- python3 $T/runtime53_load.py --output $E/runtime53 --host 192.168.40.128 --admin pg-lab-admin --operator pg-lab-operator >$E/runtime53.stdout 2>&1; note "load rc=$?"
mkdir -p $E/e-map
python3 $T/d1_privileged_inventory.py $E/policy_gate.elf --output $E/e-map/privileged-inventory.json >$E/e-map/privileged-inventory.stdout 2>&1; note "inventory rc=$?"
note RUNTIME53_DONE
