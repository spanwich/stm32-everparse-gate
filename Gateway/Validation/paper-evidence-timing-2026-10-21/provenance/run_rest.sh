#!/bin/bash
R=/home/iamfo470/stm32-projects/policy_gate; V=$R/Gateway/Validation/paper-evidence-timing-2026-10-21
cd $R
E=$V/timing-dist-scalance32
for i in 01 02 03 04 05 06 07 08 09 10; do
  if [ $i = 01 ]; then mode=--flash; else mode=--reset; fi
  timeout 300 python3 Gateway/tools/board_test.py $mode --elf $E/policy_gate.elf --output $E/boot$i --seconds 180 --expected-selftests 301 >/dev/null 2>&1
  echo "scalance boot$i lines=$(grep -c 'GATE-DIST' $E/boot$i/uart-raw.log 2>/dev/null) done=$(grep -c 'GATE-DIST\] done' $E/boot$i/uart-raw.log 2>/dev/null)"
done
for img in crit-control-1000-bucket1 crit-control-1000-bucket0; do
  D=$V/$img; first=1
  for sc in idle valid denied malformed; do
    if [ $first = 1 ]; then f=--flash; first=0; else f=; fi
    timeout 400 python3 Gateway/tools/r4_control_capture.py --elf $D/policy_gate.elf $f --scenario $sc --d1 --output $D/$sc >$D/$sc.stdout 2>&1
    echo "$img $sc rc=$? crit=$(grep -o 'critical_max_cycles=[0-9]*' $D/$sc/uart*.log 2>/dev/null | head -1) ranks=$(grep -c '\[CRIT\]' $D/$sc/uart*.log 2>/dev/null | head -1)"
  done
done
echo ALLDONE
