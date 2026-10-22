#!/bin/bash
# A1v (verified memops, 32-byte aligned; the new baseline) and A2v (A1v + ITCM), 2026-10-22.
# Builds sequentially (the build edits the shared header), then timing boots, deadline
# captures (no caller attribution) and isolation probes.
R=/home/iamfo470/stm32-projects/policy_gate; V=$R/Gateway/Validation/paper-evidence-timing-2026-10-21
P=/home/iamfo470/.claude/jobs/d4a23072/tmp/pgtim
B=$P/build_timing.py
cd $R
A1="GATEWAY_FAST_MEMOPS=1"; A2="GATEWAY_FAST_MEMOPS=1 GATEWAY_ITCM=1"
CTRL="GATEWAY_PAPER_GATE_N32=0 GATEWAY_PAPER_TIMING_DIST=0 GATEWAY_R4_CONTROL=1 GATEWAY_R4_CONTROL_HIGH=1 GATEWAY_R4_CRIT_RANK=0"
build() { # name flags...
  [ -f $V/$1/policy_gate.elf ] && { echo "have $1"; return; }
  timeout 1200 python3 $B "$@" > /tmp/pg-build-$1.out 2>&1
  echo "built $1 rc=$?"
}
# SCALANCE data for the timing variant: regenerate the data header, build, restore it.
if [ ! -f $V/a1v-timing-dist-scalance32/policy_gate.elf ]; then
  python3 Gateway/tools/gen_gate_n32_data.py --policy siemens-scalance-xb200 > /tmp/pg-gen-scalance.out 2>&1
  grep -m1 -o 'GATE_N32_POLICY "[^"]*"' Gateway/Paper/paper_gate_n32_data.h
  build a1v-timing-dist-scalance32 $A1
  git checkout -- Gateway/Paper/paper_gate_n32_data.h
fi
build a1v-timing-dist-opnsense53 $A1
build a2v-timing-dist-opnsense53 $A2
IMAGES=()
for hz in 1000 4000 10000; do for b in 0 1; do for v in a1v a2v; do
  case $v in a1v) f=$A1;; a2v) f=$A2;; esac
  n=$v-norank-control-$hz-bucket$b
  build $n $CTRL GATEWAY_R4_CONTROL_HZ=$hz GATEWAY_D1_TOKEN_BUCKET=$b $f
  IMAGES+=($n)
done; done; done
git checkout -- .settings/language.settings.xml 2>/dev/null
echo BUILDS_DONE
for img in a1v-timing-dist-opnsense53 a1v-timing-dist-scalance32 a2v-timing-dist-opnsense53; do
  E=$V/$img; first=1
  for i in 01 02 03 04 05 06 07 08 09 10; do
    [ -f $E/boot$i/uart-raw.log ] && grep -q 'GATE-DIST\] done' $E/boot$i/uart-raw.log && { echo "have $img boot$i"; continue; }
    if [ $first = 1 ]; then mode=--flash; first=0; else mode=--reset; fi
    timeout 300 python3 Gateway/tools/board_test.py $mode --elf $E/policy_gate.elf --output $E/boot$i --seconds 180 --expected-selftests 301 >/dev/null 2>&1
    echo "$img boot$i lines=$(grep -c 'GATE-DIST' $E/boot$i/uart-raw.log) done=$(grep -c 'GATE-DIST\] done' $E/boot$i/uart-raw.log) n32=$(grep -a -o 'mismatches=[0-9]* fail_closed=[0-9]*' $E/boot$i/uart-raw.log | head -1) faults=$(sed -n '/\[BOOT\] policy_gate/,$p' $E/boot$i/uart-raw.log | grep -c 'previous_fault')"
  done
done
echo TIMING_DONE
for img in "${IMAGES[@]}"; do
  D=$V/$img; first=1
  for sc in idle valid denied malformed; do
    [ -f $D/$sc.stdout ] && grep -q misses $D/$sc.stdout && { echo "have $img $sc"; continue; }
    if [ $first = 1 ]; then f=--flash; first=0; else f=; fi
    timeout 400 python3 Gateway/tools/r4_control_capture.py --elf $D/policy_gate.elf $f --scenario $sc --d1 --output $D/$sc >$D/$sc.stdout 2>&1
    echo "$img $sc rc=$? $(grep -a -o 'misses=[0-9]* lost_releases=[0-9]*' $D/$sc/uart.bin 2>/dev/null | head -1) $(grep -a -o 'critical_max_cycles=[0-9]*' $D/$sc/uart.bin 2>/dev/null | head -1)"
  done
done
echo CONTROL_DONE
python3 $P/v_run_probes.py a1v > $P/a1v_probes.log 2>&1; echo "a1v probes rc=$?"
python3 $P/v_run_probes.py a2v > $P/a2v_probes.log 2>&1; echo "a2v probes rc=$?"
git checkout -- .settings/language.settings.xml 2>/dev/null
echo ALLDONE
