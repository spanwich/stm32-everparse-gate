#!/bin/bash
# A0/A1/A2 campaign (2026-10-22): build all images (sequentially; the build edits the
# shared header), then 10 timing boots for A1 and A2, then the control matrix
# (1/4/10 kHz x token bucket 0/1, four loads each) with critical-section attribution.
R=/home/iamfo470/stm32-projects/policy_gate; V=$R/Gateway/Validation/paper-evidence-timing-2026-10-21
B=/home/iamfo470/.claude/jobs/d4a23072/tmp/pgtim/build_timing.py
cd $R
A1="GATEWAY_FAST_MEMOPS=1"; A2="GATEWAY_FAST_MEMOPS=1 GATEWAY_ITCM=1"
CTRL="GATEWAY_PAPER_GATE_N32=0 GATEWAY_PAPER_TIMING_DIST=0 GATEWAY_R4_CONTROL=1 GATEWAY_R4_CONTROL_HIGH=1"
build() { # name flags...
  [ -f $V/$1/policy_gate.elf ] && { echo "have $1"; return; }
  timeout 1200 python3 $B "$@" > /tmp/pg-build-$1.out 2>&1
  echo "built $1 rc=$? $(tail -1 /tmp/pg-build-$1.out | cut -c1-120)"
}
build a1-timing-dist-opnsense53 $A1
IMAGES=()
for hz in 1000 4000 10000; do for b in 0 1; do
  for v in a0 a1 a2; do
    [ $v = a0 ] && [ $hz = 1000 ] && { IMAGES+=(crit-control-1000-bucket$b); continue; }
    case $v in a0) f="";; a1) f=$A1;; a2) f=$A2;; esac
    n=$v-crit-control-$hz-bucket$b; [ $v = a0 ] && n=crit-control-$hz-bucket$b
    build $n $CTRL GATEWAY_R4_CONTROL_HZ=$hz GATEWAY_D1_TOKEN_BUCKET=$b $f
    IMAGES+=($n)
  done
done; done
echo BUILDS_DONE
for img in a1-timing-dist-opnsense53 a2-timing-dist-opnsense53; do
  E=$V/$img
  first=1
  for i in 01 02 03 04 05 06 07 08 09 10; do
    [ -f $E/boot$i/uart-raw.log ] && grep -q 'GATE-DIST\] done' $E/boot$i/uart-raw.log && { echo "have $img boot$i"; continue; }
    if [ $first = 1 ]; then mode=--flash; first=0; else mode=--reset; fi
    timeout 300 python3 Gateway/tools/board_test.py $mode --elf $E/policy_gate.elf --output $E/boot$i --seconds 180 --expected-selftests 301 >/dev/null 2>&1
    echo "$img boot$i lines=$(grep -c 'GATE-DIST' $E/boot$i/uart-raw.log) done=$(grep -c 'GATE-DIST\] done' $E/boot$i/uart-raw.log) resets=$(grep -c 'previous_fault' $E/boot$i/uart-raw.log)"
  done
done
for img in "${IMAGES[@]}"; do
  D=$V/$img; first=1
  for sc in idle valid denied malformed; do
    [ -f $D/$sc.stdout ] && grep -q misses $D/$sc.stdout && { echo "have $img $sc"; continue; }
    if [ $first = 1 ]; then f=--flash; first=0; else f=; fi
    timeout 400 python3 Gateway/tools/r4_control_capture.py --elf $D/policy_gate.elf $f --scenario $sc --d1 --output $D/$sc >$D/$sc.stdout 2>&1
    echo "$img $sc rc=$? $(tail -1 $D/$sc.stdout | cut -c1-200)"
  done
done
echo ALLDONE
