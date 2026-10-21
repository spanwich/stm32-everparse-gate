#!/bin/bash
# Deadline matrix without caller attribution (GATEWAY_R4_CRIT_RANK=0): the attribution
# observer runs with interrupts masked and inflates release latency, so miss counts come
# from these images; attribution images are used only for "who" and section durations.
R=/home/iamfo470/stm32-projects/policy_gate; V=$R/Gateway/Validation/paper-evidence-timing-2026-10-21
B=/home/iamfo470/.claude/jobs/d4a23072/tmp/pgtim/build_timing.py
cd $R
A1="GATEWAY_FAST_MEMOPS=1"; A2="GATEWAY_FAST_MEMOPS=1 GATEWAY_ITCM=1"
CTRL="GATEWAY_PAPER_GATE_N32=0 GATEWAY_PAPER_TIMING_DIST=0 GATEWAY_R4_CONTROL=1 GATEWAY_R4_CONTROL_HIGH=1 GATEWAY_R4_CRIT_RANK=0"
IMAGES=()
for hz in 1000 4000 10000; do for b in 0 1; do for v in a0 a1 a2; do
  case $v in a0) f="";; a1) f=$A1;; a2) f=$A2;; esac
  n=$v-norank-control-$hz-bucket$b
  if [ ! -f $V/$n/policy_gate.elf ]; then
    timeout 1200 python3 $B $n $CTRL GATEWAY_R4_CONTROL_HZ=$hz GATEWAY_D1_TOKEN_BUCKET=$b $f > /tmp/pg-build-$n.out 2>&1
    echo "built $n rc=$?"
  fi
  IMAGES+=($n)
done; done; done
echo BUILDS_DONE
for img in "${IMAGES[@]}"; do
  D=$V/$img; first=1
  for sc in idle valid denied malformed; do
    [ -f $D/$sc.stdout ] && grep -q misses $D/$sc.stdout && { echo "have $img $sc"; continue; }
    if [ $first = 1 ]; then f=--flash; first=0; else f=; fi
    timeout 400 python3 Gateway/tools/r4_control_capture.py --elf $D/policy_gate.elf $f --scenario $sc --d1 --output $D/$sc >$D/$sc.stdout 2>&1
    echo "$img $sc rc=$? $(tail -1 $D/$sc.stdout | grep -o '"misses": [0-9]*\|"max_cycles": [0-9]*' | tr '\n' ' ')"
  done
done
echo ALLDONE
