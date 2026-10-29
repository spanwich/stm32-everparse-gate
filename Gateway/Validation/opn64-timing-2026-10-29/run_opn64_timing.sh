#!/bin/bash
# Timing campaign on glue/opn64-primary (n=64 store): A0/A1v/A2v decision-time distributions,
# critical sections and deadline matrix. Idempotent (skip-if-done), redirected to this
# new dir; paper-evidence-timing-2026-10-21 untouched. Never RESET. 354 self-tests.
set -u
R=/home/iamfo470/stm32-projects/policy_gate
V=$R/Gateway/Validation/opn64-timing-2026-10-29
PG=/home/iamfo470/stm32-projects/policy_gate/Gateway/Validation/opn64-timing-2026-10-29/provenance
B=$PG/build_timing.py
T=$R/Gateway/tools
cd $R || exit 1
LOG=$V/timing-run.log
stamp(){ date -Iseconds; }
A1="GATEWAY_FAST_MEMOPS=1"; A2="GATEWAY_FAST_MEMOPS=1 GATEWAY_ITCM=1"   # A0 passes GATEWAY_FAST_MEMOPS=0
CTRL="GATEWAY_PAPER_GATE_N32=0 GATEWAY_PAPER_TIMING_DIST=0 GATEWAY_R4_CONTROL=1 GATEWAY_R4_CONTROL_HIGH=1"
build(){ name=$1; shift; [ -f $V/$name/policy_gate.elf ] && { echo "[$(stamp)] have $name" >>$LOG; return; }; timeout 1200 python3 $B $name "$@" >/tmp/pgt-$name.out 2>&1; echo "[$(stamp)] built $name rc=$?" >>$LOG; }
echo "[$(stamp)] TIMING CAMPAIGN START" >>$LOG

# ---- control images (A0 crit+norank, A1v norank, A2v norank) ----
for hz in 1000 4000 10000; do for b in 0 1; do
  build crit-control-$hz-bucket$b       $CTRL GATEWAY_FAST_MEMOPS=0 GATEWAY_R4_CONTROL_HZ=$hz GATEWAY_D1_TOKEN_BUCKET=$b
  build a0-norank-control-$hz-bucket$b   $CTRL GATEWAY_FAST_MEMOPS=0 GATEWAY_R4_CRIT_RANK=0 GATEWAY_R4_CONTROL_HZ=$hz GATEWAY_D1_TOKEN_BUCKET=$b
  build a1v-norank-control-$hz-bucket$b  $CTRL $A1 GATEWAY_R4_CRIT_RANK=0 GATEWAY_R4_CONTROL_HZ=$hz GATEWAY_D1_TOKEN_BUCKET=$b
  build a2v-norank-control-$hz-bucket$b  $CTRL $A2 GATEWAY_R4_CRIT_RANK=0 GATEWAY_R4_CONTROL_HZ=$hz GATEWAY_D1_TOKEN_BUCKET=$b
done; done
# ---- timing-dist images ----
build timing-dist-opnsense53     GATEWAY_FAST_MEMOPS=0
build a1v-timing-dist-opnsense53 $A1
build a2v-timing-dist-opnsense53 $A2
git checkout -- .settings/language.settings.xml 2>/dev/null
echo "[$(stamp)] BUILDS_DONE" >>$LOG

# ---- control captures (24 images x 4 scenarios; flash first, reset rest) ----
for img in crit-control-{1000,4000,10000}-bucket{0,1} a0-norank-control-{1000,4000,10000}-bucket{0,1} a1v-norank-control-{1000,4000,10000}-bucket{0,1} a2v-norank-control-{1000,4000,10000}-bucket{0,1}; do
  D=$V/$img; [ -f $D/policy_gate.elf ] || { echo "[$(stamp)] MISSING build $img" >>$LOG; continue; }
  first=1
  for sc in idle valid denied malformed; do
    [ -f $D/$sc/summary.json ] && { continue; }
    if [ $first = 1 ]; then f=--flash; first=0; else f=; fi
    timeout 400 python3 $T/r4_control_capture.py --elf $D/policy_gate.elf $f --scenario $sc --d1 --output $D/$sc >$D/$sc.stdout 2>&1
    echo "[$(stamp)] $img $sc rc=$? $(grep -ao '\"misses\": [0-9]*\|\"max_cycles\": [0-9]*' $D/$sc/summary.json 2>/dev/null | tr '\n' ' ')" >>$LOG
  done
done
echo "[$(stamp)] CONTROL_DONE" >>$LOG

# ---- timing-dist boots (10 each; flash first, reset rest) ----
for img in timing-dist-opnsense53 a1v-timing-dist-opnsense53 a2v-timing-dist-opnsense53; do
  E=$V/$img; [ -f $E/policy_gate.elf ] || { echo "[$(stamp)] MISSING build $img" >>$LOG; continue; }
  first=1
  for i in 01 02 03 04 05 06 07 08 09 10; do
    [ -f $E/boot$i/uart-raw.log ] && grep -q 'GATE-DIST\] done' $E/boot$i/uart-raw.log && { continue; }
    if [ $first = 1 ]; then mode=--flash; first=0; else mode=--reset; fi
    timeout 300 python3 $T/board_test.py $mode --elf $E/policy_gate.elf --output $E/boot$i --seconds 180 --expected-selftests 354 >/dev/null 2>&1
    echo "[$(stamp)] $img boot$i done=$(grep -c 'GATE-DIST\] done' $E/boot$i/uart-raw.log 2>/dev/null)" >>$LOG
  done
  python3 $PG/summarize_timing.py $E >$E/summary.txt 2>$E/summary.err && echo "[$(stamp)] summarized $img" >>$LOG
done
echo "[$(stamp)] CORE CAMPAIGN DONE" >>$LOG
