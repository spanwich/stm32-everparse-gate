#!/bin/bash
# opn64 experiment: control task (A1v norank images, built on the n=64 primary) beside the 64-partition
# gate with the OPNsense policy provisioned at run time. Idempotent (skips scenarios with summary.json).
# Never sends RESET over serial (capture tool resets via the debug probe). LAN .128, bounded rates.
set -u
R=/home/iamfo470/stm32-projects/policy_gate
V=$R/Gateway/Validation/opn64-experiment-2026-10-29
IMG=$R/Gateway/Validation/opn64-timing-2026-10-29      # a1v-norank-control-<hz>-bucket<b>/policy_gate.elf
T=$R/Gateway/tools
cd $R || exit 1
LOG=$V/experiment-run.log; stamp(){ date -Iseconds; }
echo "[$(stamp)] EXPERIMENT START (rate window 500 ms, N_max 50, n=64, OPNsense provisioned via PUT ?part=J)" >>$LOG
cap(){  # name image scenario extra-args...
  name=$1; img=$2; sc=$3; shift 3
  D=$V/$name
  [ -f $D/summary.json ] && return
  if [ "$img" != "${LASTIMG:-}" ]; then f=--flash; LASTIMG=$img; else f=; fi
  timeout 400 python3 $T/opn64_control_capture.py --elf $IMG/$img/policy_gate.elf $f --scenario $sc --d1 --provision-opn --output $D "$@" >$D.stdout 2>&1
  echo "[$(stamp)] $name rc=$? $(grep -ao '\"misses\": [0-9]*\|\"max_cycles\": [0-9]*\|\"admitted_200\": [0-9]*\|\"refused_429\": [0-9]*\|\"achieved_overall_rate_hz\": [0-9.]*' $D/summary.json 2>/dev/null | tr '\n' ' ')" >>$LOG
}
# 1. deadline matrix with the OPNsense policy live (unpaced, 1 client): valid, wcdeny; plus 4-client flood of wcdeny
for hz in 1000 4000 10000; do for b in 0 1; do
  img=a1v-norank-control-$hz-bucket$b
  cap opn64-$hz-b$b-idle     $img idle
  cap opn64-$hz-b$b-valid    $img valid
  cap opn64-$hz-b$b-wcdeny   $img wcdeny
  cap opn64-$hz-b$b-flood4   $img wcdeny --clients 4
done; done
# 2. paced sweep (worst-case-deny = full 64-partition scan), 1 kHz bucket 1, one control window (10 s) per step
img=a1v-norank-control-1000-bucket1
for r in 50 80 90 95 98 100 110 150; do
  cap opn64-sweep-r$r $img wcdeny --rate $r --clients 2
done
echo "[$(stamp)] EXPERIMENT DONE" >>$LOG
