#!/bin/bash
# 100,000-request audit on the flashed glue Debug image (paper_m4 pairing + hang
# watch). Network-only load; hang_watch is the sole serial reader. Never RESET.
set -u
R=/home/iamfo470/stm32-projects/policy_gate
V=$R/Gateway/Validation/glue-verified-2026-10-29
A=$V/audit-100k; T=$R/Gateway/tools
cd $R || exit 1
echo "[$(date -Iseconds)] audit-100k start" >$A/run.log
python3 $T/paper_m4_network.py --count 100000 --output $A/load \
  --elf-sha256-file $V/board/elf.sha256 >$A/load.stdout 2>&1 &
load=$!; echo $load >$A/load.pid
python3 $T/d1_hang_watch.py --elf $V/board/policy_gate.elf --output $A/watch \
  --load-pid-file $A/load.pid --max-hours 1 >$A/watch.stdout 2>&1
wait $load; rc=$?
echo "[$(date -Iseconds)] audit-100k load rc=$rc" >>$A/run.log
echo "AUDIT100K_RC=$rc done"
