#!/bin/bash
# D1 MPU injection probes on the opn64 primary image (354 self-tests). Never RESET.
cd /home/iamfo470/stm32-projects/policy_gate
V=Gateway/Validation/opn64-campaign-2026-10-29
while ! grep -q 'FUNCTIONAL DONE' $V/run-status.log; do sleep 5; done
echo "[$(date -Iseconds)] probes start" >>$V/run-status.log
python3 $V/provenance/d1_run_final_probes.py >$V/mpu-probes.stdout 2>&1; echo "[$(date -Iseconds)] rc=$? probes" >>$V/run-status.log
git checkout -- Gateway/Inc/paper_experiment.h .settings/language.settings.xml 2>/dev/null
echo "[$(date -Iseconds)] PROBES DONE" >>$V/run-status.log
