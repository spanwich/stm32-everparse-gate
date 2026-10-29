#!/bin/bash
# Phase 2: A1v then A2v D1 injection probes (322 self-tests). Never RESET.
cd /home/iamfo470/stm32-projects/policy_gate
V=Gateway/Validation/glue-timing-2026-10-29
P=$PWD/$V/provenance; LOG=$V/phase2-run.log
echo "[$(date -Iseconds)] a1v probes start" >>$LOG
python3 $P/v_run_probes.py a1v >$V/a1v-probes.stdout 2>&1; echo "[$(date -Iseconds)] a1v probes rc=$?" >>$LOG
python3 $P/apply_itcm_probes.py >>$LOG 2>&1
python3 $P/v_run_probes.py a2v >$V/a2v-probes.stdout 2>&1; echo "[$(date -Iseconds)] a2v probes rc=$?" >>$LOG
git checkout -- Gateway/Network/gateway_r4_boundary.c Gateway/Inc/paper_experiment.h STM32F767ZITX_FLASH.ld Core/Startup/startup_stm32f767zitx.s .settings/language.settings.xml 2>>$LOG
echo "[$(date -Iseconds)] PHASE2_PROBES_DONE" >>$LOG
