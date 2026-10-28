#!/bin/bash
# Host-only reference builds (nothing flashed), 2026-10-28, after Phase A:
#  1. A0 at a4fbff0 (GATEWAY_FAST_MEMOPS 1 -> 0 in the header, restored after) to split
#     the final2 -> A1v size/inventory change into PA0 (a2a34a8) and verified memops.
#  2. The default (A1v) again, to check that the staged primary ELF is reproduced
#     and to leave Debug/ and Release/ holding the flashed image.
R=/home/iamfo470/stm32-projects/policy_gate
V=$R/Gateway/Validation/paper-evidence-a1v-final-2026-10-28
S=/tmp/claude-1001/-home-iamfo470-stm32-projects-policy-gate/4f0c6d1e-fde2-456d-a8ba-eebd2a83a05f/scratchpad
P=$S/pgtools
H=$R/Gateway/Inc/paper_experiment.h
cd $R || exit 1
note() { echo "[$(date -Iseconds)] $*" >> $V/run-status.log; }
cp -p $H $S/paper_experiment.h.orig
sed -i 's/^#define GATEWAY_FAST_MEMOPS 1$/#define GATEWAY_FAST_MEMOPS 0/' $H
grep -q '^#define GATEWAY_FAST_MEMOPS 0$' $H || { cp -p $S/paper_experiment.h.orig $H; exit 1; }
note "start: A0 reference build (GATEWAY_FAST_MEMOPS=0)"
python3 $P/build_firmware.py --output $S/a0-reference-build > $S/a0-reference-build.stdout 2>&1
rc=$?
cp -p $S/paper_experiment.h.orig $H
git diff --quiet -- Gateway/Inc/paper_experiment.h || { note "header restore FAILED"; exit 1; }
note "rc=$rc: A0 reference build; header restored"
[ $rc = 0 ] || exit 1
mkdir -p $V/a0-reference/release
cp -p Debug/policy_gate.elf Debug/policy_gate.map $V/a0-reference/
cp -p Release/policy_gate.elf Release/policy_gate.map $V/a0-reference/release/
cp -p $S/a0-reference-build/build.log $V/a0-reference/build.log
python3 $P/d1_privileged_inventory.py $V/a0-reference/policy_gate.elf --output $V/a0-reference/privileged-inventory.json > $V/a0-reference/privileged-inventory.stdout
note "start: A1v rebuild (default flags)"
python3 $P/build_firmware.py --output $S/a1v-rebuild > $S/a1v-rebuild.stdout 2>&1
rc=$?
note "rc=$rc: A1v rebuild; Debug sha256 $(sha256sum Debug/policy_gate.elf | cut -c1-64) Release sha256 $(sha256sum Release/policy_gate.elf | cut -c1-64)"
git checkout -- .settings/language.settings.xml 2>/dev/null
