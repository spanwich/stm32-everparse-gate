# Commands run (cwd = repo root). Nothing is sent over the serial port; UART is captured read-only.
# Tools run from Gateway/tools at the committed source (6ad5bd2); outputs are explicit, so no path-rewritten copy is needed.

## Setup (host only)
git commit <feature>   # Runtime-53 variant source + tools (paper_runtime53.c/.h, /gate53 hook, d1_build_runtime53.py, runtime53_load.py)
python3 Gateway/tools/d1_build_runtime53.py   # set GATEWAY_PAPER_RUNTIME53=1, build both configs, stage Debug+Release under v11-verified-gate-runtime53/, restore the flag
#   policy + oracle vectors from: python3 /home/iamfo470/phd/paper-experiments/verified-combiner/test/gen_vectors.py --policy opnsense-19.1.7 (sha256 b21f444d...), the same generator as the on-board data

## On-board campaign: bash provenance/run.sh
## Runtime-53 2026-10-28T16:20:58+13:00
python3 Gateway/tools/board_test.py --flash --elf Gateway/Validation/paper-evidence-runtime53-2026-10-28/v11-verified-gate-runtime53/policy_gate.elf --output Gateway/Validation/paper-evidence-runtime53-2026-10-28/v11-verified-gate-runtime53/board --seconds 30 --expected-selftests 301 > Gateway/Validation/paper-evidence-runtime53-2026-10-28/v11-verified-gate-runtime53/board.stdout
python3 Gateway/tools/paper_capture_command.py --output Gateway/Validation/paper-evidence-runtime53-2026-10-28/v11-verified-gate-runtime53/runtime53-uart -- python3 Gateway/tools/runtime53_load.py --output Gateway/Validation/paper-evidence-runtime53-2026-10-28/v11-verified-gate-runtime53/runtime53 --host 192.168.40.128 > Gateway/Validation/paper-evidence-runtime53-2026-10-28/v11-verified-gate-runtime53/runtime53.stdout
python3 Gateway/tools/d1_privileged_inventory.py Gateway/Validation/paper-evidence-runtime53-2026-10-28/v11-verified-gate-runtime53/policy_gate.elf --output Gateway/Validation/paper-evidence-runtime53-2026-10-28/v11-verified-gate-runtime53/e-map/privileged-inventory.json > Gateway/Validation/paper-evidence-runtime53-2026-10-28/v11-verified-gate-runtime53/e-map/privileged-inventory.stdout
python3 Gateway/tools/board_test.py --flash --elf Gateway/Validation/paper-evidence-a1v-final-2026-10-28/v11-verified-gate-a1v/policy_gate.elf --output Gateway/Validation/paper-evidence-runtime53-2026-10-28/reflash-a1v --seconds 20 --expected-selftests 301 > Gateway/Validation/paper-evidence-runtime53-2026-10-28/reflash-a1v.stdout
