#!/usr/bin/env python3
"""Stage an R4 firmware variant with its exact ELF, build receipt and source hashes."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess

p = argparse.ArgumentParser()
p.add_argument('name')
p.add_argument('--build-log', type=Path, required=True)
p.add_argument('--fault', type=int, default=0)
a = p.parse_args()
root = Path(__file__).resolve().parents[2]
out = root / 'Gateway/Validation/paper-evidence-r4-2026-09-29' / a.name
out.mkdir(parents=True, exist_ok=True)
elf = root / 'Debug/policy_gate.elf'
assert elf.is_file() and 'Gateway post-link checks PASS' in a.build_log.read_text()
shutil.copy2(elf, out / 'policy_gate.elf')
shutil.copy2(a.build_log, out / 'build.log')
names = [
    '.cproject', 'Core/Inc/FreeRTOSConfig.h', 'Core/Src/main.c',
    'STM32F767ZITX_FLASH.ld', 'Gateway/Inc/paper_experiment.h',
    'Gateway/Inc/gateway_r4_boundary.h', 'Gateway/MPUPort/port.c',
    'Gateway/MPUPort/portmacro.h', 'Gateway/MPUPort/mpu_wrappers.c',
    'Gateway/Network/gateway_r4_boundary.c', 'Gateway/Network/gateway_network.c',
    'Gateway/Network/ethernetif.c', 'Gateway/Network/sys_arch.c',
    'Gateway/Network/lwipopts.h', 'Gateway/Core/gateway_mediation.c',
    'Gateway/Core/gateway_core.c', 'Gateway/Inc/gateway_core.h',
    'Gateway/Platform/gateway_platform.c',
    'Gateway/Paper/paper_timing.c', 'Gateway/tools/paper_timing_capture.py',
    'Gateway/tools/check_firmware.py', 'Gateway/tools/configure_project.py',
    'Gateway/tools/r4_validator_disasm.py',
    'Verification/lowstar/Mediation.Field.fst', 'Verification/tools/prove.py',
    'Gateway/Paper/paper_control_r4.c', 'Gateway/tools/r4_control_capture.py',
    'Gateway/tools/r4_run_control_matrix.py',
    'Gateway/tools/r4_summarize.py',
    'Gateway/tools/r4_run_faults_final.py',
    'Gateway/Generated/Mediation/Mediation_Format.c',
    'Gateway/Generated/Mediation/Mediation_Field.c',
    'Gateway/Generated/Mediation/Mediation_Wrapper.c',
    'Verification/evidence/proof-manifest.json',
    'Gateway/tools/paper_capture_command.py',
]
digest = lambda b: hashlib.sha256(b).hexdigest()
manifest = {
    'name': a.name,
    'fault_injection': a.fault,
    'git_base': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'dirty_tree_diff_sha256': digest(subprocess.check_output(
        ['git', 'diff', '--binary', 'HEAD'], cwd=root)),
    'dirty_tracked_diff_sha256': digest(subprocess.check_output(
        ['git', 'diff', '--binary', 'HEAD', '--', '.cproject', 'Core', 'Gateway',
         'STM32F767ZITX_FLASH.ld', 'Verification'], cwd=root)),
    'elf_sha256': digest(elf.read_bytes()),
    'source_sha256': {n: digest((root / n).read_bytes()) for n in names},
    'build_log_sha256': digest(a.build_log.read_bytes()),
}
manifest['source_manifest_sha256'] = digest(json.dumps(
    manifest['source_sha256'], sort_keys=True).encode())
(out / 'source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(out, manifest['elf_sha256'])
