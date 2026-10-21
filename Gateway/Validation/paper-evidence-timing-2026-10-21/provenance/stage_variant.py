#!/usr/bin/env python3
"""Stage an exact D1 image with its build receipt and source hashes."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess

root = Path('/home/iamfo470/stm32-projects/policy_gate')
p = argparse.ArgumentParser()
p.add_argument('name')
p.add_argument('--build-log', type=Path, required=True)
a = p.parse_args()
out = root / 'Gateway/Validation/paper-evidence-timing-2026-10-21' / a.name
out.mkdir(parents=True, exist_ok=True)
elf = root / 'Debug/policy_gate.elf'
assert elf.is_file() and 'Gateway post-link checks PASS' in a.build_log.read_text()
shutil.copy2(elf, out / 'policy_gate.elf')
shutil.copy2(a.build_log, out / 'build.log')
paths = subprocess.check_output(
    ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z', '--',
     '.cproject', 'policy_gate.ioc', 'STM32F767ZITX_FLASH.ld', 'Core',
     'Gateway', 'Verification'], cwd=root).split(b'\0')
source = {}
for raw in paths:
    if not raw:
        continue
    name = raw.decode()
    if name.startswith(('Gateway/Validation/', 'Verification/evidence/')):
        continue
    path = root / name
    if path.is_file():
        source[name] = hashlib.sha256(path.read_bytes()).hexdigest()
manifest = {
    'name': a.name,
    'git_base': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root,
                                        text=True).strip(),
    'elf_sha256': hashlib.sha256(elf.read_bytes()).hexdigest(),
    'build_log_sha256': hashlib.sha256(a.build_log.read_bytes()).hexdigest(),
    'source_sha256': dict(sorted(source.items())),
}
(out / 'source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(out, manifest['elf_sha256'])
