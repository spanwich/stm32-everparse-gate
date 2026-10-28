#!/usr/bin/env python3
"""Build and stage the runtime-53 labelled variant (GATEWAY_PAPER_RUNTIME53 = 1,
on the A1v base), then restore the primary experiment flags. Stages the Debug
and Release images with a build receipt and source hashes under the given
evidence directory. No flashing."""
from pathlib import Path
import argparse, hashlib, json, re, shutil, subprocess

root = Path(__file__).resolve().parents[2]
ap = argparse.ArgumentParser()
ap.add_argument('--name', default='v11-verified-gate-runtime53')
ap.add_argument('--evidence', default='Gateway/Validation/paper-evidence-runtime53-2026-10-28')
ap.add_argument('--build', default='/tmp/runtime53-build')
a = ap.parse_args()
header = root / 'Gateway/Inc/paper_experiment.h'
out = root / a.evidence / a.name
original = header.read_text()
try:
    changed, n = re.subn(r'(#define GATEWAY_PAPER_RUNTIME53 )\d+\b', r'\g<1>1', original)
    assert n == 1, 'flag not found'
    header.write_text(changed)
    build = Path(a.build)
    subprocess.run(['python3', str(root / 'Gateway/tools/build_firmware.py'), '--output', str(build)],
                   cwd=root, check=True)
    log = (build / 'build.log').read_text()
    assert log.count('Gateway post-link checks PASS') >= 2, 'post-link acceptance missing'
    out.mkdir(parents=True, exist_ok=True)
    (out / 'release').mkdir(exist_ok=True)
    shutil.copy2(root / 'Debug/policy_gate.elf', out / 'policy_gate.elf')
    shutil.copy2(root / 'Debug/policy_gate.map', out / 'policy_gate.map')
    shutil.copy2(root / 'Release/policy_gate.elf', out / 'release/policy_gate.elf')
    shutil.copy2(root / 'Release/policy_gate.map', out / 'release/policy_gate.map')
    shutil.copy2(build / 'build.log', out / 'build.log')
    paths = subprocess.check_output(
        ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z', '--',
         '.cproject', 'policy_gate.ioc', 'STM32F767ZITX_FLASH.ld', 'Core', 'Gateway', 'Verification'],
        cwd=root).split(b'\0')
    source = {}
    for raw in paths:
        if not raw:
            continue
        name = raw.decode()
        if name.startswith(('Gateway/Validation/', 'Verification/evidence/')):
            continue
        p = root / name
        if p.is_file():
            source[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    manifest = {
        'name': a.name,
        'git_base': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
        'flags': {'GATEWAY_PAPER_RUNTIME53': 1, 'GATEWAY_FAST_MEMOPS': 1, 'GATEWAY_VERIFIED_GATE': 1},
        'elf_sha256': hashlib.sha256((out / 'policy_gate.elf').read_bytes()).hexdigest(),
        'debug_elf_sha256': hashlib.sha256((out / 'policy_gate.elf').read_bytes()).hexdigest(),
        'release_elf_sha256': hashlib.sha256((out / 'release/policy_gate.elf').read_bytes()).hexdigest(),
        'build_log_sha256': hashlib.sha256((build / 'build.log').read_bytes()).hexdigest(),
        'source_sha256': dict(sorted(source.items())),
    }
    (out / 'source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(out, manifest['debug_elf_sha256'])
finally:
    header.write_text(original)
