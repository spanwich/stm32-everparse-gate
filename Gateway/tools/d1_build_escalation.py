#!/usr/bin/env python3
"""Build a separate MPU fault-injection image without flashing the board."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
header = root / 'Gateway/Inc/paper_experiment.h'
parser = argparse.ArgumentParser()
parser.add_argument('probe', type=int, choices=range(1, 12))
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=True)
original = header.read_text()
try:
    changed, count = re.subn(r'(#define GATEWAY_R4_FAULT_INJECT )\d+',
                             lambda m: m[1] + str(args.probe), original)
    assert count == 1
    header.write_text(changed)
    with tempfile.TemporaryDirectory(prefix='policy-d1-r4-build-') as build:
        with (out / 'build-command.log').open('wb') as log:
            subprocess.run(['python3', 'Gateway/tools/build_firmware.py',
                            '--output', build], cwd=root, stdout=log,
                           stderr=subprocess.STDOUT, check=True)
        shutil.copy2(Path(build) / 'build.log', out / 'build.log')
    elf = root / 'Debug/policy_gate.elf'
    shutil.copy2(elf, out / 'policy_gate.elf')
    manifest = {
        'probe': args.probe,
        'base_git_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                                   cwd=root, text=True).strip(),
        'elf_sha256': hashlib.sha256(elf.read_bytes()).hexdigest(),
        'source_sha256': {
            str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (header, root / 'Gateway/Network/gateway_r4_boundary.c',
                         root / 'Gateway/MPUPort/port.c',
                         root / 'Gateway/MPUPort/mpu_wrappers_v2.c',
                         root / 'Gateway/MPUPort/mpu_wrappers_v2_asm.c')},
    }
    (out / 'source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(out / 'policy_gate.elf', manifest['elf_sha256'])
finally:
    header.write_text(original)
