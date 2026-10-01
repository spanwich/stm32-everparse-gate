#!/usr/bin/env python3
"""Build and stage the section 14 labelled variant (GATEWAY_PAPER_GATE_N32 = 1),
then restore the primary experiment flags."""
from pathlib import Path
import argparse
import re
import subprocess

ap = argparse.ArgumentParser()
ap.add_argument('--name', default='v11-verified-gate-n32-variant',
                help='staged variant name (v11-verified-gate-opnsense53-variant for the OPNsense data)')
root = Path(__file__).resolve().parents[2]
header = root / 'Gateway/Inc/paper_experiment.h'
name = ap.parse_args().name
original = header.read_text()
try:
    changed, count = re.subn(r'(#define GATEWAY_PAPER_GATE_N32 )\d+\b', r'\g<1>1', original)
    assert count == 1
    header.write_text(changed)
    build = Path('/tmp') / 'd1-gate-n32-build'
    subprocess.run(['python3', 'Gateway/tools/build_firmware.py', '--output', str(build)], cwd=root, check=True)
    subprocess.run(['python3', 'Gateway/tools/d1_stage_variant.py', name,
                    '--build-log', str(build / 'build.log')], cwd=root, check=True)
finally:
    header.write_text(original)
