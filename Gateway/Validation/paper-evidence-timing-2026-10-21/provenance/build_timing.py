#!/usr/bin/env python3
"""Build the timing-distribution variant (GATE_N32=1, TIMING_DIST=1) and stage it; restore flags."""
from pathlib import Path
import re, subprocess, sys
root = Path('/home/iamfo470/stm32-projects/policy_gate')
name = sys.argv[1] if len(sys.argv) > 1 else 'timing-dist-opnsense53'
extra = dict(a.split('=') for a in sys.argv[2:])
header = root / 'Gateway/Inc/paper_experiment.h'
original = header.read_text()
flags = {'GATEWAY_PAPER_GATE_N32': '1', 'GATEWAY_PAPER_TIMING_DIST': '1', **extra}
try:
    s = original
    for k, v in flags.items():
        s, n = re.subn(r'(#define ' + k + r' )\d+\b', lambda m: m[1] + v, s)
        assert n == 1, k
    header.write_text(s)
    build = Path('/tmp') / f'pg-{name}-build'
    subprocess.run(['python3', 'Gateway/tools/build_firmware.py', '--output', str(build)], cwd=root, check=True)
    subprocess.run(['python3', str(Path(__file__).parent / 'stage_variant.py'), name,
                    '--build-log', str(build / 'build.log')], cwd=root, check=True)
finally:
    header.write_text(original)
