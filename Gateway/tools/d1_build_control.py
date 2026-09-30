#!/usr/bin/env python3
"""Build one isolated D1 timer image and restore the primary experiment flags."""
from pathlib import Path
import argparse
import re
import subprocess

root = Path(__file__).resolve().parents[2]
header = root / 'Gateway/Inc/paper_experiment.h'
p = argparse.ArgumentParser()
p.add_argument('--hz', type=int, choices=(1000, 4000, 10000), required=True)
p.add_argument('--bucket', type=int, choices=(0, 1), required=True)
a = p.parse_args()
name = f'd1-control-{a.hz}-bucket{a.bucket}'
original = header.read_text()
try:
    changed = original
    for key, value in (('GATEWAY_R4_CONTROL', 1),
                       ('GATEWAY_R4_CONTROL_HZ', a.hz),
                       ('GATEWAY_R4_CONTROL_HIGH', 1),
                       ('GATEWAY_D1_TOKEN_BUCKET', a.bucket)):
        changed, count = re.subn(r'(#define ' + key + r' )\d+\b',
                                 lambda m: m[1] + str(value), changed)
        assert count == 1, key
    header.write_text(changed)
    build = Path('/tmp') / f'd1-control-build-{a.hz}-bucket{a.bucket}'
    subprocess.run(['python3', 'Gateway/tools/build_firmware.py',
                    '--output', str(build)], cwd=root, check=True)
    subprocess.run(['python3', 'Gateway/tools/d1_stage_variant.py', name,
                    '--build-log', str(build / 'build.log')], cwd=root, check=True)
finally:
    header.write_text(original)
