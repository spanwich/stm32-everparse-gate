#!/usr/bin/env python3
"""Collect the D1 1/4/10 kHz timing matrix with exact per-image UART logs."""
from pathlib import Path
import argparse
import json
import subprocess

root = Path(__file__).resolve().parents[2]
evidence = root / 'Gateway/Validation/paper-evidence-d1-2026-09-30'
p = argparse.ArgumentParser()
p.add_argument('--frequencies', nargs='+', type=int, choices=(1000, 4000, 10000),
               default=(1000, 4000, 10000))
p.add_argument('--buckets', nargs='+', type=int, choices=(0, 1), default=(1, 0))
p.add_argument('--prefix', default='d1-control', help='evidence directory prefix (default keeps the stage-7 names)')
p.add_argument('--scenarios', nargs='+',
               choices=('idle', 'valid', 'denied', 'malformed'),
               default=('idle', 'valid', 'denied', 'malformed'))
a = p.parse_args()
for hz in a.frequencies:
    for bucket in a.buckets:
        name = f'{a.prefix}-{hz}-bucket{bucket}'
        directory = evidence / name
        image = directory / 'policy_gate.elf'
        if not image.is_file():
            subprocess.run(['python3', 'Gateway/tools/d1_build_control.py',
                            '--hz', str(hz), '--bucket', str(bucket), '--prefix', a.prefix],
                           cwd=root, check=True)
        pending = [scenario for scenario in a.scenarios
                   if not (directory / scenario / 'summary.json').is_file()]
        for index, scenario in enumerate(pending):
            command = ['python3', 'Gateway/tools/r4_control_capture.py',
                       '--elf', str(image), '--scenario', scenario, '--d1',
                       '--output', str(directory / scenario)]
            if index == 0:
                command.append('--flash')
            print(name, scenario, 'flash' if index == 0 else 'reset', flush=True)
            subprocess.run(command, cwd=root, check=True)
        summaries = [json.loads((directory / scenario / 'summary.json').read_text())
                     for scenario in a.scenarios]
        (directory / 'matrix-summary.json').write_text(json.dumps({
            'control_hz': hz, 'token_bucket': bool(bucket),
            'scenarios': summaries}, indent=2) + '\n')
        print(name, 'complete', flush=True)
