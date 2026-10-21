#!/usr/bin/env python3
"""Build a labelled variant: set paper_experiment.h flags, optionally swap in the A2
(ITCM) linker script and startup file, run the unchanged build_firmware.py, stage the
Debug ELF; always restore every swapped file."""
from pathlib import Path
import re, shutil, subprocess, sys
root = Path('/home/iamfo470/stm32-projects/policy_gate')
name = sys.argv[1] if len(sys.argv) > 1 else 'timing-dist-opnsense53'
extra = dict(a.split('=') for a in sys.argv[2:])
header = root / 'Gateway/Inc/paper_experiment.h'
swaps = []
if extra.get('GATEWAY_ITCM') == '1':
    swaps = [(root / 'STM32F767ZITX_FLASH.ld', root / 'Gateway/Provenance/itcm/STM32F767ZITX_FLASH.ld'),
             (root / 'Core/Startup/startup_stm32f767zitx.s', root / 'Gateway/Provenance/itcm/startup_stm32f767zitx.s')]
originals = {header: header.read_text(), **{dst: dst.read_text() for dst, _ in swaps}}
flags = {'GATEWAY_PAPER_GATE_N32': '1', 'GATEWAY_PAPER_TIMING_DIST': '1', **extra}
try:
    s = originals[header]
    for k, v in flags.items():
        s, n = re.subn(r'(#define ' + k + r' )\d+\b', lambda m: m[1] + v, s)
        assert n == 1, k
    header.write_text(s)
    for dst, src in swaps:
        dst.write_text(src.read_text())
    build = Path('/tmp') / f'pg-{name}-build'
    subprocess.run(['python3', 'Gateway/tools/build_firmware.py', '--output', str(build)], cwd=root, check=True)
    subprocess.run(['python3', str(Path(__file__).parent / 'stage_variant.py'), name,
                    '--build-log', str(build / 'build.log')], cwd=root, check=True)
finally:
    for path, text in originals.items():
        path.write_text(text)
