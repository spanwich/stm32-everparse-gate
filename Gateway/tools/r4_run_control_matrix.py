#!/usr/bin/env python3
"""Build and collect the R4 TIM7 control matrix on the named NUCLEO board.

Each image has one clock/cache/optimisation, frequency and task priority.
Each load gets a fresh reset and its own raw UART and per-sample CSV.
"""
from pathlib import Path
import argparse
import json
import re
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
header = root / 'Gateway/Inc/paper_experiment.h'
evidence = root / 'Gateway/Validation/paper-evidence-r4-2026-09-29'
p = argparse.ArgumentParser()
p.add_argument('--variants', nargs='+', choices=('V0', 'V1', 'V2'), default=('V0', 'V1', 'V2'))
p.add_argument('--frequencies', nargs='+', type=int, choices=(1000, 4000, 10000),
               default=(1000, 4000, 10000))
p.add_argument('--priorities', nargs='+', choices=('above', 'below'),
               default=('above', 'below'))
p.add_argument('--scenarios', nargs='+', choices=('idle', 'valid', 'denied', 'malformed'),
               default=('idle', 'valid', 'denied', 'malformed'))
p.add_argument('--continue-on-capture-error', action='store_true')
a = p.parse_args()
original = header.read_text()

def update(**values):
    content = original
    for key, value in values.items():
        pattern = r'(#define ' + re.escape(key) + r' )\d+'
        content, count = re.subn(pattern, lambda match: match[1] + str(value), content)
        assert count == 1, key
    header.write_text(content)

def run(*args):
    subprocess.run(args, cwd=root, check=True)

try:
    for variant in a.variants:
        fast = variant != 'V0'
        opt = variant == 'V2'
        for hz in a.frequencies:
            for priority in a.priorities:
                name = f'r4-control-{variant.lower()}-{hz}-{priority}'
                update(GATEWAY_PAPER_TIMING=0, GATEWAY_R4_TIMING_MASK_IRQ=0,
                       GATEWAY_R4_CONTROL=1, GATEWAY_R4_CONTROL_HZ=hz,
                       GATEWAY_R4_CONTROL_HIGH=int(priority == 'above'),
                       GATEWAY_R4_FAST_CLOCK=int(fast), GATEWAY_R4_CACHES=int(fast),
                       GATEWAY_R4_OPT_O2=int(opt), GATEWAY_R4_TRACE_NET=0,
                       GATEWAY_R4_NO_HTTP_LOG=1)
                run('python3', 'Gateway/tools/configure_project.py')
                with tempfile.TemporaryDirectory(prefix='r4-build-') as build:
                    run('python3', 'Gateway/tools/build_firmware.py', '--output', build)
                    run('python3', 'Gateway/tools/r4_stage_variant.py', name,
                        '--build-log', str(Path(build) / 'build.log'))
                (evidence / name / 'configuration.json').write_text(json.dumps({
                    'variant': variant, 'clock_hz': 216000000 if fast else 96000000,
                    'caches': bool(fast), 'optimization': '-O2' if opt else '-Os generated / Debug handwritten',
                    'control_hz': hz, 'control_priority': priority,
                    'http_request_logging': False, 'request_linger': -1,
                    'samples_per_scenario': 10000}, indent=2) + '\n')
                image = evidence / name / 'policy_gate.elf'
                for index, scenario in enumerate(a.scenarios):
                    command = ['python3', 'Gateway/tools/r4_control_capture.py',
                               '--elf', str(image), '--scenario', scenario,
                               '--output', str(evidence / name / scenario)]
                    if index == 0:
                        command.append('--flash')
                    try:
                        run(*command)
                    except subprocess.CalledProcessError as exc:
                        if not a.continue_on_capture_error:
                            raise
                        failure={'scenario':scenario,'capture_failed':True,
                                 'exit_code':exc.returncode,
                                 'uart_path':str(evidence / name / scenario / 'uart.bin')}
                        (evidence / name / scenario / 'failure.json').write_text(
                            json.dumps(failure,indent=2)+'\n')
                        print('R4 capture failed:',name,scenario,flush=True)
                summaries=[]
                for scenario in a.scenarios:
                    directory=evidence / name / scenario
                    path=directory / 'summary.json'
                    summaries.append(json.loads(path.read_text()) if path.exists() else
                                     json.loads((directory / 'failure.json').read_text()))
                (evidence / name / 'matrix-summary.json').write_text(
                    json.dumps(summaries, indent=2) + '\n')
                print('R4 matrix image complete:', name, flush=True)
finally:
    header.write_text(original)
    run('python3', 'Gateway/tools/configure_project.py')
