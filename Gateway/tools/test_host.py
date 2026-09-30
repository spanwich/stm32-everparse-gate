#!/usr/bin/env python3
"""Run the same generated C, adapters and vectors used by the MCU."""
from pathlib import Path
import argparse, os, subprocess, tempfile
parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path)
parser.add_argument('--sanitize', action='store_true')
parser.add_argument('--lab-auth-off', action='store_true')
args = parser.parse_args()
gateway = Path(__file__).resolve().parents[1]
out = args.output or Path(tempfile.mkdtemp(prefix='policy-gate-host-'))
out.mkdir(parents=True, exist_ok=True)
includes = [gateway / n for n in ['Inc', 'Shared', 'Core', 'Auth', 'Generated/Auth', 'Generated/Extractor', 'Generated/Extractor/krml_include']]
sources = sorted(p for p in (gateway / 'Auth').glob('*.c') if p.name != 'd1_auth_oracle.c') + sorted((gateway / 'Generated/Auth').glob('*.c')) + sorted((gateway / 'Generated/Extractor').glob('*.c')) + sorted((gateway / 'Generated/Policy').glob('*.c')) + sorted((gateway / 'Generated/Mediation').glob('*.c')) + sorted((gateway / 'Generated/Gate').glob('*.c')) + sorted((gateway / 'Core').glob('*.c')) + sorted((gateway / 'SelfTest').glob('*.c')) + [gateway / 'tools/host_main.c']
cmd = [os.environ.get('CC', 'gcc'), '-std=gnu11', '-Os', '-g', '-Wall', '-Wextra', '-Werror']
cmd += ['-DGATEWAY_PAPER_TIMING=0', '-DGATEWAY_PAPER_CONTROL=0', '-DGATEWAY_PAPER_ALLOC=0']
if args.lab_auth_off: cmd += ['-DGATEWAY_LAB_AUTH=0']
if args.sanitize: cmd += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
cmd += ['-I' + str(p) for p in includes] + [str(p) for p in sources] + ['-o', str(out / 'gateway_tests')]
subprocess.run(cmd, check=True)
env = os.environ.copy()
if args.sanitize:
    env['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    # LeakSanitizer cannot run under this environment's ptrace supervision;
    # keep address and undefined-behavior instrumentation enabled.
    env.setdefault('ASAN_OPTIONS', 'detect_leaks=0')
with (out / 'tests.log').open('w') as log:
    result = subprocess.run([str(out / 'gateway_tests')], stdout=log, stderr=subprocess.STDOUT, env=env)
text = (out / 'tests.log').read_text()
print('\n'.join(line for line in text.splitlines() if 'Results:' in line or 'Legacy vectors' in line or 'CORE SELFTEST' in line or 'FAIL' in line or 'runtime error' in line or 'ERROR:' in line))
print('Artifacts:', out)
raise SystemExit(result.returncode)
