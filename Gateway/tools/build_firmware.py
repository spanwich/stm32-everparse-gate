#!/usr/bin/env python3
"""Build both CubeIDE configurations in an isolated IDE workspace. No flashing."""
from pathlib import Path
import argparse, os, re, subprocess, tempfile
p = argparse.ArgumentParser()
p.add_argument('--output', type=Path)
args = p.parse_args()
root = Path(__file__).resolve().parents[2]
out = (args.output or Path(tempfile.mkdtemp(prefix='policy-gate-build-'))).resolve()
out.mkdir(parents=True, exist_ok=True)
subprocess.run(['python3', str(root / 'Gateway/tools/check_project.py')], check=True)
compiler = '/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin'
env = os.environ.copy(); env['PATH'] = compiler + os.pathsep + env['PATH']
cmd = ['/opt/st/stm32cubeide_2.0.0/headless-build.sh',
       '-configuration', str(out / 'ide-configuration'),
       '-data', str(out / 'ide-workspace'),
       '-import', str(root), '-cleanBuild', 'policy_gate/Debug', '-cleanBuild', 'policy_gate/Release']
print('Build log:', out / 'build.log', flush=True)
with (out / 'build.log').open('w') as log:
    result = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
text = (out / 'build.log').read_text()
lines = [line for line in text.splitlines() if re.search(r'Build of configuration|Build Finished|error:|warning:|CHECK FAILED|post-link|^\s+[0-9]+\s+[0-9]+\s+[0-9]+', line)]
print('\n'.join(lines[:50]))
if len(lines) > 50: print('Additional messages in build.log')
if result.returncode or re.search(r'\b(?:error|warning):', text):
    raise SystemExit(result.returncode or 1)
assert text.count('Gateway post-link checks PASS') >= 2, 'Both post-link checks must run'
print('Debug and Release validated; artifacts in the project build directories')
