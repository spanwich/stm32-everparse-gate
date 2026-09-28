#!/usr/bin/env python3
"""Freeze M0 receipts for the named, already flashed mediation image.

This is a collector: it neither builds nor talks to the board. Run it only after
the proof replay, both builds, and all three network acceptance suites complete.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
DEFAULT = ROOT / 'Gateway/Validation/paper-evidence-2026-09-29'


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    return digest(path.read_bytes())


def copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, default=DEFAULT)
p.add_argument('--build-log', type=Path, required=True)
a = p.parse_args()
out = a.output.resolve()
m0 = out / 'm0'
uart = (m0 / 'board-reset-2/uart.log').read_text()
assert '[CORE SELFTEST] PASS 297/297' in uart
assert '[HTTP] READY' in uart and 'SYSCLK=96000000 HCLK=96000000' in uart
assert 'margin=LOW' not in uart and 'log_drops=0' in uart
assert 'Download verified successfully' in (m0 / 'board-debug/programmer.log').read_text()

proof_names = [f'replay-HTTP.Extract.{n}.fst.log' for n in
               ('Types', 'Scan', 'Method', 'Path', 'Header', 'Bearer', 'Complete')]
proof_names += ['replay-IPC.Extract.fst.log', 'Mediation.Format.fst.log',
                'Mediation.Extern.fsti.log', 'Mediation.Wrapper.fst.log']
proof_dir = ROOT / 'Verification/evidence'
for name in proof_names:
    source = proof_dir / name
    assert 'All verification conditions discharged successfully' in source.read_text(), name
    copy(source, m0 / 'proof' / name)
copy(ROOT / 'Verification/toolchain.lock.json', m0 / 'proof/toolchain.lock.json')
copy(ROOT / 'Verification/evidence/proof-manifest.json', m0 / 'proof/proof-manifest.json')
copy(a.build_log, m0 / 'build.log')
for config in ('Debug', 'Release'):
    base = ROOT / config
    copy(base / 'policy_gate.map', m0 / f'{config.lower()}-link.map')
    copy(base / 'gateway.stack.json', m0 / f'{config.lower()}-stack.json')

elfs = {config.lower(): {
    'sha256': file_hash(ROOT / config / 'policy_gate.elf'),
    'bytes': (ROOT / config / 'policy_gate.elf').stat().st_size,
    'map_sha256': file_hash(ROOT / config / 'policy_gate.map'),
} for config in ('Debug', 'Release')}
assert (m0 / 'board-debug/elf.sha256').read_text().strip() == elfs['debug']['sha256']
assert (m0 / 'board-reset-2/workspace-elf-unverified.sha256').read_text().strip() == elfs['debug']['sha256']
prior = json.loads((ROOT / 'Verification/summary.json').read_text())
assert elfs['debug']['sha256'] in json.dumps(prior) and elfs['release']['sha256'] in json.dumps(prior)

source_paths = ('Core', 'Gateway/Auth', 'Gateway/Core', 'Gateway/Generated',
                'Gateway/Inc', 'Gateway/Network', 'Gateway/Platform',
                'Gateway/SelfTest', 'Gateway/Shared', 'Gateway/Web',
                'Drivers', 'Middlewares', 'STM32F767ZITX_FLASH.ld',
                '.cproject', 'policy_gate.ioc')
source_diff = subprocess.check_output(['git', 'diff', '--binary', 'HEAD', '--', *source_paths], cwd=ROOT)
workspace_diff = subprocess.check_output(['git', 'diff', '--binary', 'HEAD'], cwd=ROOT)
(m0 / 'workspace-diff.patch').write_bytes(workspace_diff)
requirements = ROOT / 'PAPER_EVIDENCE_REQUIREMENTS.md'
provenance = {
    'firmware_commit': run('git', 'rev-parse', 'HEAD'),
    'branch': run('git', 'branch', '--show-current'),
    'firmware_source_diff_sha256': digest(source_diff),
    'workspace_dirty_diff_sha256': digest(workspace_diff),
    'untracked_requirements_sha256': file_hash(requirements),
    'flashed_configuration': 'Debug',
    'elf': elfs,
    'compiler': run('/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin/arm-none-eabi-gcc', '--version').splitlines()[0],
    'clock_hz_observed': 96000000,
    'cache_configuration': 'I-cache and D-cache disabled in the primary firmware',
    'st_link_serial': '066FFF555567894967085545',
    'serial_device': '/dev/ttyACM1',
    'proof_modules_replayed': len(proof_names),
    'startup_self_tests': 297,
    'http_groups': json.loads((m0 / 'http/summary.json').read_text())['passed'],
    'dashboard_checks': json.loads((m0 / 'dashboard/summary.json').read_text())['passed'],
    'live_policy_checks': json.loads((m0 / 'live-policy/summary.json').read_text())['passed'],
    'ram_policy_restored': json.loads((m0 / 'live-policy/summary.json').read_text())['initial_policy_restored'],
}
assert provenance['http_groups'] == 34
assert provenance['dashboard_checks'] == 129
assert provenance['live_policy_checks'] == 43
(m0 / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
print('M0 receipts collected for', provenance['firmware_commit'], elfs['debug']['sha256'])
