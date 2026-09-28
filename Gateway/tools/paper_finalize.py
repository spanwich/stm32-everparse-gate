#!/usr/bin/env python3
"""Refresh the paper evidence index without inventing unmeasured results."""
from collections import Counter
from pathlib import Path
import csv
import hashlib
import json

root = Path(__file__).resolve().parents[1] / 'Validation' / 'paper-evidence-2026-09-29'


def read(name):
    return json.loads((root / name).read_text())


baseline = read('m0/provenance.json')
footprint = read('m1/release-footprint.json')
cedar = read('m1/cedar-thumb-build-result.json')
audit = read('m4/campaign-100000/summary.json')
audit_provenance = read('m4/audit-provenance.json')
entrypoints = read('m4/audit-entrypoints.json')
attacks = read('m5/attacks-audit-image/summary.json')
differential = read('m5/differential-12527/summary.json')
attack_rows = list(csv.DictReader((root / 'm5/attacks-audit-image/attack-requests.csv').open(newline='')))
classes = Counter(row['class'] for row in attack_rows)
fail_open = Counter(row['class'] for row in attack_rows if int(row['fail_open']))

summary = {
    'firmware_commit': baseline['firmware_commit'],
    'firmware_source_diff_sha256': {
        'baseline': baseline['firmware_source_diff_sha256'],
        'audit': audit_provenance['firmware_source_diff_sha256'],
    },
    'elf_sha256': {
        'baseline_debug': baseline['elf']['debug']['sha256'],
        'baseline_release': baseline['elf']['release']['sha256'],
        'audit_debug': audit_provenance['audit_debug_elf_sha256'],
        'audit_release': audit_provenance['audit_release_elf_sha256'],
    },
    'clock_hz': baseline['clock_hz_observed'],
    'cache_state': baseline['cache_configuration'],
    'compiler': baseline['compiler'],
    'policy_slots': {'active': 3, 'inactive': 5},
    'flash_bytes': {name: value['flash_bytes'] for name, value in footprint['components'].items()},
    'ram_bytes': {name: value['ram_bytes'] for name, value in footprint['components'].items()},
    'decision_path_allocations': None,
    'cedar_no_std_outcome': {
        'result': 'build_failed_std_dependency',
        'target': 'thumbv7em-none-eabihf',
        'exit_code': cedar['exit_code'],
        'first_error': "memchr 2.8.3: E0463 can't find crate for std",
        'log_sha256': cedar['log_sha256'],
    },
    'validator_cycles': None,
    'gate_path_cycles': None,
    'extract_cycles': None,
    'request_cycles': None,
    'handwritten_cycles': None,
    'cpu_share_gate': None,
    'control_task_misses': None,
    'control_task_jitter_us': None,
    'bypass_paths': None,
    'direct_bypass_paths_found': any(entrypoints['direct_paths_around_wrapper'].values()),
    'indirect_calls_unresolved': len(entrypoints['register_indirect_calls']),
    'unmatched_effects': audit['unmatched'] + attacks['unmatched_effects'],
    'requests_tested': audit['completed'],
    'audit_acceptances': audit['acceptance_count'],
    'audit_effects': audit['effect_count'],
    'audit_transport_errors': audit['transport_errors'],
    'audit_concurrent_pairs': audit['concurrent_pairs'],
    'oracle_disagreements': differential['disagreements'],
    'oracle_cases': differential['cases'],
    'oracle_corpus': 'adapted STM32 corpus, not a replay of seL4 inputs',
    'fail_open': attacks['fail_open'],
    'attack_requests': {name: {'tested': count, 'fail_open': fail_open[name]}
                        for name, count in sorted(classes.items())},
    'mpu_injections': None,
    'dma_disjoint': None,
    'mpu_overhead_cycles': None,
    'verdicts': {'H1': 'partial', 'H2': 'not measured', 'H3': 'partial',
                 'H4': 'not supported in current image', 'H5': 'partial'},
    'decision_gate': 'not established',
}
(root / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')

lines = []
for path in sorted(root.rglob('*')):
    if path.is_file() and path.name != 'SHA256SUMS':
        lines.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}')
(root / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
print(f'Wrote summary.json and {len(lines)} evidence hashes')
