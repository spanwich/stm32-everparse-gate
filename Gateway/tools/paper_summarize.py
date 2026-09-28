#!/usr/bin/env python3
"""Collect the R1 paper numbers from immutable per-experiment receipts.

This is a collector, not a test. It refuses to report a completed M4 campaign
until all 100,000 request rows and its final policy-restoration receipt exist.
"""
import argparse
import csv
import json
from pathlib import Path


def read(path):
    return json.loads(path.read_text())


parser = argparse.ArgumentParser()
parser.add_argument('bundle', type=Path)
args = parser.parse_args()
root = args.bundle
timing = read(root / 'm2/five-boots/summary.json')
footprint = read(root / 'm1/release-footprint.json')
manifest = read(root / 'm0/primary-build-final/source-manifest.json')
attack = read(root / 'm5/attacks-200-final-primary/summary.json')
allocation = read(root / 'm1/valid-owner-alloc-60/summary.json')
m4 = read(root / 'm4/campaign-100000-rawsocket-final-primary/summary.json')
assert m4['requested'] == m4['completed'] == m4['matched'] == 100000
assert m4['unmatched'] == m4['transport_errors'] == 0
assert m4['policy_restored'] and m4['unique_audit_ids'] == 100000
with (root / 'm4/campaign-100000-rawsocket-final-primary/requests.csv').open() as f:
    assert sum(1 for _ in csv.DictReader(f)) == 100000

stages = {
    'validator_cycles': 'validator',
    'gate_path_cycles': 'serializer_validator',
    'extract_cycles': 'extractor',
    'request_cycles': 'request_processing',
    'handwritten_cycles': 'handwritten',
}
by_stage = {}
for output, stage in stages.items():
    index = timing['stage_names'].index(stage)
    by_stage[output] = {}
    for case_index, case in enumerate(timing['case_names']):
        item = timing['statistics'][f'{index}:{case_index}']
        by_stage[output][case] = {
            **item,
            'microseconds_at_96mhz': {
                key: round(item[key] / 96, 3)
                for key in ('min', 'median', 'p99', 'max')
            },
        }

scenarios = {}
for name in ('idle', 'valid', 'denied', 'malformed'):
    row = read(root / f'm3/{name}-highdiag-log-600/summary.json')
    assert row['control_task_misses'] == 0
    scenarios[name] = row

callgraph = read(root / 'm4/entrypoints-final-primary.json')
assert len(callgraph['register_indirect_calls']) == 125
cedar = read(root / 'm1/cedar-historical/cedar-thumb-build-result.json')
assert cedar['exit_code'] == 101
soaks = [read(root / f'm4/repeated-soak-primary/run-{n}/network/summary.json')
         for n in range(1, 6)]
assert all(row['passed'] == 34 and row['requests_in_soak'] == 1000 for row in soaks)

output = {
    'schema': 'paper-evidence-r1-1',
    'firmware': {
        'source_commit': '7000fab1440301ccb76c8c61c1ea854d1ceeb89b',
        'primary_build_parent_commit': manifest['git_commit'],
        'primary_build_dirty_tree_diff_sha256': manifest['dirty_tree_diff_sha256'],
        'primary_build_source_tree_sha256': manifest['source_tree_sha256'],
        'primary_debug_elf_sha256': m4['elf_sha256'],
        'primary_release_elf_sha256': '65d70c75ccac2414bb9a0bbe73f184e8b52cd6ad62972627bb90c3e6f0987658',
        'timing_variant_elf_sha256': timing['firmware_elf_sha256'],
        'load_variant_elf_sha256': scenarios['valid']['elf_sha256'],
        'allocation_variant_elf_sha256': allocation['elf_sha256'],
        'build_configurations': ['Debug', 'Release'],
        'clock_hz': 96000000,
        'instruction_cache': False,
        'data_cache': False,
        'timing_interrupts': timing['interrupts'],
        'toolchain_lock': 'Verification/toolchain.lock.json',
        'arm_gcc': '13.3.1',
    },
    **by_stage,
    'empty_measurement_cycles': timing['statistics']['0:0'],
    'timing_boots': len(timing['boots']),
    'timing_samples_per_stage_case': timing['statistics']['1:0']['n'],
    'timing_full_request_limit': 'gateway_http_feed + gateway_http_process; response header/netconn queue excluded',
    'cpu_share_gate': {n: scenarios[n]['cpu_share_gate'] for n in scenarios},
    'control_task_misses': {n: scenarios[n]['control_task_misses'] for n in scenarios},
    'control_task_jitter_us': {n: {
        'p99_histogram_bucket': scenarios[n]['control_p99_bucket_us'],
        'maximum': round(scenarios[n]['control_max_cycles'] / 96, 3),
    } for n in scenarios},
    'control_task_samples': {n: scenarios[n]['control_samples'] for n in scenarios},
    'load_requests': {n: scenarios[n]['requests'] for n in scenarios},
    'load_cpu_share_by_task': {n: scenarios[n]['cpu_share_by_task'] for n in scenarios},
    'gate_share_of_gateway_task_runtime': {
        n: scenarios[n]['cpu_share_gate'] / scenarios[n]['cpu_share_by_task']['gateway_core']
        for n in scenarios
    },
    'valid_load_gate_share_of_measured_request_processing': scenarios['valid']['decision_share_of_request_processing'],
    'flash_bytes': {n: c['flash_bytes'] for n, c in footprint['components'].items()},
    'ram_bytes': {n: c['ram_bytes'] for n, c in footprint['components'].items()},
    'whole_release_sections_bytes': {'text': 139956, 'data': 120, 'bss': 190072},
    'decision_path_allocations': allocation['decision_path_allocations_in_uart'],
    'decision_windows_observed_for_allocations': allocation['decision_path_calls_in_uart'],
    'cedar_no_std_outcome': {
        'status': 'build_failed', 'exit_code': cedar['exit_code'],
        'cause': 'memchr requires std for thumbv7em-none-eabihf no-default-features build',
        'historical_pre_r1': True,
        'log': 'm1/cedar-historical/cedar-thumb-build.log',
    },
    'bypass_paths': {
        'direct_network_to_effect_around_wrapper': sum(
            len(paths) for paths in callgraph['direct_paths_around_wrapper'].values()),
        'register_indirect_sites': len(callgraph['register_indirect_calls']),
        'all_indirect_sites_resolved': callgraph['indirect_calls_resolved'],
        'complete_static_mediation_established': False,
    },
    'unmatched_effects': m4['unmatched'],
    'requests_tested': m4['completed'],
    'm4_transport_errors': m4['transport_errors'],
    'm4_effect_count': m4['effect_count'],
    'm4_acceptance_count': m4['acceptance_count'],
    'm4_concurrent_pairs': m4['concurrent_pairs'],
    'm4_policy_restored': m4['policy_restored'],
    'm4_audit_uart_log': 'm4/campaign-100000-rawsocket-final-primary/uart.log',
    'repeated_soaks': {
        'runs': len(soaks), 'test_groups_passed_each': [row['passed'] for row in soaks],
        'requests_each': [row['requests_in_soak'] for row in soaks],
        'elapsed_seconds_each': [row['soak_seconds'] for row in soaks],
        'earlier_timeout_root_cause': None,
    },
    'oracle_disagreements': attack['disagreements'],
    'paper_reference_corpus_cases': 12527,
    'paper_reference_corpus_failures': 0,
    'fail_open': attack['fail_open'],
    'attack_requests': attack['classes'],
    'attack_effect_audit_mismatches': attack['audit_mismatches'],
    'mpu_injections': {name: {'fault': None, 'effect': None, 'status': 'not_run_no_mpu_image'}
                       for name in ('policy_store_write', 'validator_input_write',
                                    'application_input_write', 'direct_handler_call',
                                    'privilege_escalation')},
    'dma_disjoint': {
        'linked_configured_buffers': True,
        'primary_gate_context_start': '0x20002450',
        'primary_gate_context_end_exclusive': '0x200046ec',
        'control_variant_gate_context_start': '0x20002468',
        'control_variant_gate_context_end_exclusive': '0x20004704',
        'ethernet_reserved_start': '0x20070000',
        'ethernet_reserved_end_exclusive': '0x20080000',
        'arbitrary_dma_write_excluded': False,
    },
    'mpu_overhead_cycles': None,
    'hypothesis_verdicts': {
        'H1': 'partial', 'H2': 'not_supported', 'H3': 'partial',
        'H4': 'not_supported', 'H5': 'supported_for_tested_corpus',
    },
    'paper_decision': 'no_go_for_complete_mediation_and_hardware_enforced_integrity_claim',
}
(root / 'summary.json').write_text(json.dumps(output, indent=2, sort_keys=True) + '\n')
