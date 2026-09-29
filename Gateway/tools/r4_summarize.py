#!/usr/bin/env python3
"""Summarize retained R4 board measurements; never substitute missing runs."""
from pathlib import Path
import csv
import json
import statistics

root=Path(__file__).resolve().parents[2]
out=root/'Gateway/Validation/paper-evidence-r4-2026-09-29'
rows=[]
for variant in ('V0','V1','V2'):
    for hz in (1000,4000,10000):
        for priority in ('above','below'):
            directory=out/f'r4-control-{variant.lower()}-{hz}-{priority}'
            manifest=json.loads((directory/'source-manifest.json').read_text())
            for scenario in ('idle','valid','denied','malformed'):
                selected=scenario
                if variant=='V0' and hz==1000 and priority=='above' and scenario=='valid':
                    selected='valid-recount'
                if variant=='V1' and hz==1000 and priority=='below' and scenario=='valid':
                    selected='valid-retry2'
                summary=json.loads((directory/selected/'summary.json').read_text())
                assert summary['elf_sha256']==manifest['elf_sha256'],directory
                assert summary['clock_hz']==(96000000 if variant=='V0' else 216000000)
                assert summary['control_hz']==hz and summary['control_above_gate']==(priority=='above')
                assert summary['samples']==10000 and summary['misses']==summary['misses_recomputed']
                assert summary.get('window_status_mismatches',0)==0
                assert summary.get('window_transport_errors',0)==0
                rows.append({'variant':variant,'clock_hz':summary['clock_hz'],
                    'control_hz':hz,'priority':priority,'scenario':scenario,
                    'selected_capture':selected,'elf_sha256':manifest['elf_sha256'],
                    'misses':summary['misses'],'samples':summary['samples'],
                    'min_cycles':summary['min_cycles'],'median_cycles':summary['median_cycles'],
                    'p99_cycles':summary['p99_cycles'],'p999_cycles':summary['p999_cycles'],
                    'max_cycles':summary['max_cycles'],
                    'critical_max_cycles':summary['critical_max_cycles'],
                    'requests':summary['requests_during_sample_window'],
                    'request_rate_hz':summary['achieved_request_rate_hz'],
                    'observed_window_seconds':summary.get('observed_window_seconds'),
                    'gate_task_share_percent':summary['runtime_task_share_percent'].get('gateway_gate',0),
                    'tcpip_task_share_percent':summary['runtime_task_share_percent'].get('TCP/IP',0),
                    'uart_path':str(directory/selected/'uart.bin'),
                    'jitter_path':str(directory/selected/'jitter-cycles.csv')})
assert len(rows)==72
with (out/'control-matrix.csv').open('w',newline='') as file:
    writer=csv.DictWriter(file,fieldnames=rows[0]);writer.writeheader();writer.writerows(rows)
max_zero={variant:max((row['request_rate_hz'] for row in rows
    if row['variant']==variant and row['scenario']=='valid' and row['misses']==0),default=0)
    for variant in ('V0','V1','V2')}
captures={variant:json.loads((out/name/'dwt/summary.json').read_text())
    for variant,name in [('V0','v0-96-off-os-field'),('V1','v1-216-cache-os-fixed'),
                         ('V2','v2-216-cache-o2'),('V0-masked','v0-96-off-os-field-masked')]}
headline={'variants':{},'control':{'rows':72,'samples':720000,
    'highest_observed_valid_rate_with_zero_control_misses_hz':max_zero,
    'selected_capture_notes':{'V0-1000-above-valid':'valid-recount',
        'V1-1000-below-valid':'valid-retry2; first capture HardFaulted, retry1 missed 894'}},
    'limitations':['DWT maxima are observations, not WCET',
        'The control sample is interrupt release to task run, not completion',
        'Each scenario has 10000 releases (10 s, 2.5 s, or 1 s)',
        'The host sends one sequential HTTP connection at a time']}
for variant,data in captures.items():
    first=data['statistics']['1:0'];full=data['statistics']['5:0']
    headline['variants'][variant]={'elf_sha256':data['firmware_elf_sha256'],
        'clock_hz':data['clock_hz'],'boots':len(data['boots']),
        'samples_per_case':first['n'],
        'first_allow_validator_cycles':first,
        'first_allow_full_request_cycles':full,
        'first_allow_original_serializer_cycles':data['statistics']['6:0'],
        'first_allow_field_serializer_cycles':data['statistics']['7:0']}
headline['control']['misses_by_variant_frequency_priority_scenario']={
    f"{r['variant']}:{r['control_hz']}:{r['priority']}:{r['scenario']}":r['misses'] for r in rows}
primary=out/'primary96-final'
primary_manifest=json.loads((primary/'source-manifest.json').read_text())
network=json.loads((primary/'network1000/test/summary.json').read_text())
attacks=json.loads((primary/'m5-attacks/test/summary.json').read_text())
with (primary/'soak5000/requests.csv').open() as file:
    soak=list(csv.DictReader(file))
assert len(soak)==5000 and all(row['status']=='200' and not row['error'] for row in soak)
latencies=sorted(float(row['latency_ms']) for row in soak)
headline['final_primary']={
    'elf_sha256':primary_manifest['elf_sha256'],
    'git_base':primary_manifest['git_base'],
    'dirty_tree_diff_sha256':primary_manifest['dirty_tree_diff_sha256'],
    'source_manifest_sha256':primary_manifest['source_manifest_sha256'],
    'clock_hz':96000000,'caches':'off','optimization':'-Os generated / Debug handwritten',
    'startup_selftests_passed':301,'onboard_reference_comparisons':12527,
    'network_suite':network,'attack_corpus':attacks,
    'http_client_soak':{'requests':5000,'failures':0,'min_ms':latencies[0],
        'median_ms':statistics.median(latencies),'p99_ms':latencies[4949],
        'max_ms':latencies[-1],
        'uart_path':str(primary/'soak5000/uart.log'),
        'requests_path':str(primary/'soak5000/requests.csv')}}
headline['hypothesis_verdicts']={'H1':'supported-within-tested-scope',
    'H2':'partial','H3':'partial','H4':'partial','H5':'supported-for-tested-corpus'}
(out/'summary.json').write_text(json.dumps(headline,indent=2)+'\n')
print('R4 summary:',len(rows),'control captures,',max_zero,'Hz zero-miss valid rate')
