#!/usr/bin/env python3
"""Aggregate exact-image D1 release, ISR and critical-section evidence."""
from pathlib import Path
import csv
import json

root = Path(__file__).resolve().parents[2]
out = root / 'Gateway/Validation/paper-evidence-d1-2026-09-30'
rows = []
for hz in (1000, 4000, 10000):
    for bucket in (1, 0):
        directory = out / f'd1-control-{hz}-bucket{bucket}'
        image_hash = None
        idle = None
        for scenario in ('idle', 'valid', 'denied', 'malformed'):
            data = json.loads((directory / scenario / 'summary.json').read_text())
            assert data['control_hz'] == hz and data['samples'] == 10000
            assert data['control_above_gate'] and data['critical_anomalies'] == 0
            assert image_hash is None or image_hash == data['elf_sha256']
            image_hash = data['elf_sha256']
            if scenario == 'idle':
                idle = data
            elif data['requests_during_sample_window'] == 0:
                raise AssertionError(f'{directory}/{scenario} had no loaded traffic')
            row = {
                'hz': hz, 'bucket': bucket, 'scenario': scenario,
                'elf_sha256': image_hash,
                'idle_misses': idle['total_misses'],
                'total_misses': data['total_misses'],
                'interference_misses': data['total_misses'] - idle['total_misses'],
                'late_delivered': data['misses'],
                'collapsed_releases': data['lost_releases'],
                'gap_anomalies': data['gap_anomalies'],
                'requests_in_window': data['requests_during_sample_window'],
                'request_rate_hz': data['achieved_request_rate_hz'],
                'status_mismatches': data['window_status_mismatches'],
                'transport_errors': data['window_transport_errors'],
                'max_latency_cycles': data['max_cycles'],
                'critical_max_cycles': data['critical_max_cycles'],
                'timer_isr_max_cycles': data['isr_max_cycles'],
                'ethernet_isr_max_cycles': data['eth_isr_max_cycles'],
                'ethernet_irqs': data['eth_isr_count'],
                'uart_sha256': data['uart_sha256'],
            }
            rows.append(row)
assert len(rows) == 24
assert all(row['total_misses'] == 0 and row['gap_anomalies'] == 0
           for row in rows if row['hz'] in (1000, 4000))
(out / 'control-matrix.json').write_text(json.dumps(rows, indent=2) + '\n')
with (out / 'control-matrix.csv').open('w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=rows[0])
    writer.writeheader()
    writer.writerows(rows)
for row in rows:
    print(row['hz'], row['bucket'], row['scenario'],
          'misses', row['total_misses'], 'requests', row['requests_in_window'],
          'critical', row['critical_max_cycles'])
