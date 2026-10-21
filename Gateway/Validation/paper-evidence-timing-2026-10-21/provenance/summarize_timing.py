#!/usr/bin/env python3
"""Summarise [GATE-DIST] lines across fresh boots of one timing variant into summary.json."""
import json, re, statistics, sys
from pathlib import Path
variant = Path(sys.argv[1])
pat = re.compile(r'\[GATE-DIST\] what=(\w+) n=(\d+) case=(\w+) irq=(on|off) answer=(\d+) samples=(\d+) '
                 r'min=(\d+) mean=(\d+) p50=(\d+) p99=(\d+) max=(\d+)')
rows, boots = {}, []
for boot in sorted(variant.glob('boot*')):
    if not (boot / 'uart-raw.log').is_file():
        continue
    log = (boot / 'uart-raw.log').read_text(errors='replace')
    if '[GATE-DIST] done' not in log:
        continue
    hz = re.search(r'\[GATE-DIST\] done .*core_hz=(\d+) overflow16=(\d+)', log)
    boots.append({'boot': boot.name, 'core_hz': int(hz[1]), 'overflow16': int(hz[2])})
    for m in pat.finditer(log):
        what, n, case, irq = m[1], int(m[2]), m[3], m[4]
        v = dict(zip(('answer', 'samples', 'min', 'mean', 'p50', 'p99', 'max'), map(int, m.groups()[4:])))
        rows.setdefault(f'{what}/n{n}/{case}/irq-{irq}', []).append(v)
summary = {}
for key, vs in sorted(rows.items()):
    summary[key] = {
        'boots': len(vs), 'samples_per_boot': vs[0]['samples'],
        'answers': sorted({v['answer'] for v in vs}),
        'best_min': min(v['min'] for v in vs),
        'mean_of_means': round(statistics.mean(v['mean'] for v in vs), 1),
        'median_p50': statistics.median(v['p50'] for v in vs),
        'max_p99': max(v['p99'] for v in vs),
        'worst_max': max(v['max'] for v in vs),
        'max_range': [min(v['max'] for v in vs), max(v['max'] for v in vs)],
    }
out = {'variant': variant.name, 'clock_hz': boots[0]['core_hz'] if boots else None,
       'boots': boots, 'cases': summary,
       'claim': 'observed DWT cycle counts, not WCET; empty bracket reported separately (not subtracted)'}
(variant / 'summary.json').write_text(json.dumps(out, indent=2) + '\n')
print(variant.name, len(boots), 'boots')
for k, v in summary.items():
    print(f"{k:38} min={v['best_min']:>7} mean={v['mean_of_means']:>9} p99={v['max_p99']:>7} max={v['worst_max']:>7}")
