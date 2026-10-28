#!/usr/bin/env python3
"""Explain the privileged-inventory change final2 -> A1v at function level.

Runs d1_privileged_inventory.py unchanged (via runpy) on each ELF, with the tool
version that produced that image's inventory: 76879e2 for final2, the current
tool (with run_target_reset) for A1v. Reads the union closure, sizes and
indirect sites from the tool's own globals and writes the set difference."""
from pathlib import Path
import json, runpy, subprocess, sys, tempfile

root = Path('/home/iamfo470/stm32-projects/policy_gate')
evidence = root / 'Gateway/Validation'
images = {
    'final2': (evidence / 'paper-evidence-d1-blob-2026-10-11/v11-verified-gate-final2/policy_gate.elf', '76879e2'),
    'a1v': (evidence / 'paper-evidence-a1v-final-2026-10-28/v11-verified-gate-a1v/policy_gate.elf', 'HEAD'),
}
out = Path(sys.argv[1])

def inventory(elf, rev):
    with tempfile.TemporaryDirectory() as tmp:
        tool = Path(tmp) / 'd1_privileged_inventory.py'
        tool.write_text(subprocess.check_output(
            ['git', 'show', f'{rev}:Gateway/tools/d1_privileged_inventory.py'], cwd=root, text=True))
        sys.argv = [str(tool), str(elf), '--output', str(Path(tmp) / 'inventory.json')]
        g = runpy.run_path(str(tool), run_name='__main__')
    functions = {f: {'bytes': g['sizes'].get(f, 0), 'indirect': g['indirect'].get(f, [])} for f in g['all_priv']}
    return g['report'], functions

result = {}
data = {name: inventory(elf, rev) for name, (elf, rev) in images.items()}
(r0, f0), (r1, f1) = data['final2'], data['a1v']
added = sorted(set(f1) - set(f0))
removed = sorted(set(f0) - set(f1))
common = sorted(set(f0) & set(f1))
resized = [{'function': f, 'final2': f0[f]['bytes'], 'a1v': f1[f]['bytes']}
           for f in common if f0[f]['bytes'] != f1[f]['bytes']]
indirect_changed = [{'function': f, 'final2': len(f0[f]['indirect']), 'a1v': len(f1[f]['indirect'])}
                    for f in common if len(f0[f]['indirect']) != len(f1[f]['indirect'])]
def rows(fs, src):
    return [{'function': f, 'bytes': src[f]['bytes'], 'indirect_sites': src[f]['indirect']} for f in fs]
result = {
    'tool_revisions': {k: v[1] for k, v in images.items()},
    'union': {'final2': r0['privileged_union'], 'a1v': r1['privileged_union']},
    'tasks': {'final2': sorted(r0['privileged_tasks']), 'a1v': sorted(r1['privileged_tasks'])},
    'isrs': {'final2': sorted(r0['isr_roots']), 'a1v': sorted(r1['isr_roots'])},
    'added_functions': rows(added, f1),
    'removed_functions': rows(removed, f0),
    'resized_common_functions': resized,
    'indirect_count_changed_common_functions': indirect_changed,
    'bytes': {'added': sum(f1[f]['bytes'] for f in added), 'removed': sum(f0[f]['bytes'] for f in removed),
              'resized_delta': sum(r['a1v'] - r['final2'] for r in resized)},
    'indirect_sites': {'added': sum(len(f1[f]['indirect']) for f in added),
                       'removed': sum(len(f0[f]['indirect']) for f in removed),
                       'common_delta': sum(r['a1v'] - r['final2'] for r in indirect_changed)},
    'per_root': {k: {'final2': {x: r0[k].get(n, {}).get(x) for x in ('functions', 'code_bytes')} | {'indirect': len(r0[k].get(n, {}).get('indirect_call_sites', []))} if n in r0[k] else None,
                     'a1v': {x: r1[k].get(n, {}).get(x) for x in ('functions', 'code_bytes')} | {'indirect': len(r1[k].get(n, {}).get('indirect_call_sites', []))} if n in r1[k] else None}
                 for k in ('privileged_tasks', 'isr_roots') for n in sorted(set(r0[k]) | set(r1[k])) for k in [k]}
}
# per_root keyed by root name only (task and ISR names do not collide)
result['per_root'] = {n: {'final2': (lambda r: r and {'functions': r['functions'], 'code_bytes': r['code_bytes'], 'indirect': len(r['indirect_call_sites'])})(r0[k].get(n)),
                          'a1v': (lambda r: r and {'functions': r['functions'], 'code_bytes': r['code_bytes'], 'indirect': len(r['indirect_call_sites'])})(r1[k].get(n))}
                      for k in ('privileged_tasks', 'isr_roots') for n in sorted(set(r0[k]) | set(r1[k]))}
out.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: result[k] for k in ('union', 'bytes', 'indirect_sites')}))
print('added', [(r['function'], r['bytes'], len(r['indirect_sites'])) for r in result['added_functions']])
print('removed', [(r['function'], r['bytes'], len(r['indirect_sites'])) for r in result['removed_functions']])
print('resized', [(r['function'], r['final2'], r['a1v']) for r in resized])
print('indirect changed', indirect_changed)
