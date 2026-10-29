#!/usr/bin/env python3
"""Summarise critical-section attribution per control image and scenario (crit-summary.json)."""
import glob, json, re, subprocess, sys
from pathlib import Path
V = Path(sys.argv[1])
A = sorted(glob.glob('/opt/st/stm32cubeide_2.0.0/plugins/*gnu-tools-for-stm32*/tools/bin/arm-none-eabi-addr2line'))[0]
N = A.replace('addr2line', 'nm')
out = {'claim': 'longest FreeRTOS task-level critical sections (vPortEnterCritical..vPortExitCritical, outermost) in the 10,000-release control window; caller = return address of vPortEnterCritical', 'images': {}}
for img in sorted(V.glob('crit-control-*')):
    elf = img / 'policy_gate.elf'
    syms = {l.split()[2]: l.split()[0] for l in subprocess.check_output([N, str(elf)], text=True).splitlines() if len(l.split()) == 3}
    entry = {'elf_sha256': json.loads((img / 'source-manifest.json').read_text())['elf_sha256'],
             'memcpy': '0x' + syms.get('memcpy', ''), 'memcpy_mod32': int(syms['memcpy'], 16) % 32, 'scenarios': {}}
    for sc in ('idle', 'valid', 'denied', 'malformed'):
        if not (img / sc / 'summary.json').is_file():
            continue
        s = json.loads((img / sc / 'summary.json').read_text())
        text = (img / sc / 'uart.bin').read_bytes().decode(errors='replace')
        ranks = []
        for m in re.finditer(r'\[CRIT\] rank=\d+ caller=(0x[0-9a-f]+) task=0x[0-9a-f]+ max_cycles=(\d+) count=(\d+)', text):
            where = subprocess.check_output([A, '-f', '-p', '-e', str(elf), '%x' % (int(m[1], 16) & ~1)], text=True).strip()
            ranks.append({'caller': m[1], 'where': where.split(' at ')[0] + ' ' + where.split('/')[-1], 'max_cycles': int(m[2]), 'count': int(m[3])})
        ranks.sort(key=lambda r: -r['max_cycles'])
        entry['scenarios'][sc] = {'critical_max_cycles': s.get('critical_max_cycles'), 'misses': s.get('misses'),
                                  'release_to_completion_max_cycles': s.get('max_cycles'), 'top_callers': ranks[:3]}
    out['images'][img.name] = entry
(V / 'crit-summary.json').write_text(json.dumps(out, indent=2) + '\n')
for k, e in out['images'].items():
    for sc, v in e['scenarios'].items():
        top = v['top_callers'][0] if v['top_callers'] else {}
        print(f"{k:34} {sc:9} crit={v['critical_max_cycles']:>6} top={top.get('where','-')} memcpy%32={e['memcpy_mod32']}")
