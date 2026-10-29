#!/usr/bin/env python3
"""Variant comparison (variants-summary.json): decision timing, critical sections and
deadline misses at 1/4/10 kHz, and code/ITCM size.
A0  = newlib-nano byte-loop memcpy/memset in flash (the original images);
A1v = GATEWAY_FAST_MEMOPS: memcpy/memset on Low*-verified loops, 32-byte aligned, flash
      (the baseline since 2026-10-22);
A2v = A1v + GATEWAY_ITCM: queue.c, the verified memops, gate and update gate in ITCM RAM;
A1, A2 = the earlier hand-written word-at-a-time memops (superseded by A1v/A2v; kept as
      a record)."""
import glob, json, re, subprocess, sys
from pathlib import Path
V = Path(sys.argv[1])
BIN = Path(sorted(glob.glob('/opt/st/stm32cubeide_2.0.0/plugins/*gnu-tools-for-stm32*/tools/bin'))[0])
# name: (timing prefix, attribution-image prefix or None, no-attribution prefix, second timing build)
VARIANTS = {
    'A0': ('', '', 'a0-', 'timing-dist-scalance32'),
    'A1v': ('a1v-', None, 'a1v-', 'a1v-timing-dist-scalance32'),
    'A2v': ('a2v-', None, 'a2v-', None),
    'A1': ('a1-', 'a1-', 'a1-', None),
    'A2': ('a2-', 'a2-', 'a2-', None),
}
TIMING_CASES = ['decide/n1/first', 'decide/n1/worst', 'decide/n53/worst', 'update/n1/valid', 'update/n1/wrong_role']
LOADS = ('idle', 'valid', 'denied', 'malformed')


def nm(elf):
    out = subprocess.check_output([str(BIN / 'arm-none-eabi-nm'), '-S', str(elf)], text=True)
    syms = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) == 4:
            syms[f[3]] = (int(f[0], 16), int(f[1], 16))
    return syms


def sections(elf):
    out = subprocess.check_output([str(BIN / 'arm-none-eabi-size'), '-A', str(elf)], text=True)
    return {f[0]: int(f[1]) for f in (l.split() for l in out.splitlines()) if len(f) == 3 and f[1].isdigit()}


def where(elf, addr):
    w = subprocess.check_output([str(BIN / 'arm-none-eabi-addr2line'), '-f', '-p', '-e', str(elf),
                                 '%x' % (addr & ~1)], text=True).strip()
    return w.split(' at ')[0] + ' ' + w.split('/')[-1]


def timing(directory, cases):
    s = json.loads((V / directory / 'summary.json').read_text())
    t = {'boots': len(s['boots'])}
    for case in cases:
        for irq in ('off', 'on'):
            c = s['cases'][f'{case}/irq-{irq}']
            t[f'{case}/irq-{irq}'] = {k: c[k] for k in ('best_min', 'mean_of_means', 'worst_max', 'max_range',
                                                       'answers', 'boots')}
    return t


out = {'claim': 'observed DWT cycle counts on one NUCLEO-F767ZI at 96 MHz, caches off; not WCET. '
                'control.attribution: critical-section maxima and callers from attribution images '
                '(*crit-control-*); control.deadline: misses (late + collapsed releases), release-to-run '
                'latency and critical-section maxima from images without attribution '
                '(*-norank-control-*, GATEWAY_R4_CRIT_RANK=0), because the attribution observer runs '
                'with interrupts masked and inflates latency',
       'variants': {}}
for var, (tpre, apre, npre, second) in VARIANTS.items():
    if not (V / f'{tpre}timing-dist-opnsense53' / 'summary.json').exists():
        print('skip', var, '(not measured in this campaign)'); continue
    entry = {'timing': timing(f'{tpre}timing-dist-opnsense53', TIMING_CASES), 'control': {}}
    if second:
        entry['timing_scalance32'] = timing(second, [c.replace('n53', 'n32') for c in TIMING_CASES])
    elf = V / f'{tpre}timing-dist-opnsense53' / 'policy_gate.elf'
    sec, syms = sections(elf), nm(elf)
    entry['size'] = {'text_flash': sec.get('.text', 0) + sec.get('.privileged_functions', 0) +
                     sec.get('.freertos_system_calls', 0) + sec.get('.itcm_priv', 0) + sec.get('.itcm_shared', 0),
                     'itcm_priv': sec.get('.itcm_priv', 0), 'itcm_shared': sec.get('.itcm_shared', 0),
                     'itcm_free_of_16384': 16384 - sec.get('.itcm_priv', 0) - sec.get('.itcm_shared', 0),
                     'memcpy': {'addr': hex(syms['memcpy'][0]), 'size': syms['memcpy'][1]},
                     'memset': {'addr': hex(syms['memset'][0]), 'size': syms['memset'][1]}}
    for hz in (1000, 4000, 10000):
        for b in (0, 1):
            row = {'attribution': {}, 'deadline': {}}
            img = V / f'{apre}crit-control-{hz}-bucket{b}' if apre is not None else None
            if img is not None and img.is_dir():
                ielf = img / 'policy_gate.elf'
                m = nm(ielf)['memcpy'][0]
                row['attribution_memcpy'] = {'addr': hex(m), 'mod32': m % 32}
                for sc in LOADS:
                    r = json.loads((img / sc / 'summary.json').read_text())
                    text = (img / sc / 'uart.bin').read_bytes().decode(errors='replace')
                    ranks = [(int(x[2]), int(x[1], 16)) for x in re.finditer(
                        r'\[CRIT\] rank=\d+ caller=(0x[0-9a-f]+) task=0x[0-9a-f]+ max_cycles=(\d+)', text)]
                    top = max(ranks) if ranks else None
                    row['attribution'][sc] = {'critical_max_cycles': r.get('critical_max_cycles'),
                                              'top_caller': where(ielf, top[1]) if top else None}
            nr = V / f'{npre}norank-control-{hz}-bucket{b}'
            m = nm(nr / 'policy_gate.elf')['memcpy'][0]
            row['deadline_memcpy'] = {'addr': hex(m), 'mod32': m % 32}
            for sc in LOADS:
                r = json.loads((nr / sc / 'summary.json').read_text())
                d = {k: r.get(k) for k in ('max_cycles', 'p99_cycles', 'critical_max_cycles',
                                           'requests_during_sample_window')}
                ctrl = re.search(r'\[CTRL R4\] hz=\d+ high=\d+ samples=\d+ misses=(\d+) lost_releases=(\d+)',
                                 (nr / sc / 'uart.bin').read_bytes().decode(errors='replace'))
                assert int(ctrl[1]) == r['misses'], (nr, sc)
                # As in the 2026-09-30 control matrix: total = late releases + releases
                # collapsed while the timer interrupt was masked.
                d.update(late=int(ctrl[1]), lost=int(ctrl[2]), misses=int(ctrl[1]) + int(ctrl[2]))
                row['deadline'][sc] = d
            entry['control'][f'{hz}/bucket{b}'] = row
    out['variants'][var] = entry
(V / 'variants-summary.json').write_text(json.dumps(out, indent=2) + '\n')

print('timing OPNsense (irq-off max | irq-on max)')
for case in TIMING_CASES:
    print(f'  {case:22}', ' | '.join(f"{v}: {e['timing'][case + '/irq-off']['worst_max']:>7} on {e['timing'][case + '/irq-on']['worst_max']:>7}"
                                    for v, e in out['variants'].items()))
for v, e in out['variants'].items():
    if 'timing_scalance32' in e:
        print(f'  SCALANCE {v}:', {k: c['worst_max'] for k, c in e['timing_scalance32'].items() if k.endswith('irq-off')})
print('control (no attribution): crit max / misses (late+lost) / max latency, loaded scenarios')
for v, e in out['variants'].items():
    for key, row in e['control'].items():
        cells = ' '.join(f"{sc}={x['critical_max_cycles']}/{x['late']}+{x['lost']}/{x['max_cycles']}"
                         for sc, x in row['deadline'].items())
        print(f'  {v:4} {key:14} memcpy%32={row["deadline_memcpy"]["mod32"]:2} {cells}')
for v, e in out['variants'].items():
    print(v, 'size', {k: e['size'][k] for k in ('text_flash', 'itcm_priv', 'itcm_shared', 'itcm_free_of_16384')})
