#!/usr/bin/env python3
"""A0/A1/A2 comparison (variants-summary.json): decision timing, control matrix with
critical-section attribution, and code/ITCM size.
A0 = newlib-nano byte-loop memcpy/memset from flash (baseline images);
A1 = GATEWAY_FAST_MEMOPS (word-at-a-time memops, flash);
A2 = A1 + GATEWAY_ITCM (queue.c, memops, gate and update gate executing from ITCM RAM)."""
import glob, json, re, subprocess, sys
from pathlib import Path
V = Path(sys.argv[1])
BIN = Path(sorted(glob.glob('/opt/st/stm32cubeide_2.0.0/plugins/*gnu-tools-for-stm32*/tools/bin'))[0])
PREFIX = {'A0': '', 'A1': 'a1-', 'A2': 'a2-'}
TIMING_CASES = ['decide/n1/first', 'decide/n1/worst', 'decide/n53/worst', 'update/n1/valid', 'update/n1/wrong_role']


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


out = {'claim': 'observed DWT cycle counts on one NUCLEO-F767ZI at 96 MHz, caches off; not WCET. '
                'control.scenarios: critical-section maxima and callers from attribution images '
                '(*crit-control-*); control.deadline: misses and release-to-run latency from images '
                'without attribution (*-norank-control-*, GATEWAY_R4_CRIT_RANK=0), because the '
                'attribution observer runs with interrupts masked and inflates latency',
       'variants': {}}
for var, pre in PREFIX.items():
    entry = {'timing': {}, 'control': {}, 'size': {}}
    timing = V / f'{pre}timing-dist-opnsense53'
    s = json.loads((timing / 'summary.json').read_text())
    entry['timing']['boots'] = len(s['boots'])
    for case in TIMING_CASES:
        for irq in ('off', 'on'):
            c = s['cases'][f'{case}/irq-{irq}']
            entry['timing'][f'{case}/irq-{irq}'] = {k: c[k] for k in
                                                    ('best_min', 'mean_of_means', 'worst_max', 'max_range', 'answers', 'boots')}
    elf = timing / 'policy_gate.elf'
    sec, syms = sections(elf), nm(elf)
    entry['size'] = {'text_flash': sec.get('.text', 0) + sec.get('.privileged_functions', 0) +
                     sec.get('.freertos_system_calls', 0) + sec.get('.itcm_priv', 0) + sec.get('.itcm_shared', 0),
                     'itcm_priv': sec.get('.itcm_priv', 0), 'itcm_shared': sec.get('.itcm_shared', 0),
                     'itcm_free_of_16384': 16384 - sec.get('.itcm_priv', 0) - sec.get('.itcm_shared', 0),
                     'memcpy': {'addr': hex(syms['memcpy'][0]), 'size': syms['memcpy'][1]},
                     'memset': {'addr': hex(syms['memset'][0]), 'size': syms['memset'][1]}}
    for hz in (1000, 4000, 10000):
        for b in (0, 1):
            img = V / f'{pre}crit-control-{hz}-bucket{b}'
            if not img.is_dir():
                continue
            ielf = img / 'policy_gate.elf'
            m = nm(ielf)['memcpy'][0]
            row = {'memcpy_addr': hex(m), 'memcpy_mod32': m % 32, 'scenarios': {}}
            for sc in ('idle', 'valid', 'denied', 'malformed'):
                f = img / sc / 'summary.json'
                if not f.is_file():
                    continue
                r = json.loads(f.read_text())
                text = (img / sc / 'uart.bin').read_bytes().decode(errors='replace')
                ranks = [(int(x[2]), int(x[1], 16)) for x in re.finditer(
                    r'\[CRIT\] rank=\d+ caller=(0x[0-9a-f]+) task=0x[0-9a-f]+ max_cycles=(\d+)', text)]
                top = max(ranks) if ranks else None
                row['scenarios'][sc] = {'critical_max_cycles': r.get('critical_max_cycles'),
                                        'misses': r.get('misses'),
                                        'release_to_completion_max_cycles': r.get('max_cycles'),
                                        'p99_cycles': r.get('p99_cycles'),
                                        'requests': r.get('requests_during_sample_window'),
                                        'top_caller': where(ielf, top[1]) if top else None}
            nr = V / f'{var.lower()}-norank-control-{hz}-bucket{b}'
            row['deadline'] = {}
            for sc in ('idle', 'valid', 'denied', 'malformed'):
                f = nr / sc / 'summary.json'
                if f.is_file():
                    r = json.loads(f.read_text())
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

print('timing (irq-off min/mean/max | irq-on max)')
for case in TIMING_CASES:
    print(' ', case, ' | '.join(
        f"{v}: {e['timing'][case + '/irq-off']['best_min']}/{e['timing'][case + '/irq-off']['mean_of_means']:.0f}/"
        f"{e['timing'][case + '/irq-off']['worst_max']} on-max {e['timing'][case + '/irq-on']['worst_max']}"
        for v, e in out['variants'].items()))
print('control: attribution-image crit_max | no-attribution misses/max_latency per scenario')
for key in out['variants']['A0']['control'] | out['variants']['A2']['control']:
    for v, e in out['variants'].items():
        row = e['control'].get(key)
        if row:
            cells = ' '.join(f"{sc}={x['critical_max_cycles']}" for sc, x in row['scenarios'].items())
            cells += ' | ' + ' '.join(f"{sc}={x['late']}+{x['lost']}/{x['max_cycles']}" for sc, x in row['deadline'].items())
            print(f'  {key:14} {v} memcpy%32={row["memcpy_mod32"]:2} {cells}')
for v, e in out['variants'].items():
    print(v, 'size', e['size'])
