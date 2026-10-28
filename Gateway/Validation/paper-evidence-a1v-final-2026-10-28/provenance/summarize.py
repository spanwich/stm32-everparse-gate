#!/usr/bin/env python3
"""Extract the Phase A metrics of final2 (A0) and the A1v primary image from
their evidence directories, with the same definitions for both, into
summary.json. Soak percentiles: nearest rank over the 200-status latencies
(reproduces final2's published 18.0 / 19.0 / 19.4 ms)."""
from pathlib import Path
import csv, hashlib, json, math, re, statistics, subprocess, sys

root = Path('/home/iamfo470/stm32-projects/policy_gate')
V = root / 'Gateway/Validation'
here = V / 'paper-evidence-a1v-final-2026-10-28'
images = {'final2': V / 'paper-evidence-d1-blob-2026-10-11/v11-verified-gate-final2',
          'a1v': here / 'v11-verified-gate-a1v'}
SIZE = Path('/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin/arm-none-eabi-size')

def text(p):
    return p.read_text(errors='replace') if p.is_file() else ''

def size(elf):
    t, d, b = subprocess.check_output([str(SIZE), str(elf)], text=True).splitlines()[1].split()[:3]
    return {'text': int(t), 'data': int(d), 'bss': int(b)}

def lastjson(p):
    """Last top-level JSON object printed in a stdout file."""
    s = text(p); i = s.rfind('\n{')
    return json.loads(s[i + 1:]) if i >= 0 else None

def heartbeat(log):
    lines = [l for l in log.splitlines() if l.startswith('[HEARTBEAT] PASS')]
    m = re.search(r'stack_free_bytes=(\d+)/(\d+) margin=(\S+) heap_free=(\d+) heap_min=(\d+) log_drops=(\d+)', lines[-1]) if lines else None
    return m and {'stack_free_core': int(m[1]), 'stack_free_diag': int(m[2]), 'margin': m[3],
                  'heap_free': int(m[4]), 'heap_min': int(m[5]), 'log_drops': int(m[6])}

def net(log):
    lines = [l for l in log.splitlines() if l.startswith('[NET]')]
    m = re.search(r'req=(\d+) rx=(\d+) tx=(\d+) drop=(\d+) txerr=(\d+) stack=(\d+)/(\d+)/(\d+) margin=(\S+) lwip=(\d+)/(\d+) err=(\d+)', lines[-1]) if lines else None
    return m and dict(zip(('req', 'rx', 'tx', 'drop', 'txerr', 'stack_free_tcpip', 'stack_free_eth_rx',
                           'stack_free_link', 'margin', 'lwip_cur', 'lwip_max', 'lwip_err'),
                          [int(x) if x.isdigit() else x for x in m.groups()]))

def faults(log):
    return len(re.findall(r'previous_fault|HardFault|MemManage|BusFault|UsageFault|PANIC|\[FAULT', log))

def summary(d):
    s = {}
    s['debug_elf_sha256'] = hashlib.sha256((d / 'policy_gate.elf').read_bytes()).hexdigest()
    s['release_elf_sha256'] = hashlib.sha256((d / 'release/policy_gate.elf').read_bytes()).hexdigest()
    s['size_debug'] = size(d / 'policy_gate.elf'); s['size_release'] = size(d / 'release/policy_gate.elf')
    s['git_base'] = json.loads(text(d / 'source-manifest.json'))['git_base']
    boot = text(d / 'board/uart-raw.log')
    boot = boot[boot.rfind('[BOOT] policy_gate'):]   # drop the previous image's output before the flash
    m = re.search(r'\[CORE SELFTEST\] PASS (\d+)/(\d+)', boot); s['selftests'] = m and f'{m[1]}/{m[2]}'
    m = re.search(r'\[PAPER CORPUS\] comparisons=(\d+) failures=(\d+)', boot)
    s['paper_corpus'] = m and {'line': m[0], 'comparisons': int(m[1]), 'failures': int(m[2])}
    s['board_acceptance'] = 'Fresh boot and UART acceptance PASS' in text(d / 'board.stdout')
    s['boot_heartbeat'] = heartbeat(boot); s['boot_faults'] = faults(boot)
    m = re.search(r'\[HEARTBEAT\] \S+ .*heap_free=(\d+) heap_min=(\d+)', boot)
    s['boot_first_heartbeat_heap'] = m and {'heap_free': int(m[1]), 'heap_min': int(m[2])}
    ns = json.loads(text(d / 'network-suite/summary.json'))
    out = text(d / 'network-suite.stdout')
    s['network_suite'] = {'passed': ns['passed'], 'pass_lines': out.count('\nPASS ') + out.startswith('PASS '),
                          'fail_lines': len(re.findall(r'^FAIL', out, re.M)),
                          'soak_200_seconds': round(ns['soak_seconds'], 3),
                          'suite_exit_code': lastjson(d / 'network-suite.stdout')['suite_exit_code']}
    uart = text(d / 'network-suite-uart/uart.log')
    s['network_suite_uart'] = {'faults': faults(uart), 'treset_lines': uart.count('[TRESET]'),
                               'last_net': net(uart), 'last_heartbeat': heartbeat(uart)}
    lp = text(d / 'live_policy-suite.stdout'); m = re.search(r'Live policy acceptance PASS (\d+)', lp)
    s['live_policy'] = {'passed': m and int(m[1]), 'fail_lines': len(re.findall(r'^FAIL', lp, re.M)),
                        'suite_exit_code': lastjson(d / 'live_policy-suite.stdout')['suite_exit_code']}
    db = json.loads(text(d / 'dashboard-suite/summary.json'))
    s['dashboard'] = {'passed': db['passed'], 'total': db['total'],
                      'authenticated_100_seconds': round(db['authenticated_100_seconds'], 3),
                      'html_sha256': db['html_sha256'],
                      'suite_exit_code': lastjson(d / 'dashboard-suite.stdout')['suite_exit_code']}
    at = json.loads(text(d / 'attacks-r1/summary.json'))
    s['attacks_r1'] = {k: at[k] for k in ('requests', 'disagreements', 'fail_open', 'audit_mismatches',
                                          'policy_preserved', 'policy_restored', 'corpus_sha256')}
    rows = list(csv.DictReader((d / 'soak/soak-5000.csv').open()))
    lat = sorted(float(r['latency_ms']) for r in rows if r['status'] == '200')
    s['soak_5000'] = {'requests': len(rows), 'ok': len(lat), 'errors': sum(1 for r in rows if r['error']),
                      'median_ms': round(statistics.median(lat), 3), 'p99_ms': lat[math.ceil(0.99 * len(lat)) - 1],
                      'max_ms': lat[-1], 'min_ms': lat[0],
                      'suite_exit_code': lastjson(d / 'soak-5000.stdout')['suite_exit_code']}
    a = d / 'e-p1-audit-100000'
    load = json.loads(text(a / 'load/summary.json'))
    req = list(csv.DictReader((a / 'load/requests.csv').open()))
    viol = [int(r['violations']) for r in req if r.get('violations') not in (None, '')]
    events = text(a / 'watch/events.log')
    s['audit'] = {k: load[k] for k in ('requested', 'completed', 'matched', 'unmatched', 'transport_errors',
                                       'effect_count', 'acceptance_count', 'unique_audit_ids', 'concurrent_pairs',
                                       'policy_restored', 'elf_sha256')}
    s['audit'].update({'elapsed_seconds': round(load['elapsed_seconds'], 1),
                       'effects_minus_acceptances': load['effect_count'] - load['acceptance_count'],
                       'rows': len(req), 'max_violations': max(viol) if viol else None,
                       'rows_with_violations': sum(1 for v in viol if v),
                       'hang': 'HANG' in events, 'stale_events': events.count('STALE'),
                       'watch_end': events.strip().splitlines()[-1] if events.strip() else None})
    ul = text(a / 'load/uart.log')
    s['audit_uart'] = {'faults': faults(ul), 'last_net': net(ul), 'last_heartbeat': heartbeat(ul)}
    sc = [json.loads(l) for l in text(d / 'socket-check-after-audit/socket-check.jsonl').splitlines() if l.strip()]
    after = [r for r in sc if r['tag'] == 'after']
    s['socket_check'] = {'probes': len(after), 'results': sorted({r['result'] for r in after}),
                         'netconn_err_max': max(r['NETCONN']['err'] for r in sc),
                         'netconn_used_max': max(r['NETCONN']['used'] for r in sc),
                         'tcp_pcb_err_max': max(r['TCP_PCB']['err'] for r in sc),
                         'tcp_pcb_used_max': max(r['TCP_PCB']['used'] for r in sc),
                         'tcp_pcb_avail': sc[0]['TCP_PCB']['avail'],
                         'active_max': max(len(r['active']) for r in sc)}
    inv = json.loads(text(d / 'e-map/privileged-inventory.json'))
    s['privileged_inventory'] = {'tasks': len(inv['privileged_tasks']), 'isrs': len(inv['isr_roots']),
                                 'indirect_sites': inv['privileged_union']['indirect_call_sites'],
                                 'functions': inv['privileged_union']['functions'],
                                 'code_bytes': inv['privileged_union']['code_bytes'],
                                 'kernel_privileged_section_bytes': inv['kernel_privileged_functions']['bytes'],
                                 'privileged_data_bytes': next(x['bytes'] for x in inv['sections'] if x['section'] == '.privileged_data')}
    return s

result = {name: summary(d) for name, d in images.items()}
# A0 at a4fbff0 (host build only, provenance/a0_reference_build.sh): splits the
# final2 -> A1v change into PA0 (final2 -> A0 at HEAD) and the verified memops.
ref = here / 'a0-reference'
inv = json.loads(text(ref / 'privileged-inventory.json'))
result['a0_reference_not_flashed'] = {
    'debug_elf_sha256': hashlib.sha256((ref / 'policy_gate.elf').read_bytes()).hexdigest(),
    'release_elf_sha256': hashlib.sha256((ref / 'release/policy_gate.elf').read_bytes()).hexdigest(),
    'size_debug': size(ref / 'policy_gate.elf'), 'size_release': size(ref / 'release/policy_gate.elf'),
    'privileged_inventory': {'tasks': len(inv['privileged_tasks']), 'isrs': len(inv['isr_roots']),
                             'indirect_sites': inv['privileged_union']['indirect_call_sites'],
                             'functions': inv['privileged_union']['functions'],
                             'code_bytes': inv['privileged_union']['code_bytes']}}
for name, d in images.items():
    boot = text(d / 'board/uart-raw.log'); boot = boot[boot.rfind('[BOOT] policy_gate'):]
    result[name]['boot_last_net'] = net(boot)
stages = []
for line in text(here / 'run-status.log').splitlines():
    m = re.match(r'\[(\S+)\] (rc=.*?|start): (.*)', line)
    if m:
        stages.append({'time': m[1], 'event': m[2], 'command': m[3][:160]})
result['run_status'] = stages
(here / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=1))
