#!/usr/bin/env python3
"""Conservative linked-image inventory for the paper's mediation audit.

Direct branches are checked mechanically. Register-indirect calls are listed,
not silently treated as safe edges. Their targets need separate resolution.
"""
from pathlib import Path
import argparse
import json
import re
import subprocess
import tempfile

COMPILER = Path('/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin')


def arm(tool, *args):
    return subprocess.check_output([str(COMPILER / ('arm-none-eabi-' + tool)), *map(str, args)], text=True)


p = argparse.ArgumentParser()
p.add_argument('elf', type=Path)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
elf = a.elf.resolve()
symbols = {}
for line in arm('nm', '-n', '--defined-only', elf).splitlines():
    match = re.fullmatch(r'([0-9a-f]+)\s+([TtWw])\s+(\S+)', line)
    if match:
        symbols[int(match[1], 16)] = match[3]

with tempfile.TemporaryDirectory(prefix='gateway-vectors-') as tmp:
    raw = Path(tmp) / 'vectors.bin'
    subprocess.run([str(COMPILER / 'arm-none-eabi-objcopy'),
                    '--dump-section', f'.isr_vector={raw}', str(elf)], check=True)
    data = raw.read_bytes()
assert len(data) % 4 == 0
vectors = []
for slot in range(1, len(data) // 4):
    address = int.from_bytes(data[4 * slot:4 * slot + 4], 'little')
    if address:
        vectors.append({'slot': slot, 'address': f'0x{address:08x}',
                        'symbol': symbols.get(address & ~1, 'UNRESOLVED')})

disassembly = arm('objdump', '-d', '--no-show-raw-insn', elf)
edges = {}
indirect = []
current = None
for line in disassembly.splitlines():
    header = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
    if header:
        current = header[2]
        edges.setdefault(current, set())
        continue
    if current is None:
        continue
    ins = re.match(r'\s*([0-9a-f]+):\s+(\S+)\s+(.*)', line)
    if not ins:
        continue
    address, op, operands = ins.groups()
    target = re.search(r'<([^>]+)>', operands)
    branch = (op in ('bl', 'blx', 'bl.w', 'blx.w', 'b', 'b.w', 'b.n') or
              re.fullmatch(r'b(?:eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(?:\.[nw])?', op))
    if branch and target:
        name = target[1].split('+')[0]
        if name != current or op.startswith('bl'):
            edges[current].add(name)
    elif op in ('bl', 'blx', 'bl.w', 'blx.w') or (op in ('bx', 'bx.w') and operands.strip() != 'lr'):
        indirect.append({'caller': current, 'address': f'0x{address}',
                         'instruction': f'{op} {operands}'})


def reachable_without(start, barrier):
    seen = set()
    pending = [start]
    while pending:
        node = pending.pop()
        if node == barrier or node in seen:
            continue
        seen.add(node)
        pending.extend(edges.get(node, ()))
    return seen


effects = {'Mediation_Extern_invoke', 'gateway_dispatch', 'gateway_login',
           'gateway_evaluate', 'pipeline_process'}
network_entries = ('serve', 'gateway_http_feed', 'gateway_http_process',
                   'ETH_IRQHandler', 'input_thread', 'tcpip_thread')
direct_paths = {}
indirect_reachable = {}
for entry in network_entries:
    assert entry in edges, f'missing network entry {entry}'
    reached = reachable_without(entry, 'Mediation_Wrapper_run')
    direct_paths[entry] = sorted(reached & effects)
    indirect_reachable[entry] = [site for site in indirect if site['caller'] in reached]

# These are registration sites, not a proof that the pointed-to targets or all
# dynamic registrations have been resolved. The raw indirect inventory remains.
registrations = {}
root = Path(__file__).resolve().parents[2]
for name in ('Gateway/Platform/gateway_platform.c', 'Gateway/Network/ethernetif.c',
             'Gateway/Network/gateway_network.c'):
    source = root / name
    registrations[name] = [f'{i}: {line.strip()}' for i, line in
                           enumerate(source.read_text().splitlines(), 1)
                           if re.search(r'\b(?:osThreadNew|tcpip_init|netifapi_netif_add|netconn_accept|HAL_ETH_\w*Callback|sys_thread_new)\b', line)]

report = {
    'elf': str(elf),
    'vector_table_slots': len(data) // 4,
    'nonzero_vectors': vectors,
    'source_registration_sites': registrations,
    'network_entries_checked': list(network_entries),
    'protected_effects_checked': sorted(effects),
    'direct_paths_around_wrapper': direct_paths,
    'indirect_sites_reachable_around_wrapper': indirect_reachable,
    'register_indirect_calls': indirect,
    'indirect_calls_resolved': False,
    'verdict': 'partial' if indirect else 'direct_calls_only',
    'limits': 'Direct branch inventory is mechanical; register-indirect calls, task registration, callbacks, and memory writes still require resolution. Startup self-tests have intentional direct handler calls outside network ingress.',
}
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(report, indent=2) + '\n')
if any(direct_paths.values()):
    raise SystemExit('Network entry has a direct path to a protected effect around the wrapper')
print(f'No direct network bypass; {len(indirect)} indirect call sites remain unresolved')
