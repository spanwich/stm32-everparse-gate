#!/usr/bin/env python3
"""D1.8 E-map: region map and privileged-code inventory of a linked image.

Privileged roots are the tasks created with portPRIVILEGE_BIT (source sites
listed below), the ISRs in the vector table, and the kernel's privileged
function section. For each root the direct-branch closure is computed
mechanically from the disassembly, with its code size and every
register-indirect call site in it; indirect targets are listed, not resolved.
The core task and the TCP/IP thread start privileged and drop privilege after
setup, so their closures over-approximate the privileged phase.
"""
from pathlib import Path
import argparse, json, re, subprocess

TOOLS = Path('/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.'
             'gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin')
TASKS = {  # entry: (source site, privilege note)
    'run_logger': ('Gateway/Platform/gateway_platform.c:307', 'privileged'),
    'watchdog_task': ('Gateway/Platform/gateway_platform.c:310', 'privileged'),
    'run_core': ('Gateway/Platform/gateway_platform.c:319', 'privileged; drops privilege before serving HTTP (NET)'),
    'run_diagnostics': ('Gateway/Platform/gateway_platform.c:339', 'privileged'),
    'run_target_reset': ('Gateway/Platform/gateway_target_reset.c:97', 'privileged USART3 RX / TGT_NRST'),
    'rt_timing_task': ('Gateway/Paper/paper_runtime53.c:275', 'privileged DWT-timing worker (RUNTIME53 variant only)'),
    'cleanup_task': ('Gateway/Network/d1_kernel_cleanup.c:93', 'privileged kernel-object worker'),
    'tcpip_thread': ('Gateway/Network/sys_arch.c:553', 'privileged; drops privilege after network setup (NET)'),
    'input_thread': ('Gateway/Network/ethernetif.c:401', 'privileged SHIM RX'),
    'link_thread': ('Gateway/Network/ethernetif.c:404', 'privileged SHIM link/PHY'),
    'tx_thread': ('Gateway/Network/ethernetif.c:407', 'privileged SHIM TX'),
}
UNPRIVILEGED = {'gate_task': 'Gateway/Network/gateway_r4_boundary.c:282',
                'app_task': 'Gateway/Network/gateway_r4_boundary.c:265',
                'auth_task': 'Gateway/Auth/d1_auth_oracle.c:138',
                'net_input_thread': 'Gateway/Network/ethernetif.c:411'}

def arm(tool, *args):
    return subprocess.check_output([str(TOOLS / ('arm-none-eabi-' + tool)), *map(str, args)], text=True)

p = argparse.ArgumentParser()
p.add_argument('elf', type=Path)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
elf = a.elf.resolve()

sizes, addr_to_sym, sym_addr = {}, {}, {}
for line in arm('nm', '-S', '--defined-only', elf).splitlines():
    m = re.fullmatch(r'([0-9a-f]+)\s+([0-9a-f]+)\s+([TtWw])\s+(\S+)', line)
    if m:
        addr = int(m[1], 16); sizes[m[4]] = int(m[2], 16); addr_to_sym[addr] = m[4]; sym_addr[m[4]] = addr

edges, indirect, current = {}, {}, None
for line in arm('objdump', '-d', '--no-show-raw-insn', elf).splitlines():
    h = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
    if h:
        current = h[2]; edges.setdefault(current, set()); indirect.setdefault(current, []); continue
    ins = re.match(r'\s*([0-9a-f]+):\s+(\S+)\s+(.*)', line) if current else None
    if not ins:
        continue
    address, op, operands = ins.groups()
    target = re.search(r'<([^>+]+)', operands)
    is_branch = op in ('bl', 'blx', 'bl.w', 'b', 'b.w', 'b.n') or re.fullmatch(
        r'b(?:eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(?:\.[nw])?', op)
    if is_branch and target and target[1] != current:
        edges[current].add(target[1])
    elif op in ('blx', 'blx.w') or (op in ('bx', 'bx.w') and operands.strip() != 'lr'):
        indirect[current].append(f'0x{address}: {op} {operands.strip()}')

def closure(root):
    seen, todo = set(), [root]
    while todo:
        n = todo.pop()
        if n in seen or n not in edges:
            continue
        seen.add(n); todo.extend(edges[n])
    return seen

vectors = []
raw = subprocess.run([str(TOOLS / 'arm-none-eabi-objcopy'), '-O', 'binary', '--only-section=.isr_vector', str(elf), '/dev/stdout'],
                     capture_output=True, check=True).stdout
for slot in range(1, len(raw) // 4):
    v = int.from_bytes(raw[4 * slot:4 * slot + 4], 'little')
    if v:
        vectors.append(addr_to_sym.get(v & ~1, f'0x{v:08x}'))
isr_roots = sorted(set(vectors))

def summarise(root):
    c = closure(root)
    sites = [f'{fn}: {s}' for fn in sorted(c) for s in indirect.get(fn, [])]
    return {'functions': len(c), 'code_bytes': sum(sizes.get(fn, 0) for fn in c), 'indirect_call_sites': sites}

sections = []
for line in arm('readelf', '-S', '-W', elf).splitlines():
    m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)', line)
    if m and int(m[2], 16) and int(m[3], 16):
        sections.append({'section': m[1], 'address': f'0x{m[2]}', 'bytes': int(m[3], 16)})

priv_start = sym_addr.get('__privileged_functions_start__') or None
kernel_priv = []
syms = {s: a for s, a in [(l.split()[2], int(l.split()[0], 16)) for l in arm('nm', elf).splitlines() if len(l.split()) == 3]}
lo, hi = syms.get('__privileged_functions_start__'), syms.get('__privileged_functions_end__')
if lo is not None and hi is not None:
    kernel_priv = sorted(((fn, sizes[fn]) for fn, ad in sym_addr.items() if lo <= ad < hi), key=lambda x: -x[1])

all_priv = set()
report = {'elf': str(elf), 'sections': sections,
          'privileged_tasks': {}, 'isr_roots': {}, 'unprivileged_tasks': UNPRIVILEGED,
          'kernel_privileged_functions': {'bytes': (hi - lo) if lo is not None else None,
                                           'functions': [{'name': n, 'bytes': b} for n, b in kernel_priv]}}
for entry, (site, note) in TASKS.items():
    if entry not in edges:
        continue  # variant-only tasks are absent from other images
    report['privileged_tasks'][entry] = {'source': site, 'note': note, **summarise(entry)}
    all_priv |= closure(entry)
for isr in isr_roots:
    if isr in edges:
        report['isr_roots'][isr] = summarise(isr)
        all_priv |= closure(isr)
report['privileged_union'] = {'functions': len(all_priv), 'code_bytes': sum(sizes.get(f, 0) for f in all_priv),
                              'indirect_call_sites': sum(len(indirect.get(f, [])) for f in all_priv)}
report['limits'] = ('Direct-branch closures only; register-indirect targets (callbacks, function pointers, '
                    'lwIP/HAL hooks) are listed, not resolved; closures of tasks that drop privilege include '
                    'their unprivileged phase.')
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(report, indent=2) + '\n')
u = report['privileged_union']
print(f"privileged roots: {len(report['privileged_tasks'])} tasks, {len(report['isr_roots'])} ISRs; union {u['functions']} functions, "
      f"{u['code_bytes']} B, {u['indirect_call_sites']} indirect sites; kernel privileged section {report['kernel_privileged_functions']['bytes']} B")
