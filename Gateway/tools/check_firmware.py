#!/usr/bin/env python3
"""Post-link admission check. A stack report is NOT a complete stack proof."""
from pathlib import Path
import json, re, subprocess, sys
COMPILER = Path('/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin')
elf = Path(sys.argv[1]).resolve()
build = elf.parent
experiment = (Path(__file__).resolve().parents[1] / 'Inc/paper_experiment.h').read_text()
opt_o2 = re.search(r'^#define\s+GATEWAY_R4_OPT_O2\s+1\b', experiment, re.M) is not None
generated_opt = '-O2' if opt_o2 else '-Os'

def run(tool, *args):
    return subprocess.check_output([str(COMPILER / ('arm-none-eabi-' + tool)), *map(str, args)], text=True)

def require(condition, message):
    if not condition:
        raise SystemExit('GATEWAY CHECK FAILED: ' + message)

symbols = run('nm', '--defined-only', elf)
required = ['extract_security_params', 'populate_auth_fields', 'populate_rate_field',
            'RbacPolicyValidateAccessRequest', 'RbacPolicyValidatePolicyBlob',
            'RbacPolicyValidateLoginRequest', 'Mediation_Wrapper_run', 'Mediation_Extern_invoke', 'gateway_mediate',
            'gateway_platform_start', 'run_core', 'run_diagnostics',
            'vApplicationMallocFailedHook', 'gateway_assert_failed']
# V11 MPU ports keep task context in the TCB and rely on MPU faults for
# unprivileged stack overruns; stack_macros.h does not call this hook.
if 'configUSE_MPU_WRAPPERS_V1                 0' not in (
        Path(__file__).resolve().parents[2] / 'Core/Inc/FreeRTOSConfig.h').read_text():
    required.append('vApplicationStackOverflowHook')
for symbol in required:
    require(re.search(r'\b[Tt] ' + re.escape(symbol) + r'$', symbols, re.M), 'missing strong function ' + symbol)
# Enforce the reserved F767 Ethernet banks in the linked image.
sections = run('objdump', '-h', elf)
for name, origin, limit in [('.eth_desc', 0x20070000, 0x20070400), ('.eth_data', 0x20070400, 0x20080000)]:
    match = re.search(r'^\s*\d+\s+' + re.escape(name) + r'\s+([0-9a-f]+)\s+([0-9a-f]+)', sections, re.M)
    require(match is not None, 'missing DMA section ' + name)
    size, address = (int(v, 16) for v in match.groups())
    require(address == origin and address + size <= limit and address % 32 == 0, 'DMA section bounds/alignment ' + name)
for name, origin, limit in [('.privileged_data', 0x20000000, 0x20020000),
                            ('.gateway_app', 0x20020000, 0x20024000),
                            ('.gateway_gate', 0x20050000, 0x20060000),
                            ('.gateway_gate_init', 0x20050000, 0x20060000),
                            ('.gateway_auth', 0x20060000, 0x20064000)]:
    match = re.search(r'^\s*\d+\s+' + re.escape(name) + r'\s+([0-9a-f]+)\s+([0-9a-f]+)', sections, re.M)
    require(match is not None, 'missing MPU isolation section ' + name)
    size, address = (int(v, 16) for v in match.groups())
    require((address == origin or name == '.gateway_gate_init' and address >= origin)
            and address + size <= limit, 'MPU isolation section bounds ' + name)
for name in ['DMARxDscrTab', 'DMATxDscrTab']:
    match = re.search(r'^([0-9a-f]+) [A-Za-z] ' + name + r'$', symbols, re.M)
    require(match is not None and 0x20070000 <= int(match[1], 16) < 0x20070400 and int(match[1], 16) % 32 == 0, 'DMA descriptor placement ' + name)
require(re.search(r'^20070000 [A-Za-z] _estack$', symbols, re.M), 'MSP must end below reserved DMA bank')
for name in ['gateway_http_feed', 'gateway_http_process', 'gateway_bearer_check',
             'gateway_login', 'gateway_d1_auth_identify',
             'gateway_d1_auth_login', 'gateway_clear', 'gateway_network_run',
             'ETH_IRQHandler']:
    require(re.search(r'\b[Tt] ' + name + r'$', symbols, re.M), 'missing network function ' + name)

objects = sorted((build / 'Gateway/Generated/Extractor').glob('*.o'))
require(len(objects) == 8, 'expected all eight generated extractor/IPC objects')
mediation_objects = sorted((build / 'Gateway/Generated/Mediation').glob('*.o'))
require(len(mediation_objects) == 3, 'expected all three verified mediation objects')
objects += mediation_objects
makefile = build / 'Gateway/Generated/subdir.mk'
# CubeIDE generates leaf makefiles; never modify them here.
makefiles = list((build / 'Gateway/Generated').rglob('subdir.mk'))
require(makefiles, 'missing generated-core compilation recipes')
for recipe in makefiles:
    commands = [line for line in recipe.read_text().splitlines() if '-mcpu=cortex-m7' in line and ' -c ' in line]
    require(commands, 'missing compiler command in ' + str(recipe))
    for line in commands:
        opts = re.findall(r'(?:^|\s)(-O(?:[0-3sgz]|fast))(?=\s|$)', line)
        require(opts and opts[-1] == generated_opt, 'generated optimization mismatch: ' + str(recipe))
extractor_names = set()
for obj in objects:
    for line in run('nm', '--defined-only', obj).splitlines():
        match = re.match(r'\S+ [Tt] (\S+)', line)
        if match and not match[1].startswith('$'): extractor_names.add(match[1])
disassembly = run('objdump', '-d', '--no-show-raw-insn', elf)
(build / 'gateway.disassembly.txt').write_text(disassembly)
edges = {}; fn = None; indirect = set(); linked = set()
for line in disassembly.splitlines():
    match = re.match(r'^[0-9a-f]+ <([^>]+)>:', line)
    if match:
        fn = match[1]; edges.setdefault(fn, set()); linked.add(fn); continue
    if fn is None: continue
    ins = re.match(r'\s*[0-9a-f]+:\s+(\S+)\s+(.*)', line)
    if not ins: continue
    op, operands = ins.groups()
    target = re.search(r'<([^>]+)>', operands)
    # Include inter-function tail branches; intra-function branches are loops.
    if (op in ('bl', 'blx', 'bl.w', 'blx.w', 'b', 'b.w', 'b.n') or
            re.fullmatch(r'b(?:eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)(?:\.[nw])?', op)) and target:
        name = target[1].split('+')[0]
        if name != fn or op in ('bl', 'blx', 'bl.w', 'blx.w'):
            edges[fn].add(name)
    elif op in ('bl', 'blx', 'bl.w', 'blx.w') or (op in ('bx', 'bx.w') and operands.strip() != 'lr'):
        indirect.add(fn)
# Call-graph admission evidence, conditional on no hidden indirect handler
# references. This is not a machine-code control-flow or memory-isolation proof.
def reachable_without(start, barrier):
    reached=set(); pending=[start]
    while pending:
        name=pending.pop()
        if name in reached or name==barrier: continue
        reached.add(name); pending.extend(edges.get(name,()))
    return reached
protected_effects={'Mediation_Extern_invoke','gateway_dispatch','gateway_login','gateway_evaluate','pipeline_process'}
require(not (reachable_without('gateway_http_process','Mediation_Wrapper_run') & protected_effects),
        'HTTP handler call path bypasses verified wrapper')
require(not (reachable_without('Mediation_Extern_check','') & protected_effects),
        'validator bridge reaches a handler')
seen = set(); active = set()
def visit(fn):
    require(fn not in active, 'recursive extractor call cycle at ' + fn)
    if fn in seen: return
    active.add(fn)
    require(fn not in indirect, 'unresolved indirect call in extractor ' + fn)
    for target in edges.get(fn, ()):
        if target in extractor_names: visit(target)
    active.remove(fn); seen.add(fn)
for fn in extractor_names & linked: visit(fn)
frames = {}
for path in build.rglob('*.su'):
    for line in path.read_text().splitlines():
        fields = line.split('\t')
        if len(fields) >= 3:
            name = fields[0].rsplit(':', 1)[-1]
            frames[name] = {'bytes': int(fields[1]), 'kind': fields[2], 'report': str(path.relative_to(build))}
for fn in extractor_names & linked:
    require(fn in frames, 'missing stack usage for extractor ' + fn)
    require(frames[fn]['kind'] == 'static', 'unbounded extractor frame ' + fn)
# For generated helpers the direct-call chain is acyclic. Unknown library frame
# costs are listed explicitly rather than misrepresented as zero-cost proofs.
def chain(fn, path=()):
    if fn in path: return 0
    return frames.get(fn, {}).get('bytes', 0) + max([chain(t, path + (fn,)) for t in edges.get(fn, ()) if t in frames] or [0])
report = {
    'elf': str(elf), 'compiler': run('gcc', '--version').splitlines()[0],
    'generated_optimization': generated_opt, 'extractor_recursive_calls': False,
    'mediation_recursive_calls': False, 'http_direct_call_graph_mediation': True,
    'extractor_linked_functions': sorted(extractor_names & linked),
    'known_frame_chain_bytes': {n: chain(n) for n in ['run_core', 'run_diagnostics', 'extract_security_params', 'gateway_evaluate', 'gateway_dispatch', 'gateway_login', 'gateway_login_validate', 'gateway_mediate', 'Mediation_Wrapper_run', 'Mediation_Format_build', 'gateway_http_process']},
    'largest_frames': sorted(({'function': n, **v} for n, v in frames.items()), key=lambda x: x['bytes'], reverse=True)[:20],
    'unmeasured_callees_from_measured_code': sorted({t for f, ts in edges.items() if f in frames for t in ts if t not in frames}),
    'indirect_calls_in_measured_code': sorted(indirect & frames.keys()),
    'limits': 'Known-frame sums exclude library/assembly/indirect-call costs, exception frames and interrupt nesting. Validate task and MSP margins on hardware; this is not a worst-case stack proof.'
}
(build / 'gateway.stack.json').write_text(json.dumps(report, indent=2) + '\n')
print('Gateway post-link checks PASS: generated '+generated_opt+', strong hooks, no recursive extractor calls')
print('Stack evidence:', build / 'gateway.stack.json')
