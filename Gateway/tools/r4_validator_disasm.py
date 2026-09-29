#!/usr/bin/env python3
"""Static ARM instruction attribution for the pinned EverParse validator.

Carry-chain and double-register instructions are a proxy for 64-bit
position/result work, not a dynamic-cycle or WCET attribution.
"""
from pathlib import Path
import argparse
import json
import re
import subprocess

p = argparse.ArgumentParser()
p.add_argument('elf', type=Path)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
compiler = Path('/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin')
data = subprocess.check_output([str(compiler / 'arm-none-eabi-objdump'), '-d',
                                '--no-show-raw-insn', str(a.elf)], text=True)
match = re.search(r'^\S+ <RbacPolicyValidateAccessRequest>:\n(.*?)(?=^\S+ <|\Z)',
                  data, re.M | re.S)
assert match, 'validator symbol missing'
rows = []
for line in match[1].splitlines():
    ins = re.match(r'\s*([0-9a-f]+):\s+(\S+)\s*(.*)', line)
    if ins:
        rows.append((int(ins[1], 16), ins[2].split('.')[0], ins[3]))
ops = [row[1] for row in rows]
counts = {
    'all_static_instructions': len(rows),
    'doubleword_load_store': sum(op in ('ldrd', 'strd') for op in ops),
    'carry_chain_arithmetic': sum(op in ('adc', 'adcs', 'sbc', 'sbcs', 'umull', 'umlal', 'smull', 'smlal') for op in ops),
    'calls': sum(op in ('bl', 'blx') for op in ops),
    'conditional_branches': sum(re.fullmatch(r'b(?:eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)',op) is not None or op in ('cbz','cbnz') for op in ops),
}
backward=[]
for address,op,operands in rows:
    target=re.match(r'\s*([0-9a-f]+)\s+<RbacPolicyValidateAccessRequest(?:\+[^>]*)?>',operands)
    if (op=='b' or re.fullmatch(r'b(?:eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)',op)) and target and int(target[1],16)<address:
        backward.append({'address':hex(address),'target':hex(int(target[1],16))})
counts['backward_intra_function_branches']=backward
address_set={row[0] for row in rows}
edges={address:[] for address,_,_ in rows}
unknown_control=[]
for index,(address,op,operands) in enumerate(rows):
    following=rows[index+1][0] if index+1<len(rows) else None
    target=re.match(r'\s*([0-9a-f]+)\s+<RbacPolicyValidateAccessRequest(?:\+[^>]*)?>',operands)
    branch=op=='b' or re.fullmatch(r'b(?:eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)',op) is not None or op in ('cbz','cbnz')
    terminal=(op=='bx' and operands.strip()=='lr') or (op in ('pop','ldmia','ldm') and 'pc' in operands)
    if branch:
        if target and int(target[1],16) in address_set:
            edges[address].append(int(target[1],16))
        else:
            unknown_control.append({'address':hex(address),'op':op,'operands':operands})
        if op!='b' and following is not None: edges[address].append(following)
    elif not terminal and following is not None:
        edges[address].append(following)
    if op in ('tbb','tbh') or (op=='bx' and operands.strip()!='lr'):
        unknown_control.append({'address':hex(address),'op':op,'operands':operands})
seen=set();active=set();cycles=set();order=[]
def visit(address):
    if address in active:
        cycles.add(address);return
    if address in seen:return
    active.add(address)
    for target in edges[address]:visit(target)
    active.remove(address);seen.add(address);order.append(address)
visit(rows[0][0])
counts['reachable_cfg_cycle_entries']=[hex(x) for x in sorted(cycles)]
counts['unknown_control_transfers']=unknown_control
if not cycles and not unknown_control:
    longest={}
    for address in order:
        longest[address]=1+max((longest[target] for target in edges[address]),default=0)
    counts['static_max_function_instructions_excluding_callees']=longest[rows[0][0]]
counts['64_bit_signature_instructions'] = counts['doubleword_load_store'] + counts['carry_chain_arithmetic']
counts['64_bit_signature_fraction_of_static_instructions'] = counts['64_bit_signature_instructions']/len(rows)
source = Path(__file__).resolve().parents[1] / 'Generated/Policy/RbacPolicy.c'
counts['uint64_t_source_uses'] = source.read_text().count('uint64_t')
counts['note'] = 'Static function footprint; includes alternate branches and excludes inlined 64-bit operations without these signatures. It is not executed-cycle share.'
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(counts, indent=2) + '\n')
print(json.dumps(counts, indent=2))
