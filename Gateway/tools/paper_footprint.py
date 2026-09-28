#!/usr/bin/env python3
"""Attribute allocated linker-map input sections to gateway components.

Object attribution excludes linker padding and cannot split inlined code.
Dashboard constants are identified by linked symbol size and moved from the
network object's flash total into their own category.
"""
from collections import defaultdict
from pathlib import Path
import argparse
import json
import re
import subprocess

COMPILER = Path('/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin')


def category(obj):
    if '/Gateway/Generated/Extractor/' in obj:
        return 'F* extractor and IPC'
    if '/Gateway/Generated/Policy/' in obj:
        return 'EverParse validators'
    if '/Gateway/Generated/Mediation/' in obj:
        return 'Low* serializer and wrapper'
    if '/Gateway/Generated/Auth/' in obj or '/Gateway/Auth/' in obj:
        return 'HACL* and login'
    if '/Gateway/Network/lwip/' in obj or '/Gateway/Network/lwip/system/' in obj:
        return 'lwIP'
    if '/Middlewares/Third_Party/FreeRTOS/' in obj:
        return 'FreeRTOS'
    if '/Drivers/' in obj or '/Gateway/Network/ethernetif.o' in obj or '/Gateway/Network/lan8742/' in obj:
        return 'HAL, Ethernet and PHY drivers'
    if '/Gateway/Core/gateway_mediation.o' in obj or '/Gateway/Core/gateway_mediation_validator.o' in obj:
        return 'trusted mediation adapter and validator bridge'
    if '/Gateway/Core/gateway_core.o' in obj:
        return 'application handlers and core'
    if '/Gateway/SelfTest/' in obj:
        return 'firmware self-tests'
    if '/Gateway/' in obj:
        return 'other gateway integration'
    if '/Core/' in obj:
        return 'startup and board integration'
    return 'C runtime and other'


def get_symbols(elf):
    raw = subprocess.check_output([str(COMPILER / 'arm-none-eabi-nm'), '-S', elf], text=True)
    result = {}
    for line in raw.splitlines():
        match = re.fullmatch(r'[0-9a-f]+\s+([0-9a-f]+)\s+[A-Za-z]\s+(\S+)', line)
        if match:
            result[match[2]] = int(match[1], 16)
    return result


p = argparse.ArgumentParser()
p.add_argument('link_map', type=Path)
p.add_argument('elf', type=Path, nargs='?')
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
map_text = a.link_map.read_text()
assert 'Linker script and memory map' in map_text
allocated = map_text.split('Linker script and memory map', 1)[1]
sections = defaultdict(lambda: {'flash_bytes': 0, 'ram_bytes': 0})
objects = defaultdict(lambda: {'flash_bytes': 0, 'ram_bytes': 0})
dashboard = 0
pending_section = None
for line in allocated.splitlines():
    first = re.fullmatch(r'\s+([.*A-Za-z0-9_]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+\.o(?:\([^)]*\))?)\s*', line)
    wrapped = re.fullmatch(r'\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+\.o(?:\([^)]*\))?)\s*', line)
    if first:
        sec, address, size, obj = first.groups()
    elif wrapped and pending_section:
        address, size, obj = wrapped.groups()
        sec = pending_section
    else:
        name = re.fullmatch(r'\s+([.][A-Za-z0-9_.]+)\s*', line)
        pending_section = name[1] if name else None
        continue
    pending_section = None
    address, size = int(address, 16), int(size, 16)
    if not size:
        continue
    if 0x08000000 <= address < 0x08200000:
        key = 'flash_bytes'
    elif 0x20000000 <= address < 0x20080000:
        key = 'ram_bytes'
    else:
        continue
    group = category(obj)
    sections[group][key] += size
    objects[obj][key] += size
    if sec in ('.rodata.gateway_dashboard', '.rodata.gateway_dashboard_js'):
        dashboard += size
    # .data occupies SRAM and has a load image in flash.
    if sec.startswith('.data'):
        sections[group]['flash_bytes'] += size
        objects[obj]['flash_bytes'] += size

assert dashboard > 0, 'dashboard sections missing from allocated map'
if a.elf:
    symbols = get_symbols(a.elf)
    assert dashboard == symbols['gateway_dashboard'] + symbols['gateway_dashboard_js']
network_obj = next(obj for obj in objects if obj.endswith('/Gateway/Network/gateway_network.o'))
assert objects[network_obj]['flash_bytes'] >= dashboard
sections[category(network_obj)]['flash_bytes'] -= dashboard
sections['dashboard assets']['flash_bytes'] += dashboard

report = {
    'map': str(a.link_map.resolve()),
    'elf': str(a.elf.resolve()) if a.elf else None,
    'components': dict(sorted(sections.items())),
    'dashboard_symbol_bytes': dashboard,
    'attributed_flash_bytes': sum(v['flash_bytes'] for v in sections.values()),
    'attributed_ram_bytes': sum(v['ram_bytes'] for v in sections.values()),
    'limits': 'Allocated input sections by object; linker padding, output-section boundaries, .isr_vector, heap/stack reservations and inlining are not attributable here. Compare totals with arm-none-eabi-size and the full map.',
}
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(report, indent=2) + '\n')
print('Attributed flash', report['attributed_flash_bytes'], 'RAM', report['attributed_ram_bytes'])
