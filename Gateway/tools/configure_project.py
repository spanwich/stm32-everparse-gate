#!/usr/bin/env python3
"""Idempotently register Gateway sources/flags in maintained CubeIDE metadata.
Run after CubeMX regeneration. Does not edit any generated Debug/Release makefile.
"""
from pathlib import Path
import copy
import re
import xml.etree.ElementTree as ET
root = Path(__file__).resolve().parents[2]
paper_flags = (root / 'Gateway/Inc/paper_experiment.h').read_text()
paper_alloc = bool(re.search(r'^#define\s+GATEWAY_PAPER_ALLOC\s+1\b', paper_flags, re.M))
path = root / '.cproject'
tree = ET.parse(path)
for cfg in tree.findall('.//configuration'):
    entries = cfg.find('sourceEntries')
    if entries is None:
        continue
    if not any(e.get('name') == 'Gateway' for e in entries):
        ET.SubElement(entries, 'entry', {'excluding': 'tools|Provenance|Validation', 'flags': 'VALUE_WORKSPACE_PATH|RESOLVED', 'kind': 'sourcePath', 'name': 'Gateway'})
    gateway_entry = next(e for e in entries if e.get('name') == 'Gateway')
    gateway_entry.set('excluding', 'tools|Provenance|Network|Validation')
    network_entries = {
        'Gateway/Network': 'lwip|lan8742',
        'Gateway/Network/lan8742': '',
        'Gateway/Network/lwip/src/core': 'ipv6',
        'Gateway/Network/lwip/src/api': '',
        'Gateway/Network/lwip/src/netif': '|'.join(p.name for p in (root / 'Gateway/Network/lwip/src/netif').iterdir() if p.name != 'ethernet.c'),
    }
    for name, excludes in network_entries.items():
        entry = next((e for e in entries if e.get('name') == name), None)
        if entry is None:
            entry = ET.SubElement(entries, 'entry', {'flags': 'VALUE_WORKSPACE_PATH|RESOLVED', 'kind': 'sourcePath', 'name': name})
        entry.set('excluding', excludes)
    base = next(f for f in cfg.findall('folderInfo') if f.get('resourcePath') == '')
    for tool in base.findall('.//tool'):
        if tool.get('superClass') != 'com.st.stm32cube.ide.mcu.gnu.managedbuild.tool.c.linker':
            continue
        option = next((o for o in tool.findall('option') if o.get('superClass', '').endswith('.tool.c.linker.option.otherflags')), None)
        if paper_alloc:
            flags = ' '.join('-Wl,--wrap=' + name for name in
                             ('pvPortMalloc', 'malloc', '_malloc_r', 'mem_malloc', 'memp_malloc'))
            if option is None:
                option = ET.SubElement(tool, 'option', {'id': 'policy_gate.paper.alloc.wrap',
                    'name': 'Other flags',
                    'superClass': 'com.st.stm32cube.ide.mcu.gnu.managedbuild.tool.c.linker.option.otherflags',
                    'valueType': 'string'})
            option.set('value', flags)
        elif option is not None and option.get('id') == 'policy_gate.paper.alloc.wrap':
            tool.remove(option)
    for tool in base.findall('.//tool'):
        if tool.get('superClass') != 'com.st.stm32cube.ide.mcu.gnu.managedbuild.tool.c.compiler':
            continue
        inc = next(o for o in tool.findall('option') if o.get('superClass', '').endswith('.includepaths'))
        for name in ['Inc', 'Shared', 'Core', 'Auth', 'Generated/Auth', 'Generated/Extractor', 'Generated/Extractor/krml_include', 'Network', 'Network/lan8742', 'Network/lwip/src/include', 'Network/lwip/system']:
            value = '../Gateway/' + name
            if not any(v.get('value') == value for v in inc):
                ET.SubElement(inc, 'listOptionValue', {'builtIn': 'false', 'value': value})
    # A folder-specific managed configuration keeps generated recursion optimized,
    # while all handwritten Debug code remains at the project's original -O0.
    for folder in list(cfg.findall('folderInfo')):
        if folder.get('resourcePath') == 'Gateway/Generated':
            cfg.remove(folder)
    generated = copy.deepcopy(base)
    generated.set('resourcePath', 'Gateway/Generated')
    generated.set('name', 'Generated')
    for element in generated.iter():
        if 'id' in element.attrib:
            element.set('id', element.get('id') + '.gateway.generated')
        if element.get('superClass', '').endswith('.compiler.option.optimization.level'):
            element.set('value', element.get('superClass') + '.value.os')
            element.set('valueType', 'enumerated')
    cfg.insert(list(cfg).index(entries), generated)
    cfg.set('postbuildStep', 'python3 ../Gateway/tools/check_firmware.py policy_gate.elf')
ET.indent(tree, space='\t')
text = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n<?fileVersion 4.0.0?>' + ET.tostring(tree.getroot(), encoding='unicode') + '\n'
if path.read_text() != text:
    path.write_text(text)
print('CubeIDE Gateway sources and generated-code -Os configuration ready')
