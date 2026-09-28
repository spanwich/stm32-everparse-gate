#!/usr/bin/env python3
"""Read-only source/build consistency check; safe before and after CubeMX."""
from pathlib import Path
import hashlib, json, re, xml.etree.ElementTree as ET
root = Path(__file__).resolve().parents[2]
manifest = json.loads((root / 'Gateway/Provenance/manifest.json').read_text())
for item in manifest['files']:
    digest = hashlib.sha256((root / item['destination']).read_bytes()).hexdigest()
    if item['kind'] == 'generated' or (item['kind'] in ('runtime', 'interface', 'specification', 'reference') and 'patch' not in item):
        assert digest == item['source_sha256'], 'Imported core/reference changed: ' + item['destination']
    elif item['kind'] == 'runtime':
        assert digest == item['local_sha256'], 'Runtime adaptation changed: update and review provenance: ' + item['destination']
project = ET.parse(root / '.cproject')
for cfg in project.findall('.//configuration'):
    if cfg.find('sourceEntries') is None: continue
    assert any(e.get('name') == 'Gateway' for e in cfg.find('sourceEntries')), 'Run Gateway/tools/configure_project.py'
    generated = cfg.find("folderInfo[@resourcePath='Gateway/Generated']")
    assert generated is not None, 'Generated-code folder configuration missing'
    opts = [o for o in generated.findall('.//option') if o.get('superClass', '').endswith('.tool.c.compiler.option.optimization.level')]
    assert len(opts) == 1 and opts[0].get('value', '').endswith('.value.os'), 'Generated C must use -Os'
    assert 'check_firmware.py' in cfg.get('postbuildStep', ''), 'Post-link admission check missing'
ioc = dict(line.split('=', 1) for line in (root / 'policy_gate.ioc').read_text().splitlines() if '=' in line)
assert ioc['ProjectManager.ProjectName'] == 'policy_gate'
assert ioc['ProjectManager.StackSize'] == '0x1000'
assert not any(k.startswith('FREERTOS.Tasks') and v for k, v in ioc.items()), 'Remove generated demo tasks; gateway tasks are application-owned'
assert ioc['FREERTOS.configCHECK_FOR_STACK_OVERFLOW'] == '2'
assert ioc['FREERTOS.configUSE_MALLOC_FAILED_HOOK'] == '1'
for name in ['STM32F767ZITX_FLASH.ld', 'STM32F767ZITX_RAM.ld']:
    assert re.search(r'_Min_Stack_Size\s*=\s*0x1000\s*;', (root / name).read_text())
config = (root / 'Core/Inc/FreeRTOSConfig.h').read_text()
assert re.search(r'#define\s+configCHECK_FOR_STACK_OVERFLOW\s+2\b', config)
assert re.search(r'#define\s+configUSE_MALLOC_FAILED_HOOK\s+1\b', config)
assert 'gateway_assert_failed(__FILE__, __LINE__)' in config
main = (root / 'Core/Src/main.c').read_text()
assert 'gateway_platform_start();' in main and 'gateway_boot_report();' in main
assert 'StartDefaultTask' not in main and 'busy_wait_ms' not in main and 'xTaskCreate(' not in main
print('Project configuration and unchanged generated algorithms PASS')

assert ioc['FREERTOS.configTOTAL_HEAP_SIZE'] == '65536'
assert '((size_t)65536)' in config
for name in ['STM32F767ZITX_FLASH.ld', 'STM32F767ZITX_RAM.ld']:
    script = (root / name).read_text()
    assert 'LENGTH = 448K' in script and '0x20070000' in script and '0x20070400' in script
network = json.loads((root / 'Gateway/Provenance/network.json').read_text())
for item in network['files']:
    assert hashlib.sha256((root / item['destination']).read_bytes()).hexdigest() == item['sha256'], 'Vendored network source changed: ' + item['destination']
print('Pinned lwIP/PHY sources and network memory configuration PASS')

# HACL algorithms are immutable; adapted handwritten helpers carry reviewed hashes.
auth = json.loads((root / 'Gateway/Provenance/auth.json').read_text())
for item in auth['files']:
    expected = item['sha256'] if item['kind'] == 'unchanged' else item['local_sha256']
    assert hashlib.sha256((root / item['destination']).read_bytes()).hexdigest() == expected, 'Auth provenance mismatch: ' + item['destination']
import subprocess
subprocess.run(['python3', str(root / 'Gateway/tools/embed_dashboard.py'), '--check'], check=True)
print('Authentication provenance and dashboard embedding PASS')

# Research wrapper has its own proof/extraction manifest; imported cores above
# retain their original provenance unchanged.
subprocess.run(["python3", str(root / "Verification/tools/check_generated.py")], check=True)
