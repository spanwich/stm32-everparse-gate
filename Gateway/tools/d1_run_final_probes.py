#!/usr/bin/env python3
"""D1.8 injection and fault-reset probes on the final (verified-gate) image.

Each probe is a separate image differing from the final image only by
GATEWAY_D1_PROBE. Per probe: build, stage (ELF, build log, manifest), flash,
trigger one HTTP request, capture UART across the fault and the watchdog reset,
then check that the rebooted gate grants operator no access (restrictive
default, E-fault). Probe 10 additionally records that the wrapper-interior
target is an SVC instruction in the staged ELF.
  1-15 NET: policy write, validator-input write, AUTH key write, AUTH key read,
  APP input write, GATE function call, AUTH function call, leaked GATE->APP
  queue handle, SVC raise, wrapper-interior jump, CONTROL write, ETH MAC
  register, DMA buffer, forged RX slot index, overlong TX request.
  20 GATE writes AUTH key; 21 APP writes GATE policy; 22 AUTH writes GATE policy.
"""
from pathlib import Path
import argparse, hashlib, json, re, shutil, subprocess, tempfile, time, urllib.request, urllib.error

root = Path(__file__).resolve().parents[2]
header = root / 'Gateway/Inc/paper_experiment.h'
evidence = root / 'Gateway/Validation/paper-evidence-d1-2026-09-30'
tools = ('/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.'
         'gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin/')
ALL = list(range(1, 16)) + [20, 21, 22]
p = argparse.ArgumentParser()
p.add_argument('probes', nargs='*', type=int, default=ALL)
a = p.parse_args()
assert set(a.probes) <= set(ALL)


def http_status(token):
    req = urllib.request.Request('http://192.168.40.128/api/status', headers={'Authorization': 'Bearer ' + token})
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:  # transport failure: the gate is down
        return type(e).__name__


def build(probe, out):
    original = header.read_text()
    try:
        changed, count = re.subn(r'(#define GATEWAY_D1_PROBE )\d+\b', lambda m: m[1] + str(probe), original)
        assert count == 1
        header.write_text(changed)
        with tempfile.TemporaryDirectory(prefix='policy-d1-probe-') as tmp:
            with (out / 'build-command.log').open('wb') as log:
                subprocess.run(['python3', 'Gateway/tools/build_firmware.py', '--output', tmp],
                               cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
            shutil.copy2(Path(tmp) / 'build.log', out / 'build.log')
    finally:
        header.write_text(original)
    elf = out / 'policy_gate.elf'
    shutil.copy2(root / 'Debug/policy_gate.elf', elf)
    manifest = {'probe': probe,
                'git_base': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
                'elf_sha256': hashlib.sha256(elf.read_bytes()).hexdigest(),
                'source_sha256': {str(x.relative_to(root)): hashlib.sha256(x.read_bytes()).hexdigest() for x in (
                    root / 'Gateway/Network/gateway_r4_boundary.c', root / 'Gateway/Network/ethernetif.c',
                    root / 'Gateway/Auth/d1_auth_oracle.c', root / 'Gateway/MPUPort/port.c')}}
    if probe == 10:
        dis = subprocess.check_output([tools + 'arm-none-eabi-objdump', '-d', str(elf)], text=True)
        sym = subprocess.check_output([tools + 'arm-none-eabi-nm', str(elf)], text=True)
        base = int(re.search(r'^([0-9a-f]+) T MPU_xTaskGetTickCount$', sym, re.M)[1], 16)
        target = f'{base + 0x12:x}'
        line = next((l for l in dis.splitlines() if l.strip().startswith(target + ':')), '')
        manifest['wrapper_target'] = {'address': '0x' + target, 'instruction': line.strip()}
        assert 'svc' in line, line
    (out / 'source-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


results = []
for probe in a.probes:
    out = evidence / f'v11-final-probe-{probe}'
    out.mkdir(parents=True, exist_ok=True)
    manifest = build(probe, out)
    board = subprocess.run(['python3', 'Gateway/tools/board_test.py', '--flash', '--elf', str(out / 'policy_gate.elf'),
                            '--output', str(out / 'board'), '--seconds', '20', '--expected-selftests', '301'],
                           cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out / 'board-command.log').write_bytes(board.stdout)
    # Trigger and observe across the watchdog reset (~8 s after a panic).
    script = ("import time,subprocess;"
              "subprocess.run(['curl','--interface','enp44s0','--max-time','5','-s','-o','/dev/null','-w','trigger=%{http_code}\\\\n',"
              "'-H','Authorization: Bearer pg-lab-operator','http://192.168.40.128/api/status']);"
              "time.sleep(30)")
    cap = subprocess.run(['python3', 'Gateway/tools/paper_capture_command.py', '--output', str(out / 'uart'),
                          '--', 'python3', '-c', script], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (out / 'capture-command.log').write_bytes(cap.stdout)
    after = http_status('pg-lab-operator')
    uart = (out / 'uart/uart.log').read_text(errors='replace')
    record = {
        'probe': probe, 'elf_sha256': manifest['elf_sha256'], 'board_exit_code': board.returncode,
        'probe_lines': [l for l in uart.splitlines() if '[PROBE]' in l],
        'reset_lines': [l for l in uart.splitlines() if l.startswith('[RESET]')],
        'escaped': 'ESCAPED' in uart,
        'rebooted_selftests': '[CORE SELFTEST] PASS 301/301' in uart.split('[RESET]', 1)[-1] if '[RESET]' in uart else False,
        'operator_status_after_reset': after,
    }
    if 'wrapper_target' in manifest:
        record['wrapper_target'] = manifest['wrapper_target']
    (out / 'probe.json').write_text(json.dumps(record, indent=2) + '\n')
    results.append(record)
    print(json.dumps(record), flush=True)
summary = evidence / 'final-probes-summary.json'
merged = {r['probe']: r for r in (json.loads(summary.read_text()) if summary.exists() else [])}
merged.update({r['probe']: r for r in results})
summary.write_text(json.dumps([merged[k] for k in sorted(merged)], indent=2) + '\n')
