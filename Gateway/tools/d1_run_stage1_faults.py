#!/usr/bin/env python3
"""Run the six inherited R4 MPU probes on the V11 stage-1 board image.

Each build is complete before its ELF is flashed. Every run retains its UART,
programmer, and SWD logs; a fault is expected, so boot-test nonzero is recorded.
"""
from pathlib import Path
import argparse
import json
import re
import subprocess

root = Path(__file__).resolve().parents[2]
out = root / 'Gateway/Validation/paper-evidence-d1-2026-09-30'
cli = ('/opt/st/stm32cubeide_2.0.0/plugins/'
       'com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.linux64_2.2.300.'
       '202508131133/tools/bin/STM32_Programmer_CLI')
nm = ('/opt/st/stm32cubeide_2.0.0/plugins/'
      'com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.'
      'linux64_1.0.100.202509120712/tools/bin/arm-none-eabi-nm')
p = argparse.ArgumentParser()
p.add_argument('probes', nargs='*', type=int, default=list(range(1, 7)))
args = p.parse_args()
assert set(args.probes) <= set(range(1, 7))

for probe in args.probes:
    directory = out / f'v11-fault-{probe}'
    directory.mkdir(parents=True, exist_ok=True)
    build = subprocess.run(['python3', 'Gateway/tools/d1_build_escalation.py',
                            str(probe), '--output', str(directory)],
                           cwd=root, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
    (directory / 'build-command.log').write_bytes(build.stdout)
    if build.returncode:
        raise SystemExit(f'probe {probe} build failed: {build.stdout.decode()}')
    board = subprocess.run(['python3', 'Gateway/tools/board_test.py',
                            '--elf', str(directory / 'policy_gate.elf'), '--flash',
                            '--output', str(directory / 'board'), '--seconds', '5',
                            '--expected-selftests', '354'], cwd=root,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (directory / 'board-command.log').write_bytes(board.stdout)
    if probe == 2:
        trigger = subprocess.run([
            'python3', 'Gateway/tools/paper_capture_command.py', '--output',
            str(directory / 'trigger'), '--', 'curl', '--interface', 'enp44s0',
            '--max-time', '4', '--silent', '--show-error', '-H',
            'Authorization: Bearer pg-lab-operator',
            'http://192.168.40.128/api/status'], cwd=root,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (directory / 'trigger-command.log').write_bytes(trigger.stdout)
    symbols = subprocess.check_output([nm, str(directory / 'policy_gate.elf')],
                                      cwd=root, text=True)
    match = re.search(r'^([0-9a-fA-F]+)\s+[bB]\s+gateway_fault_record$',
                      symbols, re.MULTILINE)
    if not match:
        raise SystemExit(f'probe {probe}: no fault record symbol')
    address = '0x' + match[1]
    swd = subprocess.run([cli, '-c', 'port=SWD',
                          'sn=066FFF555567894967085545', 'mode=HOTPLUG',
                          'freq=1000', '-r32', address, '32',
                          '-r32', '0xE000ED28', '24'], cwd=root,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (directory / 'swd.log').write_bytes(swd.stdout)
    (directory / 'probe.json').write_text(json.dumps({
        'probe': probe, 'board_exit_code': board.returncode,
        'swd_exit_code': swd.returncode,
        'fault_record_address': address,
        'serial_log': str(directory / 'board/uart.log'),
        'swd_log': str(directory / 'swd.log')}, indent=2) + '\n')
    print(f'probe={probe} board_exit={board.returncode} '
          f'swd_exit={swd.returncode} fault_record={address}', flush=True)
