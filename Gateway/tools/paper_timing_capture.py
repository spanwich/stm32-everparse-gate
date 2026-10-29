#!/usr/bin/env python3
"""Flash/reset only the named NUCLEO, capture raw DWT blocks and decode CSV."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import statistics
import struct
import subprocess
import termios
import time

p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, required=True)
p.add_argument('--boots', type=int, default=5)
p.add_argument('--seconds', type=int, default=240)
p.add_argument('--clock-hz', type=int, default=96000000)
p.add_argument('--variant', default='V0')
p.add_argument('--baud', type=int, choices=(115200, 921600), default=921600)
p.add_argument('--interrupts', choices=('enabled','masked'), default='enabled')
a = p.parse_args()
assert 1 <= a.boots <= 5
root = Path(__file__).resolve().parents[2]
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=True)
source = root / 'Debug/policy_gate.elf'
elf = out / 'timing-policy_gate.elf'
subprocess.run(['python3', str(root / 'Gateway/tools/check_firmware.py'), str(source)], check=True)
shutil.copy2(source, elf)
cli = '/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.linux64_2.2.300.202508131133/tools/bin/STM32_Programmer_CLI'
serial = '/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02'
if subprocess.run(['fuser', '-s', '/dev/ttyACM1'], stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL).returncode == 0:
    raise SystemExit('/dev/ttyACM1 already has a reader')
fd = os.open(serial, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
attrs = termios.tcgetattr(fd)
attrs[0] = attrs[1] = attrs[3] = 0
attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
attrs[4] = attrs[5] = termios.B921600 if a.baud == 921600 else termios.B115200
attrs[6][termios.VMIN] = 0
attrs[6][termios.VTIME] = 0
termios.tcsetattr(fd, termios.TCSANOW, attrs)


def decode(raw, destination):
    expected = [(0, 0)] + [(stage, case) for stage in range(1, 8) for case in range(7)]
    rows = []
    offset = 0
    for stage, case in expected:
        while True:
            marker = raw.find(b'PGB1', offset)
            assert marker >= 0, f'missing block {stage}/{case}'
            if raw[marker + 4:marker + 8] == bytes([stage, case, 0x10, 0x27]):
                break
            offset = marker + 4
        end = marker + 8 + 40000
        assert end <= len(raw), f'truncated block {stage}/{case}'
        values = struct.unpack_from('<10000I', raw, marker + 8)
        rows.extend((stage, case, i, value) for i, value in enumerate(values))
        offset = end
    assert b'[PAPER TIMING] done samples=10000' in raw[offset:], 'timing completion missing'
    with destination.open('w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(('stage', 'case', 'sample', 'cycles'))
        writer.writerows(rows)
    return rows


results = []
try:
    for boot in range(1, a.boots + 1):
        termios.tcflush(fd, termios.TCIFLUSH)
        command = [cli, '-c', 'port=SWD', 'sn=066FFF555567894967085545',
                   'mode=UR', 'freq=1000']
        if boot == 1:
            command += ['-d', str(elf), '-v']
        command += ['-rst', '-run']
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        raw_path = out / f'boot-{boot}.uart.bin'
        tail = b''
        deadline = time.monotonic() + a.seconds
        with raw_path.open('wb') as stream:
            while time.monotonic() < deadline:
                if select.select([fd], [], [], 0.2)[0]:
                    try:
                        chunk = os.read(fd, 8192)
                    except BlockingIOError:
                        continue
                    stream.write(chunk)
                    tail = (tail + chunk)[-256:]
                    if b'[PAPER TIMING] done samples=10000' in tail:
                        break
            else:
                proc.kill()
                raise TimeoutError(f'boot {boot} did not finish timing; raw UART saved')
        output, _ = proc.communicate(timeout=90)
        (out / f'boot-{boot}.programmer.log').write_bytes(output)
        assert proc.returncode == 0, f'programmer failed on boot {boot}'
        if boot == 1:
            assert b'Download verified successfully' in output
        raw = raw_path.read_bytes()
        assert b'[BOOT] SYSCLK=' + str(a.clock_hz).encode() in raw, 'clock variant differs from boot report'
        assert b'[CORE SELFTEST] PASS 353/353' in raw
        assert b'[PAPER CORPUS] comparisons=12527 failures=0' in raw
        assert b'interrupts=' + a.interrupts.encode() in raw, 'interrupt setting differs from capture label'
        csv_path = out / f'boot-{boot}.cycles.csv'
        rows = decode(raw, csv_path)
        results.append({'boot': boot, 'samples': len(rows),
                        'uart_sha256': hashlib.sha256(raw).hexdigest(),
                        'csv_sha256': hashlib.sha256(csv_path.read_bytes()).hexdigest()})
        print(f'Boot {boot}: {len(rows)} raw cycle samples saved', flush=True)
finally:
    os.close(fd)

grouped = {}
for boot in range(1, a.boots + 1):
    with (out / f'boot-{boot}.cycles.csv').open() as file:
        for row in csv.DictReader(file):
            key = (int(row['stage']), int(row['case']))
            grouped.setdefault(key, []).append(int(row['cycles']))
summary = {'firmware_elf_sha256': hashlib.sha256(elf.read_bytes()).hexdigest(),
           'variant': a.variant, 'clock_hz': a.clock_hz, 'uart_baud': a.baud,
           'interrupts': a.interrupts, 'boots': results,
           'stage_names': ['empty', 'validator', 'serializer_validator',
                           'extractor', 'handwritten', 'request_processing',
                           'serializer', 'field_serializer'],
           'case_names': ['first_allow', 'last_allow', 'absent_path',
                          'method_deny', 'role_deny', 'scope_deny', 'rate_deny'],
           'statistics': {}}
for (stage, case), samples in sorted(grouped.items()):
    ordered = sorted(samples)
    summary['statistics'][f'{stage}:{case}'] = {
        'n': len(samples), 'min': ordered[0], 'median': statistics.median(ordered),
        'p99': ordered[(99 * len(ordered) + 99) // 100 - 1], 'max': ordered[-1]}
(out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print('DWT capture complete:', out)
