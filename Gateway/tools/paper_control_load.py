#!/usr/bin/env python3
"""Ten-minute control-task load scenario with single-reader UART audit capture."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import termios
import threading
import time

p = argparse.ArgumentParser()
p.add_argument('--scenario', choices=('idle', 'valid', 'denied', 'malformed'), required=True)
p.add_argument('--duration-seconds', type=int, default=600)
p.add_argument('--interval-ms', type=float, default=0.0)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--elf', type=Path, default=Path('Debug/policy_gate.elf'))
a = p.parse_args()
assert a.duration_seconds >= 1
a.output.mkdir(parents=True, exist_ok=True)
elf_sha256 = hashlib.sha256(a.elf.read_bytes()).hexdigest()
serial = '/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02'
if subprocess.run(['fuser', '-s', '/dev/ttyACM1'], stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL).returncode == 0:
    raise SystemExit('/dev/ttyACM1 already has a reader')
fd = os.open(serial, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
attrs = termios.tcgetattr(fd)
attrs[0] = attrs[1] = attrs[3] = 0
attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
attrs[4] = attrs[5] = termios.B115200
attrs[6][termios.VMIN] = attrs[6][termios.VTIME] = 0
termios.tcsetattr(fd, termios.TCSANOW, attrs)
termios.tcflush(fd, termios.TCIFLUSH)
stop = threading.Event()
ready = threading.Event()
uart_path = a.output / 'uart.log'


def read_uart():
    tail = b''
    with uart_path.open('wb') as log:
        while not stop.is_set():
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    chunk = os.read(fd, 4096)
                except BlockingIOError:
                    continue
                log.write(chunk)
                log.flush()
                tail = (tail + chunk)[-128:]
                if b'[HTTP] READY' in tail:
                    ready.set()


thread = threading.Thread(target=read_uart)
thread.start()
records = []
request_file = (a.output / 'requests.csv').open('w', newline='')
writer = csv.DictWriter(request_file, fieldnames=('index', 'seconds', 'expected_status',
    'actual_status', 'latency_ms', 'error'))
writer.writeheader()
try:
    cli = '/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.linux64_2.2.300.202508131133/tools/bin/STM32_Programmer_CLI'
    command = [cli, '-c', 'port=SWD', 'sn=066FFF555567894967085545',
               'mode=UR', 'freq=1000', '-rst', '-run']
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=90)
    (a.output / 'programmer.log').write_bytes(result.stdout)
    assert result.returncode == 0
    assert ready.wait(45), 'HTTP listener did not start'

    def exchange(payload):
        with socket.create_connection(('192.168.40.128', 80), timeout=8) as conn:
            conn.settimeout(8)
            conn.sendall(payload)
            data = bytearray()
            while True:
                part = conn.recv(4096)
                if not part:
                    break
                data.extend(part)
                if len(data) > 16384:
                    raise AssertionError('response exceeded bound')
                if b'\r\n\r\n' in data:
                    head, body = bytes(data).split(b'\r\n\r\n', 1)
                    lengths = re.findall(rb'(?im)^content-length:\s*([0-9]+)\r?$', head)
                    if len(lengths) == 1 and len(body) >= int(lengths[0]):
                        break
            if not data or b'\r\n\r\n' not in data:
                raise AssertionError('incomplete HTTP response')
        return int(bytes(data).split(b'\r\n', 1)[0].split()[1])

    rules = ((0x33333333, 1, 1, 1), (0x22222222, 2, 1, 0),
             (0x44444444, 1, 2, 4))
    policy_wire = bytes([3]) + b''.join(struct.pack('<IBBH', *rule) for rule in rules)
    policy_wire += struct.pack('<IBBH', 0xDEADDEAD, 0, 0, 0) * 5
    update = (b'PUT /api/policy HTTP/1.1\r\nHost: board\r\n'
              b'Authorization: Bearer pg-lab-admin\r\nContent-Length: 65\r\n\r\n' + policy_wire)
    assert exchange(update) == 200, 'paper three-rule policy update failed'

    valid = b'GET /api/status HTTP/1.1\r\nHost: board\r\nAuthorization: Bearer pg-lab-operator\r\n\r\n'
    denied = [
        (b'GET /api/status HTTP/1.1\r\nHost: board\r\n\r\n', 401),
        (b'GET /api/policy HTTP/1.1\r\nHost: board\r\nAuthorization: Bearer pg-lab-operator\r\n\r\n', 403),
        (b'GET /unknown HTTP/1.1\r\nHost: board\r\nAuthorization: Bearer pg-lab-operator\r\n\r\n', 400),
    ]
    malformed = [
        (b'GET /api/status HTTP/1.1\r\nHost: board\r\nAuthorization: Bearer pg-lab-operator\r\nAuthorization: Bearer pg-lab-admin\r\n\r\n', 400),
        (b'POST /api/logout HTTP/1.1\r\nHost: board\r\nContent-Length: 1362\r\n\r\n', 413),
        (b'OPTIONS /api/status HTTP/1.1\r\nHost: board\r\n\r\n', 400),
    ]
    start = time.monotonic()
    index = 0
    while time.monotonic() - start < a.duration_seconds:
        if a.scenario == 'idle':
            time.sleep(0.2)
            continue
        payload, expected = ((valid, 200) if a.scenario == 'valid' else
                             (denied if a.scenario == 'denied' else malformed)[index % 3])
        now = time.monotonic()
        actual = 0
        error = ''
        try:
            actual = exchange(payload)
        except (OSError, ValueError, IndexError, AssertionError) as exc:
            error = type(exc).__name__ + ': ' + str(exc)
        row = {'index': index, 'seconds': round(now - start, 6),
                        'expected_status': expected, 'actual_status': actual,
                        'latency_ms': round((time.monotonic() - now) * 1000, 3),
                        'error': error}
        records.append(row)
        writer.writerow(row)
        if index % 100 == 0:
            request_file.flush()
        index += 1
        if a.interval_ms > 0:
            time.sleep(max(0.0, start + index * a.interval_ms / 1000 - time.monotonic()))
        if index % 1000 == 0:
            print(a.scenario, index, 'requests', flush=True)
    elapsed = time.monotonic() - start
finally:
    request_file.close()
    stop.set()
    thread.join(timeout=3)
    os.close(fd)

text = uart_path.read_text(errors='replace')
boot = text.rfind('[BOOT] policy_gate')
assert boot >= 0, 'fresh boot marker missing from UART capture'
text = text[boot:]
controls = [tuple(map(int, match)) for match in re.findall(
    r'\[CTRL\] samples=(\d+) misses=(\d+) max_cycles=(\d+) p99_bucket_us=(\d+) stack_free=(\d+)', text)]
assert len(controls) >= a.duration_seconds - 5, 'control observations missing'
runtime = {}
for name, cycles, total in re.findall(
    r'\[RUNTIME\] task=(.+?) cycles=(\d+) total_cycles=(\d+)', text):
    runtime[name] = runtime.get(name, 0) + int(cycles)
gatecpu = [tuple(map(int, match)) for match in re.findall(
    r'\[GATECPU\] decision_cycles=(\d+) decision_calls=(\d+) request_cycles=(\d+) request_calls=(\d+)', text)]
# The first diagnostics interval can include startup self-tests before READY.
gatecpu = gatecpu[1:]
decision_cycles = sum(row[0] for row in gatecpu)
request_cycles = sum(row[2] for row in gatecpu)
runtime_total = sum(runtime.values())
summary = {'scenario': a.scenario, 'duration_seconds': elapsed,
           'interval_ms': a.interval_ms,
           'elf_sha256': elf_sha256,
           'policy_sha256': hashlib.sha256(policy_wire).hexdigest(),
           'active_rule_slots': 3,
           'requests': len(records), 'status_mismatches': sum(r['actual_status'] != r['expected_status'] for r in records),
           'transport_errors': sum(bool(r['error']) for r in records),
           'control_samples': controls[-1][0] - controls[0][0],
           'control_task_misses': controls[-1][1] - controls[0][1],
           'control_max_cycles': max(item[2] for item in controls),
           'control_p99_bucket_us': controls[-1][3],
           'runtime_cycles_by_task': runtime,
           'cpu_share_by_task': {name: cycles / runtime_total for name, cycles in runtime.items()} if runtime_total else {},
           'decision_cycles': decision_cycles,
           'request_processing_cycles': request_cycles,
           'cpu_share_gate': decision_cycles / (elapsed * 96_000_000),
           'decision_share_of_request_processing': decision_cycles / request_cycles if request_cycles else None,
           'uart_log': str(uart_path)}
(a.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
assert summary['status_mismatches'] == 0 and summary['transport_errors'] == 0
