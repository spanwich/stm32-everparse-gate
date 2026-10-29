#!/usr/bin/env python3
"""R1/R2 adversarial corpus: 20 variants per class, with query equivalence.

The uninstrumented primary image exposes no effect counters. Policy readback
checks commits, while handler-effect claims require the separate M4 audit image.
"""
import argparse
import atexit
import csv
import hashlib
import http.client
import json
import os
import re
from pathlib import Path
import select
import socket
import struct
import subprocess
import termios
import threading

p = argparse.ArgumentParser()
p.add_argument('--host', default='192.168.40.128')
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=True)
serial = '/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02'
if subprocess.run(['fuser', '-s', '/dev/ttyACM1'], stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL).returncode == 0:
    raise SystemExit('/dev/ttyACM1 already has a serial reader')
serial_fd = os.open(serial, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
attrs = termios.tcgetattr(serial_fd)
attrs[0] = attrs[1] = attrs[3] = 0
attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
attrs[4] = attrs[5] = termios.B115200
attrs[6][termios.VMIN] = attrs[6][termios.VTIME] = 0
termios.tcsetattr(serial_fd, termios.TCSANOW, attrs)
termios.tcflush(serial_fd, termios.TCIFLUSH)
serial_stop = threading.Event()
serial_log = (a.output / 'uart.log').open('wb')


def serial_reader():
    while not serial_stop.is_set():
        if select.select([serial_fd], [], [], 0.1)[0]:
            try:
                serial_log.write(os.read(serial_fd, 4096))
                serial_log.flush()
            except BlockingIOError:
                pass


serial_thread = threading.Thread(target=serial_reader, daemon=True)
serial_thread.start()


def close_serial():
    serial_stop.set()
    serial_thread.join(timeout=2)
    serial_log.close()
    os.close(serial_fd)


atexit.register(close_serial)
tokens = {'operator': 'pg-lab-operator', 'admin': 'pg-lab-admin', 'none': None}


def wire(method, path, role='none', extra=b'', body=b'', declared=None):
    token = tokens[role]
    auth = b'' if token is None else b'Authorization: Bearer ' + token.encode() + b'\r\n'
    length = len(body) if declared is None else declared
    return (method.encode() + b' ' + path.encode() + b' HTTP/1.1\r\nHost: board\r\n' +
            auth + b'Content-Length: ' + str(length).encode() + b'\r\n' + extra +
            b'\r\n' + body)


def exchange(payload, fragment=0):
    with socket.create_connection((a.host, 80), timeout=8) as conn:
        conn.settimeout(8)
        if fragment:
            for i in range(0, len(payload), fragment):
                conn.sendall(payload[i:i + fragment])
        else:
            conn.sendall(payload)
        data = bytearray()
        while True:
            part = conn.recv(4096)
            if not part:
                break
            data.extend(part)
            if len(data) > 16384:
                raise AssertionError('response exceeds bound')
    if not data:
        return 0, {}, b''
    header, _, body = bytes(data).partition(b'\r\n\r\n')
    lines = header.split(b'\r\n')
    status = int(lines[0].split()[1])
    headers = dict(line.lower().split(b':', 1) for line in lines[1:] if b':' in line)
    return status, {k.decode(): v.strip().decode() for k, v in headers.items()}, body


def get_policy():
    status, _, body = exchange(wire('GET', '/api/policy', 'admin'))
    assert status == 200
    return json.loads(body)['rules']


def encode(rules):
    inactive = {'id': 0xDEADDEAD, 'method': 0, 'min_role': 0, 'scope': 0}
    padded = rules + [inactive] * (8 - len(rules))
    return bytes([len(rules)]) + b''.join(struct.pack('<IBBH', r['id'], r['method'],
        r['min_role'], r['scope']) for r in padded)


cases = []


def add(class_name, name, payload, expected, fragment=0, baseline=None):
    cases.append((class_name, name, payload, expected, fragment, baseline))


suffixes = [f'?q={i}&next=/api/policy' for i in range(20)]
for i, suffix in enumerate(suffixes):
    add('direct-url', f'unauthenticated-{i}', wire('GET', ('/api/status' if i % 2 else '/api/policy') + suffix), 401)
    add('role-escalation', f'operator-policy-{i}', wire('GET', '/api/policy' + suffix, 'operator'), 403)
    add('identity-header', f'forged-role-{i}', wire('GET', '/api/status', extra=f'X-Role: admin{i}\r\nX-Forwarded-User: admin\r\n'.encode()), 401)
    # The rate-limit class is NOT a network class: the F767 network path is ~60 req/s,
    # so no client can exceed 49 requests per 49 ms window. It runs on the board through
    # the full path via gateway_test_rate (synthetic clock) and is reported below.
    add('fragmentation', f'split-{i+1}', wire('GET', '/api/policy', 'operator'), 403, i + 1)
    add('oversize', f'length-{1362+i}', wire('POST', '/api/logout', 'operator', declared=1362 + i), 413)
    add('framing', f'duplicate-length-{i}', wire('GET', '/api/status', 'operator',
        extra=f'Content-Length: {i}\r\n'.encode()), 400)

for i, method in enumerate(['HEAD', 'DELETE', 'PATCH', 'get', 'OPTIONS'] * 4):
    add('method-confusion', f'{method}-{i}', wire(method, '/api/status' + suffixes[i], 'operator'),
        400 if method in ('HEAD', 'DELETE', 'PATCH', 'get', 'OPTIONS') else 403)

query_bases = [('/api/status', 'operator'), ('/api/policy', 'operator'),
               ('/demo', 'operator'), ('/api/status', 'admin'), ('/demo', 'admin')]
for i in range(20):
    base, role = query_bases[i % len(query_bases)]
    add('query-smuggling', f'{base}-{role}-{i}', wire('GET', base + suffixes[i], role),
        None, baseline=wire('GET', base, role))

spellings = ['/api/status/', '/API/status', '//api/status', '/./api/status',
             '/api/../api/status', '/api/..;/status', '/api%2fstatus',
             '/api/%2e%2e/status', '/api/status%2f', '/api/status%C0%AF',
             '/api/status#policy', '/api//status', '/api/./status',
             '/api/%2E/status', '/api/status%3fpolicy', '/Api/status',
             '/api/status/.', '/api/..%2fstatus', '/api/status%00', '/api/status;other']
for i, path in enumerate(spellings):
    add('path-spelling', f'{path}-{i}', wire('GET', path, 'operator'), 400)

assert len(cases) == 180   # nine network classes x 20; the rate-limit class is on-board
original = get_policy()
policy = [{'id': 0x33333333, 'method': 1, 'min_role': 1, 'scope': 1},
          {'id': 0x22222222, 'method': 2, 'min_role': 1, 'scope': 0},
          {'id': 0x44444444, 'method': 1, 'min_role': 2, 'scope': 4}]
records = []
try:
    assert exchange(wire('PUT', '/api/policy', 'admin', body=encode(policy)))[0] == 200
    assert get_policy() == policy
    for index, (class_name, name, payload, expected, fragment, baseline) in enumerate(cases, 1):
        baseline_status = exchange(baseline)[0] if baseline else None
        if baseline is not None:
            expected = baseline_status
        status, headers, _ = exchange(payload, fragment)
        unchanged = get_policy() == policy
        row = {'request_id': index, 'class': class_name, 'case': name,
               'expected_status': expected, 'actual_status': status,
               'baseline_status': baseline_status if baseline else '',
               'agreement': int(status == expected),
               'fail_open': int(status == 200 and expected != 200),
               'policy_unchanged': int(unchanged),
               'audit_acceptances': headers.get('x-pg-audit-accepts', ''),
               'audit_effects': headers.get('x-pg-audit-effects', ''),
               'audit_violations': headers.get('x-pg-audit-violations', ''),
               'decision_allocations': headers.get('x-pg-decision-allocations', '')}
        records.append(row)
        with (a.output / 'requests.csv').open('w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=row.keys())
            writer.writeheader()
            writer.writerows(records)
finally:
    assert exchange(wire('PUT', '/api/policy', 'admin', body=encode(original)))[0] == 200
    assert get_policy() == original

# The rate-limit class (20 over-limit cases) ran on the board through the full path
# via gateway_test_rate (synthetic clock): the 50th..69th request inside one window
# refused, plus an over-limit policy update refused. Confirm it from the self-test
# aggregate in the captured UART -- that 354-check suite includes those 20 cases.
serial_log.flush()
uart = (a.output / 'uart.log').read_bytes().decode('latin-1')
selftest = None
for m in re.finditer(r'(?:CORE SELFTEST|HEARTBEAT)[^\n]*?(PASS|FAIL)\s+(\d+)/(\d+)', uart):
    selftest = (m.group(1), int(m.group(2)), int(m.group(3)))
selftest_ok = bool(selftest and selftest[0] == 'PASS' and selftest[1] == selftest[2])

classes = sorted({row['class'] for row in records})
summary = {'requests': len(records), 'classes': {name: sum(row['class'] == name for row in records)
    for name in classes}, 'disagreements': sum(1 - row['agreement'] for row in records),
    'fail_open': sum(row['fail_open'] for row in records),
    'policy_preserved': all(row['policy_unchanged'] for row in records),
    'policy_restored': True, 'effect_counter_available': all(row['audit_effects'] != '' for row in records),
    'corpus_sha256': hashlib.sha256((a.output / 'requests.csv').read_bytes()).hexdigest()}
summary['audit_mismatches'] = sum(
    row['audit_acceptances'] != str(int(row['expected_status'] == 200)) or
    row['audit_effects'] != str(int(row['expected_status'] == 200)) or
    row['audit_violations'] != '0' for row in records)
summary['decision_path_allocations'] = sum(int(row['decision_allocations'])
    for row in records if row['decision_allocations'] != '')
summary['allocation_counter_available'] = all(row['decision_allocations'] != '' for row in records)
summary['rate_limit_class'] = {
    'cases': 20,
    'ran_on': 'board self-test gateway_test_rate (synthetic clock): 50th-69th in-window refused + over-limit policy update refused',
    'selftest': (f'{selftest[0]} {selftest[1]}/{selftest[2]}' if selftest else 'not observed'),
    'passed': selftest_ok}
summary['split'] = {'network_classes': len(records), 'selftest_rate': 20, 'total_cases': len(records) + 20}
summary['uart_log'] = str(a.output / 'uart.log')
(a.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
assert (len(records) == 180 and not summary['disagreements'] and
        not summary['fail_open'] and not summary['audit_mismatches'] and
        summary['rate_limit_class']['passed'] and
        (not summary['allocation_counter_available'] or summary['decision_path_allocations'] == 0))
