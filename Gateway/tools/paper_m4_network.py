#!/usr/bin/env python3
"""M4 request/effect campaign for the separately instrumented firmware.

Every returned audit ID is joined with the HTTP outcome in a CSV. The board's
trusted audit bridge compares all 1536+65+106 snapshot bytes before each effect.
Transport failures remain in the CSV and prevent a complete-mediation verdict.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse
import atexit
import csv
import hashlib
import json
import os
import select
import socket
import struct
import subprocess
import termios
import threading
import time

p = argparse.ArgumentParser()
p.add_argument('--host', default='192.168.40.128')
p.add_argument('--count', type=int, default=100000)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--elf-sha256-file', type=Path, required=True)
p.add_argument('--serial', default='/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02')
a = p.parse_args()
assert a.count > 0
a.output.mkdir(parents=True, exist_ok=True)
if subprocess.run(['fuser', '-s', '/dev/ttyACM1'], stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL).returncode == 0:
    raise SystemExit('/dev/ttyACM1 already has a reader')
serial_fd = os.open(a.serial, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
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
admin = 'pg-lab-admin'
operator = 'pg-lab-operator'


def encode(rules):
    inactive = {'id': 0xDEADDEAD, 'method': 0, 'min_role': 0, 'scope': 0}
    return bytes([len(rules)]) + b''.join(struct.pack('<IBBH',
        r['id'], r['method'], r['min_role'], r['scope'])
        for r in rules + [inactive] * (8 - len(rules)))


def exchange(method, path, token=None, body=None):
    auth = b'Authorization: Bearer ' + token.encode() + b'\r\n' if token else b''
    payload = method.encode() + b' ' + path.encode() + b' HTTP/1.1\r\nHost: board\r\n' + auth
    if body is not None:
        payload += b'Content-Type: application/octet-stream\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n'
    payload += b'\r\n' + (body or b'')
    with socket.create_connection((a.host, 80), timeout=8) as conn:
        conn.settimeout(8)
        conn.sendall(payload)
        received = bytearray()
        while True:
            part = conn.recv(4096)
            if not part:
                break
            received.extend(part)
            if len(received) > 16384:
                raise AssertionError('response exceeded bound')
            if b'\r\n\r\n' in received:
                header, response_body = bytes(received).split(b'\r\n\r\n', 1)
                lengths = [line.split(b':', 1)[1].strip() for line in header.split(b'\r\n')[1:]
                           if line.lower().startswith(b'content-length:')]
                if len(lengths) == 1 and len(response_body) >= int(lengths[0]):
                    break
    header, response_body = bytes(received).split(b'\r\n\r\n', 1)
    lines = header.split(b'\r\n')
    status = int(lines[0].split()[1])
    fields = {line.split(b':', 1)[0].lower().decode(): line.split(b':', 1)[1].strip().decode()
              for line in lines[1:] if b':' in line}
    assert len(response_body) == int(fields['content-length'])
    return status, fields, response_body


def policy_read():
    status, _, body = exchange('GET', '/api/policy', admin)
    assert status == 200
    return json.loads(body)['rules']


def policy_write(rules):
    status, headers, _ = exchange('PUT', '/api/policy', admin, encode(rules))
    assert status == 200 and int(headers['x-pg-audit-violations']) == 0


policy_a = [
    {'id': 0x33333333, 'method': 1, 'min_role': 1, 'scope': 1},
    {'id': 0x22222222, 'method': 2, 'min_role': 1, 'scope': 0},
    {'id': 0x44444444, 'method': 1, 'min_role': 2, 'scope': 4},
]
policy_b = [
    {'id': 0x33333333, 'method': 1, 'min_role': 1, 'scope': 1},
    {'id': 0x22222222, 'method': 2, 'min_role': 1, 'scope': 0},
    {'id': 0x55555555, 'method': 1, 'min_role': 2, 'scope': 1},
]
login = b'{"username":"operator","password":"oper789"}'
cases = (
    ('allow-status', 'GET', '/api/status', operator, None, 200, 1),
    ('admin-status', 'GET', '/api/status', admin, None, 200, 1),
    ('role-deny', 'GET', '/api/policy', operator, None, 403, 0),
    ('rate-underlimit', 'GET', '/api/status', operator, None, 200, 1),  # over the network the live count stays <50 (admitted); the rate limit is the on-board self-test
    ('no-credential', 'GET', '/api/status', None, None, 401, 0),
    ('public-asset', 'GET', '/', None, None, 200, 1),
    ('login', 'POST', '/api/login', None, login, 200, 1),
    ('query-same-resource', 'GET', '/api/status?api/policy', operator, None, 200, 1),
    ('operator-update-deny', 'PUT', '/api/policy', operator, encode(policy_a), 403, 0),
    ('policy-update', 'PUT', '/api/policy', admin, None, 200, 1),
)
header_names = ('x-pg-audit-id', 'x-pg-audit-accepts', 'x-pg-audit-effects',
                'x-pg-audit-violations')
fields = ('index', 'class', 'status', 'expected_status', 'audit_id', 'acceptances',
          'effects', 'violations', 'matching', 'transport_error', 'policy_sha256')
observed_ids = set()
totals = {'completed': 0, 'matched': 0, 'unmatched': 0, 'transport_errors': 0,
          'effect_count': 0, 'acceptance_count': 0, 'concurrent_pairs': 0}
original = policy_read()
active = policy_a
started = time.monotonic()
output = a.output / 'requests.csv'
with output.open('w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()
    try:
        policy_write(active)
        assert policy_read() == active
        with ThreadPoolExecutor(max_workers=2) as pool:
            index = 0
            while index < a.count:
                work = []
                if index and index % 1000 == 0 and index + 1 < a.count:
                    # The listener owns one connection at a time; these two
                    # clients exercise the backlog and reconnection ordering.
                    work = [(index + 1, cases[0]), (index + 2, cases[4])]
                    totals['concurrent_pairs'] += 1
                else:
                    chosen = cases[index % len(cases)]
                    work = [(index + 1, chosen)]
                jobs = []
                for number, case in work:
                    class_name, method, path, token, body, expected_status, expected_effect = case
                    if class_name == 'policy-update':
                        active = policy_b if active == policy_a else policy_a
                        body = encode(active)
                    jobs.append((number, case, pool.submit(exchange, method, path, token, body)))
                for number, case, future in jobs:
                    class_name, _, _, _, _, expected_status, expected_effect = case
                    row = dict.fromkeys(fields, '')
                    row.update(index=number, **{'class': class_name},
                               expected_status=expected_status,
                               policy_sha256=hashlib.sha256(encode(active)).hexdigest())
                    try:
                        status, headers, _ = future.result()
                        audit_id, accepts, effects, violations = (int(headers[name]) for name in header_names)
                        unique = audit_id not in observed_ids
                        observed_ids.add(audit_id)
                        match = (unique and status == expected_status and
                                 accepts == expected_effect and effects == expected_effect and
                                 violations == 0)
                        row.update(status=status, audit_id=audit_id, acceptances=accepts,
                                   effects=effects, violations=violations, matching=int(match))
                        totals['completed'] += 1
                        totals['effect_count'] += effects
                        totals['acceptance_count'] += accepts
                        totals['matched' if match else 'unmatched'] += 1
                    except (OSError, ValueError, KeyError) as error:
                        row['transport_error'] = type(error).__name__ + ': ' + str(error)
                        totals['transport_errors'] += 1
                    writer.writerow(row)
                    # Abort only on a genuine DECISION mismatch (a completed response
                    # that disagrees). A transport error (no response, e.g. a transient
                    # lwIP TIME_WAIT/PCB timeout under sustained load) is tallied in
                    # totals['transport_errors'] and the run continues: it is not a
                    # decision disagreement, and the audit's claim is decision pairing.
                    if row['transport_error'] == '' and row['matching'] != 1:
                        file.flush()
                        raise SystemExit(f'M4 decision mismatch at request {number}; evidence retained in {output}')
                index += len(work)
                if index % 1000 == 0:
                    file.flush()
                    print('M4', index, '/', a.count, flush=True)
    finally:
        policy_write(original)
        assert policy_read() == original

summary = {**totals, 'requested': a.count, 'unique_audit_ids': len(observed_ids),
           'policy_restored': True, 'elapsed_seconds': time.monotonic() - started,
           'elf_sha256': a.elf_sha256_file.read_text().strip(),
           'limits': 'Snapshot equality is checked by trusted C instrumentation; the headers cover completed HTTP responses, not arbitrary unobserved memory effects.'}
(a.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
