#!/usr/bin/env python3
"""Labelled, fail-closed HTTP attack corpus for the paper's M5 experiment.

The audit image also returns trusted per-request acceptance/effect counters.
The uninstrumented baseline supplies only status and policy readback.
"""
from pathlib import Path
import argparse
import csv
import hashlib
import http.client
import json
import socket
import struct

p = argparse.ArgumentParser()
p.add_argument('--host', default='192.168.40.128')
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=True)
admin = 'pg-lab-admin'
operator = 'pg-lab-operator'


def request(method, path, token=None, body=None):
    conn = http.client.HTTPConnection(a.host, 80, timeout=8)
    headers = {'Authorization': 'Bearer ' + token} if token else {}
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def active_policy():
    status, body = request('GET', '/api/policy', admin)
    assert status == 200
    return json.loads(body)['rules']


def encode(rules):
    assert 1 <= len(rules) <= 8
    return bytes([len(rules)]) + b''.join(struct.pack('<IBBH',
        r['id'], r['method'], r['min_role'], r['scope']) for r in rules) + bytes(8 * (8 - len(rules)))


def raw(method, path, token=None, extra=b'', body=b'', length=True):
    auth = b'' if token is None else b'Authorization: Bearer ' + token.encode() + b'\r\n'
    content = b'' if not length else b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
    return method.encode() + b' ' + path.encode() + b' HTTP/1.1\r\nHost: board\r\n' + auth + content + extra + b'\r\n' + body


def exchange(data, fragment=None):
    with socket.create_connection((a.host, 80), timeout=8) as sock:
        sock.settimeout(8)
        response = bytearray()
        try:
            if fragment:
                for index in range(0, len(data), fragment):
                    sock.sendall(data[index:index + fragment])
            else:
                sock.sendall(data)
            while True:
                part = sock.recv(4096)
                if not part:
                    break
                response.extend(part)
                assert len(response) <= 16384
        except (BrokenPipeError, ConnectionResetError):
            pass
        if not response:
            return 'connection_reset', {}
        head = bytes(response).split(b'\r\n\r\n', 1)[0]
        lines = head.split(b'\r\n')
        headers = dict(line.lower().split(b':', 1) for line in lines[1:] if b':' in line)
        return int(lines[0].split()[1]), {key.decode(): value.strip().decode() for key, value in headers.items()}


cases = [
    ('direct-url', 'status without credentials', raw('GET', '/api/status'), None),
    ('direct-url', 'policy without credentials', raw('GET', '/api/policy'), None),
    ('role-escalation', 'operator reads admin policy', raw('GET', '/api/policy', operator), None),
    ('identity-header', 'X-Role without credentials', raw('GET', '/api/status', extra=b'X-Role: admin\r\n'), None),
    ('identity-header', 'X-Forwarded-User on admin route', raw('GET', '/api/policy', operator, b'X-Forwarded-User: admin\r\n'), None),
    ('identity-header', 'duplicate Authorization', raw('GET', '/api/policy', operator, b'Authorization: Bearer pg-lab-admin\r\n'), None),
    ('identity-header', 'duplicate Authorization reversed', raw('GET', '/api/policy', admin, b'Authorization: Bearer pg-lab-operator\r\n'), None),
    ('method-confusion', 'HEAD protected API', raw('HEAD', '/api/status', operator), None),
    ('method-confusion', 'lowercase GET', raw('get', '/api/status', operator), None),
    ('method-confusion', 'unknown method', raw('PATCH', '/api/status', operator), None),
    ('method-confusion', 'GET on logout', raw('GET', '/api/logout', operator), None),
    ('query-smuggling', 'demo query points to API', raw('GET', '/demo?api/status', admin), None),
    ('query-smuggling', 'status query points to policy', raw('GET', '/api/status?api/policy', operator), None),
    ('query-smuggling', 'encoded question mark', raw('GET', '/api/status%3fapi/policy', operator), None),
    ('oversize', 'declared 1362-byte body', raw('POST', '/api/logout', operator,
        extra=b'Content-Length: 1362\r\n', length=False), None),
    ('framing', 'duplicate content length', raw('POST', '/api/logout', operator, b'Content-Length: 0\r\n'), None),
    ('framing', 'chunked transfer encoding', raw('POST', '/api/logout', operator, b'Transfer-Encoding: chunked\r\n'), None),
]
for variant in ('/api/status/', '/API/status', '//api/status', '/./api/status',
                '/api/../api/status', '/api/..;/status', '/api%2fstatus',
                '/api/%2e%2e/status', '/api/status%2f', '/api/status%C0%AF'):
    cases.append(('path-spelling', variant, raw('GET', variant, operator), None))

records = []
original = active_policy()
# Three active rules and five inactive slots, matching the paper's default size.
policy = [
    {'id': 0x33333333, 'method': 1, 'min_role': 1, 'scope': 1},
    {'id': 0x22222222, 'method': 2, 'min_role': 1, 'scope': 0},
    {'id': 0x44444444, 'method': 1, 'min_role': 2, 'scope': 4},
]
try:
    assert request('PUT', '/api/policy', admin, encode(policy))[0] == 200
    assert active_policy() == policy
    policy_hash = hashlib.sha256(encode(policy)).hexdigest()
    cases.append(('role-escalation', 'operator policy write',
                  raw('PUT', '/api/policy', operator, body=encode(original)), None))
    # The rate-limit class is not a network case (the network path cannot exceed 49
    # requests per 49 ms window); it runs on the board via the gateway_test_rate self-test.
    cases.append(('fragmentation', 'fragmented protected request', raw('GET', '/api/policy', operator), 1))
    for number, (class_name, name, wire, fragment) in enumerate(cases, 1):
        status, headers = exchange(wire, fragment)
        unchanged = active_policy() == policy
        row = {'request_id': number, 'class': class_name, 'case': name,
               'expected_decision': 'deny', 'actual_status': status,
               'fail_open': int(status == 200), 'policy_unchanged': int(unchanged),
               'policy_sha256': policy_hash,
               'audit_id': headers.get('x-pg-audit-id', ''),
               'acceptances': headers.get('x-pg-audit-accepts', ''),
               'effects': headers.get('x-pg-audit-effects', ''),
               'violations': headers.get('x-pg-audit-violations', '')}
        records.append(row)
        with (a.output / 'attack-requests.csv').open('w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=row.keys())
            writer.writeheader()
            writer.writerows(records)
finally:
    assert request('PUT', '/api/policy', admin, encode(original))[0] == 200
    assert active_policy() == original

summary = {'requests': len(records), 'fail_open': sum(r['fail_open'] for r in records),
           'policy_preserved': all(r['policy_unchanged'] for r in records),
           'policy_restored': True, 'effect_counter_available': False,
           'classes': {name: sum(r['class'] == name for r in records) for name in sorted({r['class'] for r in records})}}
summary['effect_counter_available'] = all(r['effects'] != '' for r in records)
summary['unmatched_effects'] = sum(int(r['effects'] != '' and
    (int(r['effects']) != 0 or int(r['acceptances']) != 0 or int(r['violations']) != 0))
    for r in records)
(a.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
if summary['fail_open'] or not summary['policy_preserved'] or summary['unmatched_effects']:
    raise SystemExit('Attack corpus found fail-open, policy mutation or unmatched effect; see attack-requests.csv')
