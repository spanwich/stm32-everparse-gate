#!/usr/bin/env python3
"""Independent three-rule HTTP decision oracle against the audit firmware.

This is an adapted STM32 corpus, not the seL4 bit-mask-method corpus. HTTP
fixtures expose rate counts 0 and 50; rate 49/255 and authenticated role 0
require a separate board fixture and are not claimed here.
"""
from pathlib import Path
import argparse
import csv
import hashlib
import http.client
import json
import random
import struct
import time

p = argparse.ArgumentParser()
p.add_argument('--host', default='192.168.40.128')
p.add_argument('--count', type=int, default=12527)
p.add_argument('--seed', type=int, default=20260929)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
assert a.count > 0
a.output.mkdir(parents=True, exist_ok=True)
rng = random.Random(a.seed)
PATH_STATUS, PATH_DEMO, DEAD = 0x33333333, 0x55555555, 0xDEADDEAD
tokens = {'operator': ('pg-lab-operator', 1, 1, 0),
          'admin': ('pg-lab-admin', 2, 7, 0),
          'limited': ('pg-lab-limited', 1, 1, 50)}


def encode(rules):
    return bytes([len(rules)]) + b''.join(struct.pack('<IBBH',
        r['id'], r['method'], r['min_role'], r['scope']) for r in rules) + bytes(8 * (8 - len(rules)))


def exchange(method, path, token=None, body=None):
    conn = http.client.HTTPConnection(a.host, 80, timeout=8)
    headers = {'Authorization': 'Bearer ' + token} if token else {}
    if body is not None:
        headers['Content-Type'] = 'application/octet-stream'
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        status = response.status
        fields = {key.lower(): value for key, value in response.getheaders()}
        data = response.read()
        return status, fields, data
    finally:
        conn.close()


def policy_read():
    status, _, body = exchange('GET', '/api/policy', tokens['admin'][0])
    assert status == 200
    return json.loads(body)['rules']


def policy_write(rules):
    status, headers, _ = exchange('PUT', '/api/policy', tokens['admin'][0], encode(rules))
    assert status == 200 and int(headers['x-pg-audit-accepts']) == 1
    assert int(headers['x-pg-audit-effects']) == 1 and int(headers['x-pg-audit-violations']) == 0


def rule(path=DEAD, method=0, role=0, scope=0):
    return {'id': path, 'method': method, 'min_role': role, 'scope': scope}


def make_case(index):
    kind = ('first-allow', 'last-allow', 'absent-path', 'method-deny',
            'role-deny', 'scope-deny', 'rate-deny', 'admin-boundary',
            'scope-boundary', 'random')[index % 10]
    rules = [rule(), rule(), rule()]
    path, method, identity = PATH_STATUS, 1, 'operator'
    if kind == 'first-allow':
        rules[0] = rule(path, method, 1, 1)
    elif kind == 'last-allow':
        rules[2] = rule(path, method, 1, 1)
    elif kind == 'absent-path':
        rules[0] = rule(0, method, 0, 0)
    elif kind == 'method-deny':
        rules[0] = rule(path, 2, 1, 1)
    elif kind == 'role-deny':
        rules[0] = rule(path, method, 2, 1)
    elif kind == 'scope-deny':
        rules[0] = rule(path, method, 1, 2)
    elif kind == 'rate-deny':
        identity = 'limited'
        rules[0] = rule(path, method, 1, 1)
    elif kind == 'admin-boundary':
        identity = 'admin'
        rules[1] = rule(path, method, 2, 4)
    elif kind == 'scope-boundary':
        identity = 'admin'
        rules[1] = rule(path, method, 0, 8)
    else:
        path = rng.choice((PATH_STATUS, PATH_DEMO))
        method = 1 if path == PATH_DEMO else rng.choice((1, 2, 3))
        identity = rng.choice(tuple(tokens))
        for j in range(3):
            rules[j] = rule(rng.choice((path, PATH_STATUS, PATH_DEMO, DEAD, 0)),
                            rng.choice((0, 1, 2, 3)), rng.choice((0, 1, 2)),
                            rng.choice((0, 1, 2, 4, 7, 8, 65535)))
    return kind, rules, path, method, identity


def oracle(rules, path, method, identity):
    _, role, scope, rate = tokens[identity]
    if rate >= 50:
        return 429
    permit = any(r['id'] == path and r['method'] == method and role >= r['min_role']
                 and (scope & r['scope']) == r['scope'] for r in rules)
    return 200 if permit else 403


fields = ('index', 'class', 'policy_sha256', 'rules_json', 'path_id', 'method_id',
          'identity', 'role', 'scope', 'rate_count', 'expected_status', 'actual_status',
          'audit_id', 'acceptances', 'effects', 'violations', 'match', 'error')
rows = 0
matches = 0
errors = 0
seen = set()
original = policy_read()
started = time.monotonic()
try:
    with (a.output / 'differential-requests.csv').open('w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for index in range(a.count):
            kind, rules, path_id, method_id, identity = make_case(index)
            token, role, scope, rate = tokens[identity]
            method = {1: 'GET', 2: 'POST', 3: 'PUT'}[method_id]
            path = '/demo' if path_id == PATH_DEMO else '/api/status'
            expected = oracle(rules, path_id, method_id, identity)
            row = dict.fromkeys(fields, '')
            row.update(index=index + 1, **{'class': kind},
                       policy_sha256=hashlib.sha256(encode(rules)).hexdigest(),
                       rules_json=json.dumps(rules, separators=(',', ':')),
                       path_id=path_id, method_id=method_id, identity=identity,
                       role=role, scope=scope, rate_count=rate, expected_status=expected)
            try:
                policy_write(rules)
                status, headers, _ = exchange(method, path, token,
                                               b'' if method != 'GET' else None)
                audit_id = int(headers['x-pg-audit-id'])
                accept = int(headers['x-pg-audit-accepts'])
                effect = int(headers['x-pg-audit-effects'])
                violations = int(headers['x-pg-audit-violations'])
                valid = (audit_id not in seen and status == expected and
                         accept == int(expected == 200) and
                         effect == int(expected == 200) and violations == 0)
                seen.add(audit_id)
                row.update(actual_status=status, audit_id=audit_id,
                           acceptances=accept, effects=effect,
                           violations=violations, match=int(valid))
                matches += int(valid)
            except (OSError, KeyError, ValueError, AssertionError) as exc:
                row['error'] = f'{type(exc).__name__}: {exc}'
                errors += 1
            writer.writerow(row)
            rows += 1
            if not int(row['match'] or 0):
                file.flush()
                raise SystemExit(f'Differential mismatch at case {index + 1}; see CSV')
            if rows % 1000 == 0:
                file.flush()
                print(f'M5 {rows} / {a.count}', flush=True)
finally:
    policy_write(original)
    assert policy_read() == original

summary = {'cases': rows, 'matched': matches, 'disagreements': rows - matches,
           'errors': errors, 'unique_audit_ids': len(seen), 'seed': a.seed,
           'policy_restored': True, 'elapsed_seconds': time.monotonic() - started,
           'limits': 'Adapted STM32 HTTP corpus. Does not cover synthetic rate 49/255 or authenticated role 0; audit counters are trusted C observations.'}
(a.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
