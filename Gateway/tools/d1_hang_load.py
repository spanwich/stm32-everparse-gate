#!/usr/bin/env python3
"""Reset-tolerant HTTP load for reproducing the D1 NET hang.

Mirrors the M4 mix (public asset, login, allowed/denied queries, admin policy
reads, alternating policy updates, occasional overlapping pairs) but records
each request's client source port and continues after transport errors, so a
run is not cut short by one reset. For every reset it records when the same
client port was last used, to test the TIME_WAIT port-reuse explanation.
Stops after --count requests or after --dead consecutive transport failures.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import argparse, csv, json, socket, struct, time

p = argparse.ArgumentParser()
p.add_argument('--host', default='192.168.40.128')
p.add_argument('--count', type=int, default=200000)
p.add_argument('--dead', type=int, default=200)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=True)
admin, operator = 'pg-lab-admin', 'pg-lab-operator'


def encode(rules):
    inactive = (0xDEADDEAD, 0, 0, 0)
    rows = rules + [inactive] * (8 - len(rules))
    return bytes([len(rules)]) + b''.join(struct.pack('<IBBH', *r) for r in rows)


STATUS, POLICY = 0x22222222, 0x44444444
policy_a = encode([(STATUS, 1, 1, 0), (POLICY, 1, 2, 4), (POLICY, 4, 2, 4)])
policy_b = encode([(STATUS, 1, 2, 0), (POLICY, 1, 2, 4), (POLICY, 4, 2, 4)])


def exchange(method, path, token=None, body=None):
    s = socket.create_connection((a.host, 80), timeout=8)
    port = s.getsockname()[1]
    try:
        head = f'{method} {path} HTTP/1.1\r\nHost: {a.host}\r\n'
        if token:
            head += f'Authorization: Bearer {token}\r\n'
        if body is not None:
            head += f'Content-Type: application/octet-stream\r\nContent-Length: {len(body)}\r\n'
        s.sendall(head.encode() + b'\r\n' + (body or b''))
        data = b''
        while b'\r\n\r\n' not in data:
            part = s.recv(4096)
            if not part:
                break
            data += part
        header, _, body_part = data.partition(b'\r\n\r\n')
        length = 0
        for line in header.split(b'\r\n')[1:]:
            name, _, value = line.partition(b':')
            if name.strip().lower() == b'content-length':
                length = int(value.strip())
        while len(body_part) < length:   # read the whole response before closing
            part = s.recv(4096)
            if not part:
                break
            body_part += part
        status = int(data.split(b' ', 2)[1]) if data.startswith(b'HTTP/') else 0
        return port, status, ''
    except OSError as e:
        return port, None, type(e).__name__
    finally:
        s.close()


CASES = [('public-asset', 'GET', '/', None, None),
         ('login', 'POST', '/api/login', None, b'{"username":"operator","password":"operator123"}'),
         ('query-allowed', 'GET', '/api/status', operator, None),
         ('query-denied', 'GET', '/api/policy', operator, None),
         ('admin-read', 'GET', '/api/policy', admin, None)]
port_last = {}
fields = ['index', 'class', 'port', 'status', 'error', 't', 'port_last_seen_s']
out = (a.output / 'requests.csv').open('w', newline='')
w = csv.writer(out)
w.writerow(fields)
totals = {'requests': 0, 'errors': 0}
start = time.time()
dead = 0
index = 0
active = policy_a
with ThreadPoolExecutor(max_workers=2) as pool:
    while index < a.count and dead < a.dead:
        batch = []
        if index % 100 == 50:
            active = policy_b if active == policy_a else policy_a
            batch.append(('policy-update', 'PUT', '/api/policy', admin, active))
        batch.append(CASES[index % len(CASES)])
        if index % 10 == 5:
            batch.append(CASES[(index + 2) % len(CASES)])   # overlapping pair
        futures = [(c, pool.submit(exchange, c[1], c[2], c[3], c[4])) for c in batch]
        for case, fut in futures:
            port, status, error = fut.result()
            now = time.time() - start
            last = port_last.get(port)
            port_last[port] = now
            w.writerow([index, case[0], port, status, error, f'{now:.3f}',
                        f'{now - last:.1f}' if last is not None else ''])
            totals['requests'] += 1
            if error:
                totals['errors'] += 1
                dead += 1
            else:
                dead = 0
            index += 1
        if index % 1000 < len(batch):
            out.flush()
            print(f'load {index} errors={totals["errors"]}', flush=True)
out.close()
totals.update(elapsed_s=round(time.time() - start, 1), stopped_dead=dead >= a.dead)
(a.output / 'summary.json').write_text(json.dumps(totals, indent=2) + '\n')
print(json.dumps(totals))
