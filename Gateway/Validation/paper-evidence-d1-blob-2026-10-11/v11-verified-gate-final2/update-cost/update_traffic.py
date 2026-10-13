#!/usr/bin/env python3
"""Policy-update traffic for the debugger cycle measurement. Restores the
initial policy at the end. mode: accept | operator | malformed."""
import http.client, json, struct, sys, time
mode, count = sys.argv[1], int(sys.argv[2])
host = '192.168.40.128'
def req(method, path, body=None, token=None):
    c = http.client.HTTPConnection(host, 80, timeout=20)
    h = {'Authorization': 'Bearer ' + token} if token else {}
    if body is not None: h['Content-Type'] = 'application/octet-stream'
    c.request(method, path, body=body, headers=h); r = c.getresponse(); d = r.read(); c.close()
    return r.status, d
def enc(rules):
    inactive = (0xDEADDEAD, 0, 0, 0)
    rules = rules + [inactive] * (8 - len(rules))
    return bytes([len([r for r in rules if r[0] != 0xDEADDEAD])]) + b''.join(struct.pack('<IBBH', *r) for r in rules)
A = [(0x33333333, 1, 1, 1), (0x22222222, 2, 1, 0), (0x44444444, 1, 2, 4)]
B = [(0x33333333, 1, 1, 1), (0x22222222, 2, 1, 0), (0x55555555, 1, 2, 1)]
s, d = req('GET', '/api/policy', token='pg-lab-admin'); assert s == 200, s
initial = json.loads(d)['rules']
init_bytes = enc([(r['id'], r['method'], r['min_role'], r['scope']) for r in initial])
statuses = []
try:
    time.sleep(3)
    for i in range(count):
        if mode == 'accept': s, _ = req('PUT', '/api/policy', enc(A if i % 2 else B), 'pg-lab-admin')
        elif mode == 'operator': s, _ = req('PUT', '/api/policy', enc(A), 'pg-lab-operator')
        else:
            body = bytearray(enc(A)); body[0] = 9      # count > 8: malformed blob
            s, _ = req('PUT', '/api/policy', bytes(body), 'pg-lab-admin')
        statuses.append(s)
finally:
    s, _ = req('PUT', '/api/policy', init_bytes, 'pg-lab-admin')
    s2, d = req('GET', '/api/policy', token='pg-lab-admin')
    print(json.dumps({'mode': mode, 'statuses': {str(k): statuses.count(k) for k in set(statuses)},
                      'restored': s == 200 and json.loads(d)['rules'] == initial}))
