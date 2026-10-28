#!/usr/bin/env python3
"""Runtime-53 host driver (labelled variant GATEWAY_PAPER_RUNTIME53).

Loads the full OPNsense 19.1.7 policy (420 rules / 53 partitions) into the board
over HTTP through the verified PolicyBlob update gate, one partition per request
to the labelled /gate53 endpoint, then:
  - verifyload: the loaded store matches the intended policy;
  - negatives: operator update, out-of-range partition, oversized/malformed blob,
    rule count 0 and 9 are each rejected with the policy digest unchanged;
  - equiv: the 20,256 OPNsense oracle vectors decided on the board against the
    runtime-loaded store (chunked), require 20,256/20,256, 0 fail-closed;
  - e2e: a 200-request allow/deny HTTP sample over the 420 paths, each status
    checked against the oracle;
  - timing: DWT update cost (first/middle/last partition) and the n=53
    constructed-worst decision.

Policy and vectors come from the same generator as the on-board data
(gen_vectors.py --policy opnsense-19.1.7). HTTP only; nothing is sent over the
serial port. Writes results.json to --output."""
from pathlib import Path
import argparse, http.client, json, random, struct, subprocess, sys, time

AP = argparse.ArgumentParser()
AP.add_argument('--host', default='192.168.40.128')
AP.add_argument('--policy', default='opnsense-19.1.7')
AP.add_argument('--gen', default='/home/iamfo470/phd/paper-experiments/verified-combiner/test/gen_vectors.py')
AP.add_argument('--output', type=Path, required=True)
AP.add_argument('--admin', default='pg-lab-admin')
AP.add_argument('--operator', default='pg-lab-operator')
AP.add_argument('--equiv-chunk', type=int, default=1000)
AP.add_argument('--e2e', type=int, default=200)
AP.add_argument('--timeout', type=float, default=10.0)
A = AP.parse_args()
A.output.mkdir(parents=True, exist_ok=True)
SENT = 0xDEADDEAD


def gen():
    txt = subprocess.check_output(['python3', A.gen, '--policy', A.policy], text=True)
    lines = txt.split('\n')
    assert lines[0].startswith('P ')
    n = int(lines[0].split()[1])
    rules = [tuple(int(x) for x in l.split()) for l in lines[1:1 + 8 * n]]
    qs = [tuple(int(x) for x in l.split()[1:]) for l in lines[1 + 8 * n:] if l.startswith('Q ')]
    return n, rules, qs


def blob(rules8):
    """65-byte PolicyBlob body: num_rules(1) + 8 x (path LE32, mask, min_role, scope LE16).
    Inactive slots (sentinel path) carry min_role 0 so the verified validator (min_role<=2)
    accepts them; the gate ignores a sentinel slot's min_role."""
    b = bytearray([8])
    for (path, mask, min_role, scope) in rules8:
        mr = 0 if min_role > 2 else min_role
        b += struct.pack('<IBBH', path & 0xFFFFFFFF, mask & 0xFF, mr & 0xFF, scope & 0xFFFF)
    assert len(b) == 65, len(b)
    return bytes(b)


def req(method, path, body=None, token=None):
    c = http.client.HTTPConnection(A.host, 80, timeout=A.timeout)
    headers = {'Host': A.host, 'Connection': 'close'}
    if token is not None:
        headers['Authorization'] = 'Bearer ' + token
    if body is not None:
        headers['Content-Length'] = str(len(body))
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read()
    c.close()
    try:
        j = json.loads(data.decode('ascii', 'replace'))
    except Exception:
        j = None
    return r.status, j


def status_digest():
    s, j = req('GET', '/gate53?op=status')
    return j['digest'] if j else None


results = {'host': A.host, 'policy': A.policy, 'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}
n, rules, qs = gen()
results['partitions'] = n
results['rules'] = len(rules)
results['vectors'] = len(qs)
print(f'policy {A.policy}: n={n} rules={len(rules)} vectors={len(qs)}', flush=True)
partitions = [rules[8 * j:8 * j + 8] for j in range(n)]
blobs = [blob(p) for p in partitions]
fail = []

# 1. Load all 53 partitions.
t0 = time.time()
applied = 0
for j in range(n):
    s, jr = req('PUT', f'/gate53?op=update&p={j}', body=blobs[j], token=A.admin)
    ok = s == 200 and jr and jr.get('status') == 'ok'
    if not ok:
        fail.append(f'load partition {j}: status={s} {jr}')
    else:
        applied += 1
results['load'] = {'applied': applied, 'of': n, 'seconds': round(time.time() - t0, 2),
                   'digest_after_load': status_digest()}
loaded_digest = results['load']['digest_after_load']
print(f'loaded {applied}/{n} partitions, digest={loaded_digest}', flush=True)

# 2. verifyload: store equals the intended policy.
s, jr = req('GET', '/gate53?op=verifyload')
results['verifyload'] = {'status': s, **(jr or {})}
if not (s == 200 and jr and jr.get('mismatch') == 0):
    fail.append(f'verifyload mismatch: {s} {jr}')

# 3. Negatives, each with the digest unchanged.
neg = {}
def negative(name, method, path, body, token):
    before = status_digest()
    s, jr = req(method, path, body=body, token=token)
    after = status_digest()
    rejected = s != 200
    unchanged = before == after == loaded_digest
    neg[name] = {'status': s, 'json': jr, 'rejected': rejected, 'digest_unchanged': unchanged}
    if not (rejected and unchanged):
        fail.append(f'negative {name}: status={s} rejected={rejected} unchanged={unchanged} {jr}')

negative('operator_update', 'PUT', '/gate53?op=update&p=0', blobs[0], A.operator)
negative('out_of_range', 'PUT', f'/gate53?op=update&p={n}', blobs[0], A.admin)
negative('oversized_blob', 'PUT', '/gate53?op=update&p=0', bytes(100), A.admin)
mal = bytearray(blobs[0]); mal[1 + 5] = 9  # slot0 min_role = 9 (> 2): validator rejects
negative('malformed_blob', 'PUT', '/gate53?op=update&p=0', bytes(mal), A.admin)
c0 = bytearray(blobs[0]); c0[0] = 0
negative('rule_count_0', 'PUT', '/gate53?op=update&p=0', bytes(c0), A.admin)
c9 = bytearray(blobs[0]); c9[0] = 9
negative('rule_count_9', 'PUT', '/gate53?op=update&p=0', bytes(c9), A.admin)
results['negatives'] = neg

# 4. Equivalence sweep over all 20,256 oracle vectors (chunked).
t0 = time.time()
frm = 0
eq = None
while True:
    s, jr = req('GET', f'/gate53?op=equiv&from={frm}&count={A.equiv_chunk}')
    if s != 200 or not jr:
        fail.append(f'equiv chunk from={frm}: {s} {jr}')
        break
    eq = jr
    if jr.get('done'):
        break
    frm = jr['to']
results['equiv'] = {**(eq or {}), 'seconds': round(time.time() - t0, 2)}
if not (eq and eq.get('mismatches') == 0 and eq.get('fail_closed') == 0 and eq.get('vectors') == len(qs)):
    fail.append(f'equiv not clean: {eq}')
print(f'equiv: {results["equiv"]}', flush=True)

# 5. End-to-end HTTP sample over the 420 paths, status checked against the oracle.
rnd = random.Random(53)
sample = rnd.sample(range(len(qs)), min(A.e2e, len(qs)))
e2e_ok = 0
e2e_bad = []
for idx in sample:
    path, meth, role, scope, count, expected = qs[idx]
    s, jr = req('GET', f'/gate53?op=decide&path={path}&meth={meth}&role={role}&scope={scope}&count={count}')
    want_status = 200 if expected == 1 else 403
    want_dec = 1 if expected == 1 else 0
    dec = jr.get('decision') if jr else None
    if s == want_status and dec == want_dec:
        e2e_ok += 1
    else:
        e2e_bad.append({'vector': idx, 'path': path, 'status': s, 'want': want_status,
                        'decision': dec, 'expected': expected})
results['e2e'] = {'sent': len(sample), 'ok': e2e_ok, 'bad': e2e_bad[:10]}
if e2e_bad:
    fail.append(f'e2e mismatches: {len(e2e_bad)}/{len(sample)}')
print(f'e2e: {e2e_ok}/{len(sample)} match oracle', flush=True)

# 6. Timing (DWT, interrupts masked). Update cost first/middle/last partition
#    (re-applies the original blob, store unchanged), then the loaded-policy
#    decision (absent full-scan, last match), then the constructed worst (last,
#    overwrites the store).
timing = {}
for j in (0, n // 2, n - 1):
    # PUT: the request carries the 65-byte blob; a GET with a body is rejected.
    s, jr = req('PUT', f'/gate53?op=timing&which=update&p={j}', body=blobs[j], token=A.admin)
    timing[f'update_p{j}'] = jr
    if s != 200 or not jr:
        fail.append(f'timing update p={j}: {s} {jr}')
for case in ('absent', 'last'):
    s, jr = req('GET', f'/gate53?op=timing&which=decide&case={case}')
    timing[f'decide_{case}'] = jr
    if s != 200 or not jr:
        fail.append(f'timing decide {case}: {s} {jr}')
s, jr = req('GET', '/gate53?op=timing&which=worst')
timing['decide_worst_n53'] = jr
if s != 200 or not jr:
    fail.append(f'timing worst: {s} {jr}')
results['timing'] = timing
digest_after_update_timing = status_digest()
results['digest_after_update_timing'] = digest_after_update_timing
print('timing:', json.dumps(timing), flush=True)

results['pass'] = not fail
results['failures'] = fail
(A.output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
print(('PASS' if not fail else 'FAIL (%d)' % len(fail)) + ' -> ' + str(A.output / 'results.json'), flush=True)
for f in fail:
    print('  FAIL', f, flush=True)
sys.exit(0 if not fail else 1)
