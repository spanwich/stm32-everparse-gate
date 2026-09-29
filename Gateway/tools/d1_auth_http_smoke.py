#!/usr/bin/env python3
"""Exercise D1 AUTH LOGIN and IDENTIFY through the live board HTTP path."""
import http.client
import json
import argparse

p = argparse.ArgumentParser()
p.add_argument('--repeat', type=int, default=0)
args = p.parse_args()

host = '192.168.40.128'

def request(method, path, body=None, token=None):
    conn = http.client.HTTPConnection(host, 80, timeout=5)
    headers = {'Host': host}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    if token is not None:
        headers['Authorization'] = 'Bearer ' + token
    conn.request(method, path, body=body, headers=headers)
    reply = conn.getresponse()
    result = {'status': reply.status, 'body': reply.read().decode(errors='replace')}
    conn.close()
    return result

admin = request('POST', '/api/login', '{"username":"admin","password":"admin456"}')
assert admin['status'] == 200, admin
admin_token = json.loads(admin['body'])['token']
checks = {
    'admin_login': admin,
    'issued_admin_status': request('GET', '/api/status', token=admin_token),
    'fixture_admin_status': request('GET', '/api/status', token='pg-lab-admin'),
    'forged_token_status': request('GET', '/api/status', token=admin_token[:-1] +
                                   ('0' if admin_token[-1] != '0' else '1')),
    'bad_login': request('POST', '/api/login',
                         '{"username":"admin","password":"wrong"}'),
}
assert checks['issued_admin_status']['status'] == 200, checks
assert checks['fixture_admin_status']['status'] == 200, checks
assert checks['forged_token_status']['status'] == 401, checks
assert checks['bad_login']['status'] == 401, checks
for i in range(args.repeat):
    status = request('GET', '/api/status', token=admin_token)['status']
    assert status == 200, {'iteration': i, 'status': status}
checks['repeated_identify_count'] = args.repeat
print(json.dumps(checks, indent=2))
