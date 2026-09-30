#!/usr/bin/env python3
"""Check restrictive fresh boot, install the demo policy as admin, run a suite,
then restore the restrictive policy. The called regression suite is unchanged."""
import argparse
import http.client
import json
import struct
import subprocess
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--output',type=Path,required=True)
p.add_argument('suite',nargs=argparse.REMAINDER)
a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=True)
host='192.168.40.128'

def request(method,path,body=None,token=None):
    conn=http.client.HTTPConnection(host,80,timeout=8)
    headers={}
    if token: headers['Authorization']='Bearer '+token
    if body is not None: headers['Content-Type']='application/octet-stream'
    conn.request(method,path,body=body,headers=headers)
    response=conn.getresponse()
    status,data=response.status,response.read()
    conn.close()
    return status,data

def encode(rules):
    assert 1<=len(rules)<=8
    return bytes([len(rules)])+b''.join(struct.pack('<IBBH',
        r['id'],r['method'],r['min_role'],r['scope']) for r in rules)+bytes(8*(8-len(rules)))

admin_status,admin_body=request('POST','/api/login',
    b'{"username":"admin","password":"admin456"}')
assert admin_status==200,(admin_status,admin_body)
admin=json.loads(admin_body)['token']
operator_status,_=request('GET','/api/status',token='pg-lab-operator')
assert operator_status in (403,404),(operator_status,'fresh boot must deny operator status')
read_status,read_body=request('GET','/api/policy',token=admin)
assert read_status==200,(read_status,read_body)
initial=json.loads(read_body)['rules']
assert len(initial)==3 and {r['id'] for r in initial}=={0x22222222,0x44444444},initial
demo=[
    {'id':0x33333333,'method':1,'min_role':1,'scope':1},
    {'id':0x22222222,'method':2,'min_role':1,'scope':0},
    {'id':0x44444444,'method':1,'min_role':2,'scope':4},
    {'id':0x55555555,'method':1,'min_role':2,'scope':1},
]
install_status,_=request('PUT','/api/policy',encode(demo),admin)
assert install_status==200,install_status
status_after_install,_=request('GET','/api/status',token='pg-lab-operator')
assert status_after_install==200,status_after_install
record={'fresh_boot_operator_status':operator_status,'fresh_boot_policy':initial,
        'admin_login_status':admin_status,'admin_install_status':install_status,
        'operator_status_after_install':status_after_install,'suite':a.suite}
try:
    if a.suite:
        cmd=a.suite[1:] if a.suite[0]=='--' else a.suite
        done=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        (a.output/'suite.log').write_bytes(done.stdout)
        print(done.stdout.decode(errors='replace'),end='')
        record['suite_exit_code']=done.returncode
        if done.returncode: raise SystemExit(done.returncode)
finally:
    restore_status,_=request('PUT','/api/policy',encode(initial),admin)
    assert restore_status==200,restore_status
    read_status,read_body=request('GET','/api/policy',token=admin)
    assert read_status==200 and json.loads(read_body)['rules']==initial
    final_status,_=request('GET','/api/status',token='pg-lab-operator')
    assert final_status in (403,404),final_status
    record['restored_operator_status']=final_status
    (a.output/'policy-transitions.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))

