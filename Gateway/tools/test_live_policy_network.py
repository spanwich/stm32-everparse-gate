#!/usr/bin/env python3
"""Live policy acceptance; snapshots and restores the initial policy in finally."""
import argparse, http.client, json, struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--host',default='192.168.40.128');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=True);results=[]
def req(method,path,token=None,body=None):
    headers={}
    if token:headers['Authorization']='Bearer '+token
    if isinstance(body,dict):body=json.dumps(body).encode();headers['Content-Type']='application/json'
    c=http.client.HTTPConnection(a.host,timeout=7)
    try:
        c.request(method,path,body=body,headers=headers);r=c.getresponse();data=r.read()
        assert len(data)==int(r.getheader('Content-Length'))
        return r.status,dict(r.getheaders()),data
    finally:c.close()
def check(name,ok):
    results.append({'name':name,'pass':bool(ok)})
    (a.output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    assert ok,name
    print('PASS',name)
def login(user,password):
    r=req('POST','/api/login',body={'username':user,'password':password});assert r[0]==200
    return json.loads(r[2])['token']
def encode(rules):
    return bytes([len(rules)])+b''.join(struct.pack('<IBBH',r['id'],r['method'],r['min_role'],r['scope']) for r in rules)+bytes(8*(8-len(rules)))
def read():
    r=req('GET','/api/policy',admin);assert r[0]==200;return json.loads(r[2])['rules']
def edited(rules,path,allow):
    return [r for r in rules if not(r['id']==path and r['method']==1)]+[{'id':path,'method':1,'min_role':1 if allow else 2,'scope':1}]
admin=login('admin','admin456');operator=login('operator','oper789');original=read();demo=0x55555555;status=0x33333333
try:
    for file,path,media in [('dashboard.html','/','text/html'),('dashboard.js','/dashboard.js','application/javascript')]:
        r=req('GET',path);expected=(Path(__file__).resolve().parents[1]/'Web'/file).read_bytes()
        check('Static asset '+path,r[0]==200 and r[2]==expected and r[1]['Content-Type'].startswith(media))
    check('Script exercises response larger than request buffer',len(expected)>4096)
    check('Missing token cannot read demo',req('GET','/demo')[0]==401)
    check('Operator cannot read policy',req('GET','/api/policy',operator)[0]==403)
    desired=edited(original,demo,True)
    check('Operator cannot write policy',req('PUT','/api/policy',operator,encode(desired))[0]==403)
    check('Rejected operator write leaves policy unchanged',read()==original)
    for allow in [True,False,True,False]:
        before=read();desired=edited(before,demo,allow)
        check('Admin demo toggle '+str(allow),req('PUT','/api/policy',admin,encode(desired))[0]==200)
        check('Readback matches edit',read()==desired)
        r=req('GET','/demo',operator)
        check('Operator demo reflects live edit '+str(allow),r[0]==(200 if allow else 403))
        if allow:check('Demo is plain text',r[1]['Content-Type'].startswith('text/plain') and r[2]==b'Policy gate demo: access allowed.\n')
        check('Admin retains demo access',req('GET','/demo',admin)[0]==200)
        check('Status unaffected by demo edit',req('GET','/api/status',operator)[0]==200)
    before=read();desired=edited(before,status,False)
    check('Admin disables operator status',req('PUT','/api/policy',admin,encode(desired))[0]==200)
    check('Operator status denied live',req('GET','/api/status',operator)[0]==403)
    check('Admin status still allowed',req('GET','/api/status',admin)[0]==200)
    check('Admin management still usable',req('GET','/api/policy',admin)[0]==200)
    # Even a custom policy rule cannot grant operator access to the admin PUT operation.
    attack=[{'id':0x44444444,'method':3,'min_role':1,'scope':0}]+desired
    check('Admin can upload custom test rule',req('PUT','/api/policy',admin,encode(attack))[0]==200)
    check('Operator update still forbidden with permissive rule',req('PUT','/api/policy',operator,encode(original))[0]==403)
    check('Rejected update preserves custom policy',read()==attack)
    for path in ['/demo/','/demo?x=1','/Demo','/demo%00','/dashboard.js/']:
        check('No route alias bypass '+path,req('GET',path,operator)[0]==400)
    check('Demo POST rejected',req('POST','/demo',admin,b'{}')[0]==400)
finally:
    restored=req('PUT','/api/policy',admin,encode(original))
    assert restored[0]==200,'Failed to restore initial policy'
check('Initial policy restored',read()==original)
(a.output/'summary.json').write_text(json.dumps({'passed':len(results),'total':len(results),'initial_policy_restored':True},indent=2)+'\n')
print('Live policy acceptance PASS',len(results))
