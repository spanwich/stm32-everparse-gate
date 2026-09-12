#!/usr/bin/env python3
"""Dashboard/login acceptance on the lab board. Does not change RAM policy."""
import argparse, hashlib, hmac, http.client, json, time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--host',default='192.168.40.128');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=True); results=[]
def req(method,path,body=None,token=None):
    c=http.client.HTTPConnection(a.host,timeout=7)
    headers={'Content-Type':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    if isinstance(body,dict):body=json.dumps(body).encode()
    try:
        c.request(method,path,body=body,headers=headers);r=c.getresponse();data=r.read()
        assert len(data)==int(r.getheader('Content-Length'))
        return r.status,dict(r.getheaders()),data
    finally:c.close()
def check(name,ok):
    results.append({'name':name,'pass':bool(ok)})
    (a.output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    if not ok:raise AssertionError(name)
status,headers,html=req('GET','/')
expected=Path(__file__).resolve().parents[1]/'Web/dashboard.html'
check('Exact dashboard HTML served',status==200 and html==expected.read_bytes() and headers['Content-Type'].startswith('text/html'))
(a.output/'dashboard.html').write_bytes(html)
check('Dashboard no-store',headers.get('Cache-Control')=='no-store')
js_status,js_headers,js=req('GET','/dashboard.js')
check('Exact JavaScript asset served',js_status==200 and js==expected.with_suffix('.js').read_bytes() and js_headers['Content-Type'].startswith('application/javascript'))
check('Unauthenticated API rejected',req('GET','/api/status')[0]==401)
tokens={}
for user,password,role,scope in [('admin','admin456',2,0x3f),('operator','oper789',1,3)]:
    status,headers,data=req('POST','/api/login',{'username':user,'password':password})
    check(user+' login',status==200)
    token=json.loads(data)['token'];tokens[user]=token
    # Independent Python HMAC oracle for the original lab protocol, '-' encoding.
    key=bytes.fromhex('deadbeefcafebabe0102030405060708f0e1d2c3b4a5968778695a4b3c2d1e0f')
    claims=user.encode()+bytes([role])+scope.to_bytes(2,'little')
    oracle='-'.join([user.encode().hex(),bytes([role]).hex(),scope.to_bytes(2,'little').hex(),hmac.new(key,claims,hashlib.sha256).hexdigest()])
    check(user+' token matches independent HMAC oracle',token==oracle)
    check(user+' status',req('GET','/api/status',token=token)[0]==200)
    check(user+' policy permissions',req('GET','/api/policy',token=token)[0]==(200 if user=='admin' else 403))
    check(user+' logout',req('POST','/api/logout',{},token)[0]==200)
    check(user+' original stateless logout semantics',req('GET','/api/status',token=token)[0]==200)
check('Wrong password',req('POST','/api/login',{'username':'admin','password':'bad'})[0]==401)
check('Unknown account',req('POST','/api/login',{'username':'unknown','password':'admin456'})[0]==401)
for length in [64,65,255,256,257]:
    check('Password length '+str(length),req('POST','/api/login',{'username':'admin','password':'x'*length})[0]==(401 if length==64 else 400))
for body in [b'{',b'{"username":"admin","password":"admin456"} trailing',b'{"username":"admin","username":"admin"}',b'{"username":"admin","password":"\\u0000"}']:
    check('Malformed JSON '+str(len(body)),req('POST','/api/login',body)[0]==400)
token=tokens['admin'];bad=token[:-1]+('1' if token[-1]=='0' else '0')
check('Tampered signature rejected',req('GET','/api/status',token=bad)[0]==401)
check('Old colon format rejected',req('GET','/api/status',token=token.replace('-',':'))[0]==400)
start=time.monotonic()
for i in range(100):
    check('Authenticated request '+str(i),req('GET','/api/status',token=tokens['operator'])[0]==200)
summary={'passed':len(results),'total':len(results),'authenticated_100_seconds':time.monotonic()-start,'html_sha256':hashlib.sha256(html).hexdigest()}
(a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
