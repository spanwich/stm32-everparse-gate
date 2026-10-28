#!/usr/bin/env python3
"""HTTP acceptance for the lab board. Policy writes are RAM-only and restored.
Requires the configured board on the local Ethernet link; never configures host IPs.
"""
import argparse, json, socket, struct, time, select
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('--host',default='192.168.40.128'); p.add_argument('--count',type=int,default=1000); p.add_argument('--output',type=Path,required=True)
a=p.parse_args(); a.output.mkdir(parents=True,exist_ok=True)
results=[]
def check(name,ok):
 results.append({'name':name,'passed':bool(ok)}); print(('PASS ' if ok else 'FAIL ')+name,flush=True)
 (a.output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
 if not ok: raise AssertionError(name)
def request(path='/api/status',token='pg-lab-operator',method='GET',body=b'',extra=b''):
 auth=b'' if token is None else b'Authorization: Bearer '+token.encode()+b'\r\n'
 cl=b'' if method=='GET' else b'Content-Length: '+str(len(body)).encode()+b'\r\n'
 return method.encode()+b' '+path.encode()+b' HTTP/1.1\r\nHost: board\r\n'+auth+cl+extra+b'\r\n'+body
def receive(s):
 data=b''
 while True:
  b=s.recv(4096)
  if not b: break
  data+=b
  if b'\r\n\r\n' in data:
   head,body=data.split(b'\r\n\r\n',1)
   lengths=re.findall(rb'(?im)^content-length:\s*([0-9]+)\r?$',head)
   if len(lengths)==1 and len(body)>=int(lengths[0]):break
  if len(data)>8192: raise AssertionError('Unbounded HTTP response')
 head,body=data.split(b'\r\n\r\n',1); lines=head.split(b'\r\n'); status=int(lines[0].split()[1])
 headers=dict(line.lower().split(b':',1) for line in lines[1:])
 assert int(headers[b'content-length'])==len(body), 'Incorrect Content-Length'
 assert headers[b'connection'].strip()==b'close'
 return status,headers,body
def exchange(data,split=None):
 with socket.create_connection((a.host,80),timeout=8) as s:
  if split is None:s.sendall(data)
  else:
   for i in range(0,len(data),split):s.sendall(data[i:i+split]);time.sleep(.001)
  return receive(s)
def policy(rules):
 return bytes([len(rules)])+b''.join(struct.pack('<IBBH',*r) for r in rules)+struct.pack('<IBBH',0xDEADDEAD,0,0,0)*(8-len(rules))
# Reference sentinel values, asserted by the source and exercised on the board.
PATH_STATUS=0x11111111
# Read exact constants from the maintained header, rather than invent hashes.
import re
shared=Path(__file__).resolve().parents[1]/'Shared/path_hashes.h'
text=shared.read_text()
def constant(name):return int(re.search(r'#define\s+'+name+r'\s+(0x[0-9A-Fa-f]+)',text)[1],16)
PATH_STATUS=constant('PATH_STATUS'); PATH_LOGOUT=constant('PATH_LOGOUT'); PATH_POLICY=constant('PATH_POLICY')
default=policy([(PATH_STATUS,1,1,1),(PATH_LOGOUT,2,1,0),(PATH_POLICY,1,2,4),(0x55555555,1,2,1)])
check('operator status and JSON',exchange(request())[0::2]==(200,b'{"status":"ok","role":"OPERATOR"}'))
for token,code in [(None,401),('bad',401),('pg-lab-operatorX',401),('PG-LAB-OPERATOR',401),('pg-lab-admin',200)]:
 r=exchange(request(token=token));check('identity '+str(token),r[0]==code and (code!=401 or b'www-authenticate' in r[1]))
check('operator denied policy read',exchange(request('/api/policy'))[0]==403)
check('admin policy read',exchange(request('/api/policy','pg-lab-admin'))[0]==200)
check('bytewise fragmentation',exchange(request(),split=1)[0]==200)
check('maximum binary body',exchange(request('/api/logout',method='POST',body=bytes(1361)),split=71)[0]==200)
prefix=request()[:-2]+b'X-Pad: '
full=prefix+b'A'*(4096-len(prefix)-4)+b'\r\n\r\n'
check('maximum complete 4096-byte request',exchange(full,split=512)[0]==200)
check('overlarge body',exchange(request('/api/logout',method='POST',body=bytes(1362)))[0]==413)
check('case and whitespace normalization',exchange(request().replace(b'Authorization: Bearer ',b'aUtHoRiZaTiOn:\t bEaReR   '))[0]==200)
for name,data,code in [
 ('duplicate auth',request(extra=b'authorization: Bearer pg-lab-admin\r\n'),400),
 ('duplicate length',request('/api/logout',method='POST',extra=b'content-length: 0\r\n'),400),
 ('transfer encoding',request(extra=b'Transfer-Encoding: chunked\r\n'),400),
 ('expect',request(extra=b'Expect: 100-continue\r\n'),417),
 ('folded header',request(extra=b' x: y\r\n'),400),
 ('pipeline never executes twice',request()+request(),400),
 ('long token',request(token='A'*129),401),
 ('unterminated maximum request',b'A'*4096,413)]:
 check(name,exchange(data)[0]==code)
# RAM update and transactional rollback through the real network path.
try:
 check('operator update denied',exchange(request('/api/policy',method='PUT',body=default))[0]==403)
 restricted=policy([(PATH_STATUS,1,2,4)])
 check('admin policy update',exchange(request('/api/policy','pg-lab-admin','PUT',restricted))[0]==200)
 check('updated policy denies operator',exchange(request())[0]==403)
 check('updated policy allows admin',exchange(request(token='pg-lab-admin'))[0]==200)
 check('malformed update denied',exchange(request('/api/policy','pg-lab-admin','PUT',restricted[:-1]))[0]==403)
 check('denied update preserves policy',exchange(request())[0]==403)
finally:
 check('restore default RAM policy',exchange(request('/api/policy','pg-lab-admin','PUT',default))[0]==200)
with socket.create_connection((a.host,80),timeout=8) as slow:
 slow.sendall(b'GET /api/status HTTP/1.1\r\n')
 start=time.monotonic();next_byte=start+0.8
 while True:
  if select.select([slow],[],[],.1)[0]:r=receive(slow);break
  if time.monotonic()>=next_byte:
   slow.sendall(b'x');next_byte+=.8
  if time.monotonic()-start>7:raise AssertionError('Trickle client defeated absolute deadline')
 elapsed=time.monotonic()-start
 check('absolute deadline despite trickle input',r[0]==408 and 4.5<=elapsed<=6)
with socket.create_connection((a.host,80),timeout=8) as first:
 first.sendall(b'GET /api/status HTTP/1.1\r\n')
 with socket.create_connection((a.host,80),timeout=8) as second:
  second.sendall(request()); first.close()
  check('queued connection survives active disconnect',receive(second)[0]==200)
for phase in ('receive','response'):
 with socket.create_connection((a.host,80),timeout=8) as s:
  s.sendall(request() if phase=='response' else b'GET /api/status HTTP/1.1\r\n')
  s.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
 deadline=time.monotonic()+3; recovered=False
 while time.monotonic()<deadline:
  try:
   recovered=exchange(request())[0]==200
   if recovered:break
  except OSError:pass
  time.sleep(.05)
 check('recover within 3s from reset during '+phase,recovered)
start=time.monotonic()
for i in range(a.count):
 token,code=[('pg-lab-operator',200),('bad',401),('pg-lab-admin',200)][i%3]
 r=exchange(request(token=token))
 if r[0]!=code:check('sequential request '+str(i),False)
 if (i+1)%100==0:print('Progress',i+1,flush=True)
check(str(a.count)+' sequential mixed requests',True)
(a.output/'summary.json').write_text(json.dumps({'passed':len(results),'requests_in_soak':a.count,'soak_seconds':time.monotonic()-start},indent=2)+'\n')
