#!/usr/bin/env python3
"""Flash/reset one R4 timer image and retain exact jitter samples and UART."""
from pathlib import Path
import argparse
import csv
import hashlib
import http.client
import json
import os
import re
import select
import socket
import statistics
import struct
import subprocess
import termios
import threading
import time

p=argparse.ArgumentParser()
p.add_argument('--elf',type=Path,required=True)
p.add_argument('--flash',action='store_true')
p.add_argument('--scenario',choices=('idle','valid','denied','malformed'),required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--max-seconds',type=int,default=35)
p.add_argument('--d1',action='store_true',help='install D1 demo policy before valid load')
a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=True)
elf=a.elf.resolve(); digest=hashlib.sha256(elf.read_bytes()).hexdigest()
if a.flash:
    manifest=json.loads((elf.parent/'source-manifest.json').read_text())
    assert manifest['elf_sha256']==digest
serial='/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02'
if subprocess.run(['fuser','-s','/dev/ttyACM1'],stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL).returncode==0:
    raise SystemExit('serial reader already open')
fd=os.open(serial,os.O_RDONLY|os.O_NONBLOCK|os.O_NOCTTY)
attrs=termios.tcgetattr(fd);attrs[0]=attrs[1]=attrs[3]=0
attrs[2]=termios.CS8|termios.CREAD|termios.CLOCAL
attrs[4]=attrs[5]=termios.B115200
attrs[6][termios.VMIN]=attrs[6][termios.VTIME]=0
termios.tcsetattr(fd,termios.TCSANOW,attrs);termios.tcflush(fd,termios.TCIFLUSH)
ready=threading.Event();measurement_started=threading.Event();measurement_done=threading.Event();complete=threading.Event();stop=threading.Event()
window_start=[None];window_end=[None]
raw=bytearray()
def reader():
    with (a.output/'uart.bin').open('wb') as output:
        while not stop.is_set():
            if select.select([fd],[],[],0.1)[0]:
                try: chunk=os.read(fd,8192)
                except BlockingIOError: continue
                if not chunk: continue
                raw.extend(chunk);output.write(chunk);output.flush()
                if b'[HTTP] READY' in raw and b'[ETH] link=UP' in raw: ready.set()
                if b'[CTRL R4] START' in raw and not measurement_started.is_set():
                    window_start[0]=time.monotonic();measurement_started.set()
                pos=raw.find(b'[CTRL R4] hz=')
                if pos>=0 and not measurement_done.is_set():
                    window_end[0]=time.monotonic()
                    measurement_done.set()
                if pos>=0:
                    block=raw.find(b'PGC1',pos)
                    if block>=0 and len(raw)>=block+40008: complete.set()
thread=threading.Thread(target=reader);thread.start()
cli='/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.linux64_2.2.300.202508131133/tools/bin/STM32_Programmer_CLI'
requests=[]
try:
    command=[cli,'-c','port=SWD','sn=066FFF555567894967085545','mode=UR','freq=1000']
    if a.flash: command+=['-d',str(elf),'-v']
    command+=['-rst','-run']
    proc=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90)
    (a.output/'programmer.log').write_bytes(proc.stdout)
    assert proc.returncode==0 and (not a.flash or b'Download verified successfully' in proc.stdout)
    assert ready.wait(35),'HTTP listener did not start'
    if a.d1 and a.scenario=='valid':
        def control_request(method,path,body=None,token=None):
            connection=http.client.HTTPConnection('192.168.40.128',80,timeout=5)
            headers={'Authorization':'Bearer '+token} if token else {}
            connection.request(method,path,body=body,headers=headers)
            response=connection.getresponse()
            status,payload=response.status,response.read()
            connection.close()
            return status,payload
        status,body=control_request('POST','/api/login',
                                    b'{"username":"admin","password":"admin456"}')
        assert status==200,(status,body)
        token=json.loads(body)['token']
        rules=((0x33333333,1,1,1),(0x22222222,2,1,0),
               (0x44444444,1,2,4),(0x55555555,1,2,1))
        policy=bytes([len(rules)])+b''.join(struct.pack('<IBBH',*rule)
                                            for rule in rules)+bytes(8*(8-len(rules)))
        status,_=control_request('PUT','/api/policy',policy,token)
        assert status==200,status
    cases={
        'valid':(b'GET /api/status HTTP/1.1\r\nHost: board\r\nAuthorization: Bearer pg-lab-operator\r\n\r\n',200),
        'denied':(b'GET /api/status HTTP/1.1\r\nHost: board\r\n\r\n',401),
        'malformed':(b'GET /api/status HTTP/1.1\r\nHost: board\r\nAuthorization: Bearer pg-lab-operator\r\nAuthorization: Bearer pg-lab-admin\r\n\r\n',400),
    }
    start=time.monotonic()
    while not measurement_done.is_set() and time.monotonic()-start<a.max_seconds:
        if a.scenario=='idle':
            time.sleep(0.05);continue
        payload,expected=cases[a.scenario]
        now=time.monotonic();actual=0;error=''
        try:
            with socket.create_connection(('192.168.40.128',80),timeout=4) as conn:
                conn.settimeout(4);conn.sendall(payload);data=bytearray()
                while len(data)<16384:
                    part=conn.recv(4096)
                    if not part: break
                    data.extend(part)
                    if b'\r\n\r\n' in data:
                        head,body=data.split(b'\r\n\r\n',1)
                        lengths=re.findall(rb'(?im)^content-length:\s*([0-9]+)\r?$',head)
                        if len(lengths)==1 and len(body)>=int(lengths[0]):break
                actual=int(data.split(b'\r\n',1)[0].split()[1])
        except (OSError,ValueError,IndexError) as exc:
            error=type(exc).__name__+': '+str(exc)
        requests.append((len(requests),time.monotonic()-start,expected,actual,
                         (time.monotonic()-now)*1000,error))
    assert complete.wait(10),'R4 binary control record missing'
    deadline=time.monotonic()+5
    while b'[RUNTIME R4] end' not in raw and time.monotonic()<deadline:
        time.sleep(0.02)
    assert b'[RUNTIME R4] end' in raw,'R4 runtime counter record missing'
finally:
    stop.set();thread.join();os.close(fd)

with (a.output/'requests.csv').open('w',newline='') as file:
    writer=csv.writer(file);writer.writerow(('index','seconds','expected','actual','latency_ms','error'))
    writer.writerows(requests)
data=bytes(raw)
if a.d1:
    assert data.count(b'[BOOT] policy_gate') == 1, 'board reset during D1 timing capture'
    assert data.find(b'[HTTP] READY') < data.find(b'[CTRL R4] START'), \
        'D1 timer started before the HTTP listener was ready'
assert b'[CORE SELFTEST] PASS 353/353' in data
text=data.decode(errors='replace')
match=re.search(r'\[CTRL R4\] hz=(\d+) high=(\d+) samples=(\d+) misses=(\d+)(?: lost_releases=(\d+) gap_anomalies=(\d+))? max_cycles=(\d+) critical_max_cycles=(\d+)(?: critical_anomalies=(\d+))?(?: isr_max_cycles=(\d+))?(?: eth_isr_max_cycles=(\d+) eth_isr_count=(\d+))? stack_free=(\d+)',text)
assert match,'control summary missing'
hz,high,count,misses,lost_releases,gap_anomalies,max_cycles,critical_max,critical_anomalies,isr_max,eth_isr_max,eth_isr_count,stack_free=(
    int(value or 0) for value in match.groups())
assert count==10000
marker=data.find(b'PGC1',data.find(b'[CTRL R4]'))
assert marker>=0 and data[marker+4:marker+8]==struct.pack('<HBB',hz,high,0)
values=struct.unpack_from('<10000I',data,marker+8)
with (a.output/'jitter-cycles.csv').open('w',newline='') as file:
    writer=csv.writer(file);writer.writerow(('sample','release_to_run_cycles'))
    writer.writerows(enumerate(values))
clock=re.search(rb'\[BOOT\] SYSCLK=(\d+)',data)
assert clock
clock_hz=int(clock[1]);period=clock_hz//hz
ordered=sorted(values)
summary={'elf_sha256':digest,'scenario':a.scenario,'clock_hz':clock_hz,
         'control_hz':hz,'control_above_gate':bool(high),
         'samples':count,'misses':misses,'misses_recomputed':sum(v>=period for v in values),
         'lost_releases':lost_releases,'total_misses':misses+lost_releases,
         'gap_anomalies':gap_anomalies,
         'min_cycles':ordered[0],'median_cycles':statistics.median(ordered),
         'p99_cycles':ordered[9899],'p999_cycles':ordered[9989],
         'max_cycles':ordered[-1],'board_max_cycles':max_cycles,
         'stack_free_bytes':stack_free,'requests':len(requests),
         'critical_max_cycles':critical_max,
         'critical_anomalies':critical_anomalies,
         'isr_max_cycles':isr_max,
         'eth_isr_max_cycles':eth_isr_max,
         'eth_isr_count':eth_isr_count,
         'status_mismatches':sum(row[2]!=row[3] for row in requests),
         'transport_errors':sum(bool(row[5]) for row in requests),
         'load_duration_seconds':requests[-1][1] if requests else 0,
         'requests_during_sample_window':sum(window_start[0]<=start+row[1]<window_end[0]
                                             for row in requests) if window_start[0] is not None and window_end[0] is not None else 0,
         'observed_window_seconds':window_end[0]-window_start[0]
             if window_start[0] is not None and window_end[0] is not None else None,
         'window_start_offset_seconds':window_start[0]-start if window_start[0] is not None else None,
         'window_end_offset_seconds':window_end[0]-start if window_end[0] is not None else None,
         'uart_sha256':hashlib.sha256(data).hexdigest(),
         'samples_sha256':hashlib.sha256((a.output/'jitter-cycles.csv').read_bytes()).hexdigest()}
runtime_total=re.search(r'\[RUNTIME R4\] total_cycles=(\d+) tasks=(\d+)',text)
assert runtime_total
summary['runtime_total_cycles']=int(runtime_total[1])
summary['runtime_tasks']={name:int(cycles) for name,cycles in re.findall(
    r'\[RUNTIME R4\] task=(.+?) cycles=(\d+)',text)}
summary['runtime_task_sum_cycles']=sum(summary['runtime_tasks'].values())
summary['runtime_task_share_percent']={name:round(100*cycles/summary['runtime_task_sum_cycles'],3)
    for name,cycles in summary['runtime_tasks'].items()} if summary['runtime_task_sum_cycles'] else {}
window_rows=[row for row in requests if window_start[0] is not None and
             window_end[0] is not None and window_start[0]<=start+row[1]<window_end[0]]
summary['window_status_mismatches']=sum(row[2]!=row[3] for row in window_rows)
summary['window_transport_errors']=sum(bool(row[5]) for row in window_rows)
assert summary['misses']==summary['misses_recomputed']
assert summary['max_cycles']==summary['board_max_cycles']
summary['achieved_request_rate_hz']=summary['requests_during_sample_window']/((count+lost_releases)/hz)
if a.d1 and a.scenario != 'idle':
    assert summary['requests_during_sample_window'] > 0, \
        'D1 loaded window contained no completed HTTP requests'
(a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({key:summary[key] for key in ('scenario','clock_hz','control_hz',
    'control_above_gate','misses','p99_cycles','max_cycles',
    'requests_during_sample_window','achieved_request_rate_hz',
    'window_status_mismatches','window_transport_errors')},sort_keys=True),flush=True)
