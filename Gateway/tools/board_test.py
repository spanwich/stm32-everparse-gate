#!/usr/bin/env python3
"""Explicit deployment + fresh-boot UART acceptance. Requires --flash or --reset.
Only the named Nucleo probe is used. No host networking configuration is changed.
"""
from pathlib import Path
import argparse, hashlib, os, re, select, shutil, subprocess, termios, threading, time
p=argparse.ArgumentParser()
p.add_argument('--config',choices=['Debug','Release'],default='Debug')
a=p.add_mutually_exclusive_group(required=True); a.add_argument('--flash',action='store_true'); a.add_argument('--reset',action='store_true')
p.add_argument('--output',type=Path,required=True)
p.add_argument('--seconds',type=float,default=25)
p.add_argument('--expected-selftests',type=int)
args=p.parse_args(); root=Path(__file__).resolve().parents[2]; out=args.output.resolve(); out.mkdir(parents=True,exist_ok=True)
cli='/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.linux64_2.2.300.202508131133/tools/bin/STM32_Programmer_CLI'
elf=root/args.config/'policy_gate.elf'
if args.flash:
 subprocess.run(['python3',str(root/'Gateway/tools/check_firmware.py'),str(elf)],check=True)
 staged=out/'policy_gate.elf';shutil.copy2(elf,staged);elf=staged
image_hash=hashlib.sha256(elf.read_bytes()).hexdigest()
serial='/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02'
if subprocess.run(['fuser','-s','/dev/ttyACM1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:
 raise SystemExit('/dev/ttyACM1 is already open; close minicom or other serial readers before resetting the board')
fd=os.open(serial,os.O_RDONLY|os.O_NONBLOCK|os.O_NOCTTY)
attr=termios.tcgetattr(fd); attr[0]=attr[1]=attr[3]=0; attr[2]=termios.CS8|termios.CREAD|termios.CLOCAL
attr[4]=attr[5]=termios.B115200; attr[6][termios.VMIN]=0; attr[6][termios.VTIME]=0
termios.tcsetattr(fd,termios.TCSANOW,attr); termios.tcflush(fd,termios.TCIFLUSH)
chunks=[]; stop=threading.Event()
def read():
 while not stop.is_set():
  if select.select([fd],[],[],0.1)[0]:
   try: chunks.append(os.read(fd,4096))
   except BlockingIOError: pass
thread=threading.Thread(target=read); thread.start()
try:
 cmd=[cli,'-c','port=SWD','sn=066FFF555567894967085545','mode=UR','freq=1000']
 if args.flash: cmd += ['-d',str(elf),'-v']
 cmd += ['-rst','-run']
 proc=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=90)
 log=re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',proc.stdout)
 (out/'programmer.log').write_text(log); print(log,flush=True)
 if proc.returncode: raise SystemExit(proc.returncode)
 deadline=time.monotonic()+args.seconds
 while time.monotonic()<deadline: time.sleep(0.2)
finally:
 stop.set(); thread.join(); os.close(fd)
 raw=b''.join(chunks).decode(errors='replace').replace('\r\n','\n')
 (out/'uart-raw.log').write_text(raw)
 start=raw.rfind('[BOOT] policy_gate'); log=raw[start:] if start>=0 else ''
 (out/'uart.log').write_text(log)
 print('\n'.join(s for s in log.splitlines() if any(k in s for k in ('[BOOT]','[CORE SELFTEST]','[HTTP]','[ETH]','[NET]','FAIL'))),flush=True)
 (out/('elf.sha256' if args.flash else 'workspace-elf-unverified.sha256')).write_text(image_hash+'\n')
m=re.search(r'\[CORE SELFTEST\] PASS (\d+)/(\d+)',log)
assert m and int(m[1])>=193 and m[1]==m[2], 'Fresh core test acceptance missing'
if args.expected_selftests is not None:
 assert int(m[1])==args.expected_selftests, 'Self-test count differs from the pinned image expectation'
assert '[HTTP] READY' in log, 'Listener startup missing'
assert len(re.findall(r'\[HEARTBEAT\] PASS',log))>=5, 'Insufficient heartbeats'
assert 'margin=LOW' not in log and re.search(r'log_drops=[1-9]',log) is None, 'Stack/log acceptance failed'
print('Fresh boot and UART acceptance PASS; network reachability tested separately')
