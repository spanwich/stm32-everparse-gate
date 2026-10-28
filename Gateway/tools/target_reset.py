#!/usr/bin/env python3
"""Send a target-reset command over the ST-LINK VCP and wait for the [TRESET] reply.

RESET pulses PA3 (TGT_NRST, the Nucleo "A0" header pin, open-drain) low for 100 ms; STATUS reports the line.
Use only one serial reader: stop capture_uart.py or any terminal first.
"""
import argparse,os,select,sys,termios,time
p=argparse.ArgumentParser();p.add_argument('command',nargs='?',default='RESET',choices=('RESET','STATUS'));p.add_argument('--timeout',type=float,default=2);a=p.parse_args()
fd=os.open('/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02',os.O_RDWR|os.O_NONBLOCK|os.O_NOCTTY)
t=termios.tcgetattr(fd);t[0]=t[1]=t[3]=0;t[2]=termios.CS8|termios.CREAD|termios.CLOCAL;t[4]=t[5]=termios.B115200;t[6][termios.VMIN]=0;t[6][termios.VTIME]=0;termios.tcsetattr(fd,termios.TCSANOW,t);termios.tcflush(fd,termios.TCIOFLUSH)
try:
 os.write(fd,(a.command+'\n').encode());buf=b'';end=time.monotonic()+a.timeout
 while time.monotonic()<end:
  if select.select([fd],[],[],.1)[0]:
   try:buf+=os.read(fd,4096)
   except BlockingIOError:continue
   for line in buf.split(b'\n'):
    if line.startswith(b'[TRESET]'):print(line.decode(errors='replace').strip());sys.exit(0 if b'pulse' in line or a.command=='STATUS' else 1)
finally:os.close(fd)
print('no [TRESET] reply',file=sys.stderr);sys.exit(2)
