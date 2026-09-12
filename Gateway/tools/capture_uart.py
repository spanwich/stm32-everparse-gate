#!/usr/bin/env python3
"""Read-only UART capture; configures serial framing but never transmits bytes."""
import argparse,os,select,termios,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--seconds',type=float,default=60);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.output.parent.mkdir(parents=True,exist_ok=True)
fd=os.open('/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02',os.O_RDONLY|os.O_NONBLOCK|os.O_NOCTTY)
t=termios.tcgetattr(fd);t[0]=t[1]=t[3]=0;t[2]=termios.CS8|termios.CREAD|termios.CLOCAL;t[4]=t[5]=termios.B115200;t[6][termios.VMIN]=0;t[6][termios.VTIME]=0;termios.tcsetattr(fd,termios.TCSANOW,t);termios.tcflush(fd,termios.TCIFLUSH)
try:
 with a.output.open('wb') as f:
  end=time.monotonic()+a.seconds
  while time.monotonic()<end:
   if select.select([fd],[],[],.2)[0]:
    try:b=os.read(fd,4096)
    except BlockingIOError:continue
    f.write(b);f.flush()
finally:os.close(fd)
print('UART capture:',a.output)
