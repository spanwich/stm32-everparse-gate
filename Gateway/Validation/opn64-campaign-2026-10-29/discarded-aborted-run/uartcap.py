import os,termios,select,time,sys
fd=os.open('/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02',os.O_RDONLY|os.O_NONBLOCK|os.O_NOCTTY)
a=termios.tcgetattr(fd);a[0]=a[1]=a[3]=0;a[2]=termios.CS8|termios.CREAD|termios.CLOCAL;a[4]=a[5]=termios.B115200
termios.tcsetattr(fd,termios.TCSANOW,a);out=open(sys.argv[1],'wb');t=time.time()
while time.time()-t<float(sys.argv[2]):
    if select.select([fd],[],[],0.2)[0]:
        try: out.write(os.read(fd,4096)); out.flush()
        except BlockingIOError: pass
