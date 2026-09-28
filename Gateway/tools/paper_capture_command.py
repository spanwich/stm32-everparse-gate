#!/usr/bin/env python3
"""Capture the named board's sole UART reader during a host test command."""
import argparse
import json
import os
from pathlib import Path
import select
import subprocess
import termios
import threading

p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, required=True)
p.add_argument('command', nargs=argparse.REMAINDER)
a = p.parse_args()
command = a.command[1:] if a.command and a.command[0] == '--' else a.command
if not command:
    p.error('a command is required after --')
a.output.mkdir(parents=True, exist_ok=True)
if subprocess.run(['fuser', '-s', '/dev/ttyACM1'], stdout=subprocess.DEVNULL,
                  stderr=subprocess.DEVNULL).returncode == 0:
    raise SystemExit('/dev/ttyACM1 already has a reader')
serial = '/dev/serial/by-id/usb-STMicroelectronics_STM32_STLink_066FFF555567894967085545-if02'
fd = os.open(serial, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
attrs = termios.tcgetattr(fd)
attrs[0] = attrs[1] = attrs[3] = 0
attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
attrs[4] = attrs[5] = termios.B115200
attrs[6][termios.VMIN] = attrs[6][termios.VTIME] = 0
termios.tcsetattr(fd, termios.TCSANOW, attrs)
termios.tcflush(fd, termios.TCIFLUSH)
stop = threading.Event()


def reader():
    with (a.output / 'uart.log').open('wb') as log:
        while not stop.is_set():
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    log.write(os.read(fd, 4096))
                    log.flush()
                except BlockingIOError:
                    pass


thread = threading.Thread(target=reader)
thread.start()
try:
    result = subprocess.run(command, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
finally:
    stop.set()
    thread.join(timeout=3)
    os.close(fd)
(a.output / 'command.log').write_bytes(result.stdout)
(a.output / 'capture.json').write_text(json.dumps({
    'command': command, 'exit_code': result.returncode,
    'uart_log': str(a.output / 'uart.log')}, indent=2) + '\n')
print(result.stdout.decode(errors='replace'))
raise SystemExit(result.returncode)
