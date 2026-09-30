#!/usr/bin/env python3
"""Watch the running board over ST-LINK/SWD without halting it, and on a NET
hang halt it and dump the kernel state (Gateway/tools/d1_hang_dump.py).

OpenOCD attaches without reset; the IWDG is frozen for debug halts
(DBGMCU_APB1_FZ.DBG_IWDG_STOP) so a halt does not reset the evidence away.
Every --period seconds it reads, with memory accesses that do not stop the
CPU: the HTTP request counter, kernel-object pool and registry occupancy,
FreeRTOS heap, and the pending-message counts of the one-slot reply queues
(object worker, NET<-GATE, GATE<-APP). A reply that lingers across samples
while its consumer is idle is logged as a stale-reply event. A hang is the
request counter frozen for --stall seconds while the load process is alive.
"""
from pathlib import Path
import argparse, csv, re, socket, subprocess, time

root = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument('--elf', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--period', type=float, default=0.2)
p.add_argument('--stall', type=float, default=20.0)
p.add_argument('--load-pid-file', type=Path, required=True, help='file holding the load process PID')
p.add_argument('--max-hours', type=float, default=3.0)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=True)

def resolve(expr):
    out = subprocess.check_output(['gdb-multiarch', '-q', '-batch', '-ex', f'print (unsigned int)&{expr}', str(a.elf)], text=True)
    return int(re.search(r'= (\d+)', out)[1])

ADDR = {
    'requests': resolve("'gateway_network.c'::requests"),
    'heap_free': resolve('xFreeBytesRemaining'),
    'pool': resolve('xKernelObjectPool'),
    'registry': resolve("'d1_kernel_cleanup.c'::registered"),
    'worker_reply': resolve("'d1_kernel_cleanup.c'::reply_cb") + 56,
    'worker_request': resolve("'d1_kernel_cleanup.c'::request_cb") + 56,
    'gate_reply': resolve("'gateway_r4_boundary.c'::reply_cb") + 56,
    'app_reply': resolve('app_reply_cb') + 56,
}

ocd = subprocess.Popen(['openocd', '-f', 'interface/stlink.cfg', '-c', 'transport select hla_swd',
                        '-c', 'hla_serial 066FFF555567894967085545', '-f', 'target/stm32f7x.cfg',
                        '-c', 'gdb_port 3333', '-c', 'tcl_port 6666', '-c', 'telnet_port disabled', '-c', 'init'],
                       stdout=(a.output / 'openocd.log').open('w'), stderr=subprocess.STDOUT)
time.sleep(3)
sock = socket.create_connection(('127.0.0.1', 6666))

def tcl(cmd):
    sock.sendall(cmd.encode() + b'\x1a')
    data = b''
    while not data.endswith(b'\x1a'):
        data += sock.recv(65536)
    return data[:-1].decode(errors='replace')

def words(addr, count):
    out = tcl(f'mdw {addr:#x} {count}')
    return [int(w, 16) for line in out.splitlines() for w in line.split(':', 1)[1].split()] if ':' in out else []

tcl('mmw 0xE0042008 0x1000 0')   # DBG_IWDG_STOP: freeze the watchdog while halted
log = (a.output / 'watch.csv').open('w', newline='')
w = csv.writer(log)
w.writerow(['t', 'requests', 'heap_free', 'pool_used', 'registry_used', 'worker_reply', 'worker_request',
            'gate_reply', 'app_reply'])
events = (a.output / 'events.log').open('w')
start = time.time(); last_req = None; last_change = time.time(); linger = {}
while time.time() - start < a.max_hours * 3600:
    req = words(ADDR['requests'], 1)[0]
    heap = words(ADDR['heap_free'], 1)[0]
    pool = words(ADDR['pool'], 128 * 3)
    pool_used = sum(1 for i in range(0, len(pool), 3) if pool[i])
    reg_used = sum(1 for x in words(ADDR['registry'], 128) if x)
    q = {k: words(ADDR[k], 1)[0] for k in ('worker_reply', 'worker_request', 'gate_reply', 'app_reply')}
    now = time.time()
    w.writerow([f'{now - start:.2f}', req, heap, pool_used, reg_used, q['worker_reply'], q['worker_request'],
                q['gate_reply'], q['app_reply']])
    for k in ('worker_reply', 'gate_reply', 'app_reply'):
        linger[k] = linger.get(k, 0) + 1 if q[k] else 0
        if linger[k] == 3:   # a reply left unconsumed across three samples
            events.write(f'{now - start:.2f} STALE {k} requests={req} pool={pool_used} registry={reg_used}\n'); events.flush()
    if req != last_req:
        last_req, last_change = req, now
    try:
        load_alive = Path(f'/proc/{int(a.load_pid_file.read_text())}').exists()
    except (OSError, ValueError):
        load_alive = False
    if now - last_change > a.stall and last_req:
        events.write(f'{now - start:.2f} HANG requests={req} load_alive={load_alive} pool={pool_used} registry={reg_used}\n')
        events.flush(); log.flush()
        tcl('halt')
        dump = subprocess.run(['gdb-multiarch', '-q', '-batch', '-ex', 'set pagination off',
                               '-ex', 'target extended-remote :3333',
                               '-ex', f'source {root / "Gateway/tools/d1_hang_dump.py"}', str(a.elf)],
                              capture_output=True, text=True, timeout=300)
        (a.output / 'hang-dump.txt').write_text(dump.stdout + dump.stderr)
        events.write('board left HALTED for inspection (IWDG frozen)\n'); events.flush()
        break
    if not load_alive and now - start > 30:
        events.write(f'{now - start:.2f} load finished without hang; requests={req}\n'); events.flush()
        break
    log.flush()
    time.sleep(a.period)
sock.close()
ocd.terminate()
