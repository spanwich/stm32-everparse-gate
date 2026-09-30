#!/usr/bin/env python3
"""Check whether closed TCP connections are released (non-halting SWD reads).

Sends one HTTP request per second and, after each, reads over SWD: lwIP memp
stats for NETCONN and TCP_PCB (used/max/err/avail) and the TCP state and ports
of every pcb on the active and TIME_WAIT lists, with the owning netconn's
state. Addresses come from --elf; struct offsets are those of lwIP 2.1.2 in this build."""
from pathlib import Path
import argparse, json, socket, subprocess, time

p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, required=True)
p.add_argument('--seconds', type=int, default=60)
p.add_argument('--elf', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=True)
def resolve(expr):
    out = subprocess.check_output(['gdb-multiarch', '-q', '-batch', '-ex', f'print (unsigned int)({expr})', str(a.elf)], text=True)
    return int(out.rsplit('=', 1)[1].split()[0])
LWIP_STATS_MEMP = resolve('&lwip_stats.memp[0]')
MEMP = {'TCP_PCB': resolve('MEMP_TCP_PCB'), 'NETCONN': resolve('MEMP_NETCONN')}
ACTIVE, TIMEWAIT = resolve('&tcp_active_pcbs'), resolve('&tcp_tw_pcbs')
STATES = ['CLOSED', 'LISTEN', 'SYN_SENT', 'SYN_RCVD', 'ESTABLISHED', 'FIN_WAIT_1', 'FIN_WAIT_2',
          'CLOSE_WAIT', 'CLOSING', 'LAST_ACK', 'TIME_WAIT']
NETCONN_STATES = ['NONE', 'WRITE', 'LISTEN', 'CONNECT', 'CLOSE']

ocd = subprocess.Popen(['openocd', '-f', 'interface/stlink.cfg', '-c', 'transport select hla_swd',
                        '-c', 'hla_serial 066FFF555567894967085545', '-f', 'target/stm32f7x.cfg',
                        '-c', 'gdb_port disabled', '-c', 'tcl_port 6666', '-c', 'telnet_port disabled', '-c', 'init'],
                       stdout=(a.output / 'openocd.log').open('w'), stderr=subprocess.STDOUT)
time.sleep(3)
sock = socket.create_connection(('127.0.0.1', 6666))

def tcl(cmd):
    sock.sendall(cmd.encode() + b'\x1a')
    data = b''
    while not data.endswith(b'\x1a'):
        data += sock.recv(65536)
    return data[:-1].decode(errors='replace')

def word(addr):
    return int(tcl(f'mdw {addr:#x}').split(':', 1)[1].split()[0], 16)

def u8(addr):
    return int(tcl(f'mdb {addr:#x}').split(':', 1)[1].split()[0], 16)

def u16(addr):
    return int(tcl(f'mdh {addr:#x}').split(':', 1)[1].split()[0], 16)

def memp(name):
    s = word(LWIP_STATS_MEMP + 4 * MEMP[name])
    return {'err': u16(s), 'avail': u16(s + 2), 'used': u16(s + 4), 'max': u16(s + 6)}

def pcbs(head):
    out, pcb, seen = [], word(head), 0
    while pcb and seen < 32:
        conn = word(pcb + 16)
        st = u8(pcb + 20)
        out.append({'pcb': hex(pcb), 'state': STATES[st] if st < len(STATES) else st,
                    'local': u16(pcb + 22), 'remote': u16(pcb + 24),
                    'netconn': hex(conn),
                    'netconn_state': NETCONN_STATES[u8(conn + 1)] if conn and u8(conn + 1) < 5 else None})
        pcb, seen = word(pcb + 12), seen + 1
    return out

def request():
    try:
        s = socket.create_connection(('192.168.40.128', 80), timeout=5)
        port = s.getsockname()[1]
        s.sendall(b'GET /api/status HTTP/1.1\r\nHost: board\r\nAuthorization: Bearer pg-lab-operator\r\n\r\n')
        data = b''
        while True:
            part = s.recv(4096)
            if not part:
                break
            data += part
        s.close()
        return port, data.split(b'\r\n', 1)[0].decode()
    except OSError as e:
        return None, 'ERR ' + type(e).__name__

log = (a.output / 'socket-check.jsonl').open('w')
def snapshot(tag, port=None, result=None):
    rec = {'t': round(time.time() - start, 2), 'tag': tag, 'client_port': port, 'result': result,
           'NETCONN': memp('NETCONN'), 'TCP_PCB': memp('TCP_PCB'),
           'active': pcbs(ACTIVE), 'time_wait': pcbs(TIMEWAIT)}
    log.write(json.dumps(rec) + '\n'); log.flush()
    print(f"{rec['t']:6} {tag:8} {str(result):28} NETCONN used={rec['NETCONN']['used']}/{rec['NETCONN']['avail']} "
          f"err={rec['NETCONN']['err']} TCP_PCB used={rec['TCP_PCB']['used']}/{rec['TCP_PCB']['avail']} "
          f"active={[(x['state'], x['netconn_state']) for x in rec['active']]} tw={len(rec['time_wait'])}", flush=True)

start = time.time()
snapshot('before')
while time.time() - start < a.seconds:
    port, result = request()
    time.sleep(0.3)
    snapshot('after', port, result)
    time.sleep(0.7)
sock.close(); ocd.terminate()
