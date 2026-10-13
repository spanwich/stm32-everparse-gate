# gdb -batch -x this (after `target extended-remote :3333`, ELF loaded).
# Measures DWT CYCCNT between entry of FUNC and its return (CYCCNT stops while
# the core is halted). Writes CSV rows to OUT. Env: FUNC, COND, N, OUT, CAL.
import gdb, os, csv
FUNC = os.environ['FUNC']; N = int(os.environ['N']); OUT = os.environ['OUT']
COND = os.environ.get('COND', '')
gdb.execute('set pagination off'); gdb.execute('set confirm off')
gdb.execute('monitor mmw 0xE0042008 0x1000 0')        # freeze IWDG in halt
gdb.execute('monitor mww 0xE000EDFC 0x01000000')       # DEMCR.TRCENA
gdb.execute('monitor mmw 0xE0001000 1 0')              # DWT CYCCNT enable
def cyc():
    return int(gdb.parse_and_eval('*(unsigned int*)0xE0001004')) & 0xffffffff
rows = []
if os.environ.get('CAL'):
    # Overhead calibration: entry bp, then bp on the next instruction.
    addr = int(gdb.parse_and_eval(f'(unsigned int)&{FUNC}')) & ~1
    gdb.execute(f'hbreak *{addr:#x}')
    for i in range(N):
        gdb.execute('continue', to_string=True)
        c0 = cyc()
        gdb.execute('stepi', to_string=True)
        rows.append((i, 'calibration-stepi', (cyc() - c0) & 0xffffffff, 'stepi'))
else:
    gdb.execute(f'hbreak {FUNC}' + (f' if {COND}' if COND else ''))
    for i in range(N):
        gdb.execute('continue', to_string=True)
        c0 = cyc()
        ret = gdb.execute('finish', to_string=True)
        val = ''
        for line in ret.splitlines():
            if line.startswith('Value returned'):
                val = line.split('=')[-1].strip()
        rows.append((i, FUNC, (cyc() - c0) & 0xffffffff, val))
gdb.execute('delete')
with open(OUT, 'w', newline='') as f:
    w = csv.writer(f); w.writerow(['i', 'what', 'cycles', 'return']); w.writerows(rows)
gdb.execute('continue &', to_string=True)
gdb.execute('disconnect')
