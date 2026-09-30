import gdb
TCBS = ['gateway_tcb','gate_tcb','app_tcb','auth_tcb','tcpip_tcb','net_input_tcb','input_tcb','link_tcb','tx_tcb','cleanup_tcb','diagnostic_tcb','log_tcb']
def u32(a): return int(gdb.parse_and_eval(f'*(unsigned int*){a}')) & 0xffffffff
def sym(a):
    try: return gdb.execute(f'info symbol {a:#x}', to_string=True).strip()
    except gdb.error: return '?'
cur = int(gdb.parse_and_eval('(unsigned int)pxCurrentTCB'))
for name in TCBS:
    try: base = int(gdb.parse_and_eval(f'(unsigned int)&{name}'))
    except gdb.error: continue
    t = f'((struct tskTaskControlBlock *){base:#x})'
    top = u32(base)
    pc, lr, psp = u32(top-8), u32(top-12), u32(top-36)
    info = gdb.parse_and_eval(f'{t}->xMPUSettings.xSystemCallStackInfo')
    entry_lr = int(info['ulLinkRegisterAtSystemCallEntry']) & 0xffffffff
    task_stack = int(info['pulTaskStack']) & 0xffffffff
    ev = int(gdb.parse_and_eval(f'(unsigned int){t}->xEventListItem.pvContainer'))
    st = int(gdb.parse_and_eval(f'(unsigned int){t}->xStateListItem.pvContainer'))
    tname = gdb.parse_and_eval(f'{t}->pcTaskName').string()
    print(f'== {name} ({tname}){" RUNNING" if base==cur else ""}')
    print(f'   pc={pc:#010x} {sym(pc)}')
    print(f'   lr={lr:#010x} {sym(lr)}')
    print(f'   syscall entry lr={entry_lr:#010x} {sym(entry_lr) if entry_lr else ""} task_stack={task_stack:#x}')
    print(f'   state_list={st:#x} {sym(st)}  event_list={ev:#x} {sym(ev) if ev else "-"}')
    # Scan the saved task stack for plausible return addresses (heuristic).
    if task_stack:
        rets = []
        for i in range(0, 64):
            v = u32(task_stack + 4*i)
            if 0x08000000 <= v < 0x08100000 and v & 1:
                s = sym(v & ~1)
                if 'No symbol' not in s: rets.append(s.split(' in section')[0])
        print('   stack return candidates:', ' <- '.join(dict.fromkeys(rets))[:600])
