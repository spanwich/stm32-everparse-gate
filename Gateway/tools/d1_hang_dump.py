# GDB Python script (source it after `target extended-remote :3333` on a
# halted board). Dumps the state needed to classify the D1 NET hang:
# per-task saved context (V11 MPU wrappers v2 keep it in the TCB), the kernel
# object each task waits on, and for NET's wait object its queue fields,
# kernel-object pool slot, the ACL bits of NET and TCP/IP for that slot, and
# its occurrences in the privileged object registry.
import gdb

TCBS = ['gateway_tcb', 'gate_tcb', 'app_tcb', 'auth_tcb', 'tcpip_tcb', 'net_input_tcb',
        'input_tcb', 'link_tcb', 'tx_tcb', 'cleanup_tcb', 'diagnostic_tcb', 'log_tcb']
QUEUE_WAIT_RX = 36          # offsetof(Queue_t, xTasksWaitingToReceive)
QUEUE_WAIT_TX = 16          # offsetof(Queue_t, xTasksWaitingToSend)
INDEX_OFFSET = 1


def ev(expr):
    return gdb.parse_and_eval(expr)


def u32(addr):
    return int(ev(f'*(unsigned int *){addr:#x}')) & 0xffffffff


def sym(addr):
    try:
        return gdb.execute(f'info symbol {addr:#x}', to_string=True).strip().split(' in section')[0]
    except gdb.error:
        return '?'


def tcb(name):
    return f"((struct tskTaskControlBlock *)&{name})"


def acl_bit(task, index):
    word = int(ev(f'{tcb(task)}->xMPUSettings.ulAccessControlList[{index // 32}]')) & 0xffffffff
    return (word >> (index % 32)) & 1


def pool_index(handle_addr):
    for i in range(128):
        if int(ev(f'(unsigned int)xKernelObjectPool[{i}].xInternalObjectHandle')) == handle_addr:
            return i, int(ev(f'xKernelObjectPool[{i}].ulKernelObjectType'))
    return None, None


def describe_queue(addr, label):
    q = f'((Queue_t *){addr:#x})'
    print(f'  {label} queue {addr:#x} ({sym(addr)}): waiting={int(ev(q + "->uxMessagesWaiting"))} '
          f'length={int(ev(q + "->uxLength"))} itemsize={int(ev(q + "->uxItemSize"))} '
          f'type={int(ev(q + "->ucQueueType"))} '
          f'rx_waiters={int(ev(q + "->xTasksWaitingToReceive.uxNumberOfItems"))} '
          f'tx_waiters={int(ev(q + "->xTasksWaitingToSend.uxNumberOfItems"))}')
    i, kind = pool_index(addr)
    if i is None:
        print('    NOT in kernel object pool (freed or never registered)')
        return
    handle = i + INDEX_OFFSET
    reg = [k for k in range(128) if int(ev(f"(unsigned int)'d1_kernel_cleanup.c'::registered[{k}]")) == handle]
    print(f'    pool slot {i} (external handle {handle}, type {kind}); registry entries {reg}; '
          f'ACL NET={acl_bit("gateway_tcb", i)} TCP/IP={acl_bit("tcpip_tcb", i)} '
          f'NET-input={acl_bit("net_input_tcb", i)}')


print('== kernel object pool in use:',
      sum(1 for i in range(128) if int(ev(f'(unsigned int)xKernelObjectPool[{i}].xInternalObjectHandle')) != 0))
print('== registry entries:',
      sum(1 for k in range(128) if int(ev(f"(unsigned int)'d1_kernel_cleanup.c'::registered[{k}]")) != 0))
print('== heap free:', int(ev('xFreeBytesRemaining')), 'requests:', int(ev("'gateway_network.c'::requests")))
current = int(ev('(unsigned int)pxCurrentTCB'))
for name in TCBS:
    base = int(ev(f'(unsigned int)&{name}'))
    t = tcb(name)
    top = u32(base)
    pc, lr = u32(top - 8), u32(top - 12)
    info = ev(f'{t}->xMPUSettings.xSystemCallStackInfo')
    entry = int(info['ulLinkRegisterAtSystemCallEntry']) & 0xffffffff
    event = int(ev(f'(unsigned int){t}->xEventListItem.pvContainer'))
    state = int(ev(f'(unsigned int){t}->xStateListItem.pvContainer'))
    print(f"== {name} ({ev(t + '->pcTaskName').string()}){' RUNNING' if base == current else ''}")
    print(f'  pc={sym(pc)} lr={sym(lr)} syscall-entry={sym(entry) if entry else "-"} state={sym(state)}')
    if event:
        for offset, label in ((QUEUE_WAIT_RX, 'receive-wait'), (QUEUE_WAIT_TX, 'send-wait')):
            describe_queue(event - offset, label) if int(ev(f'(unsigned int)((Queue_t *){event - offset:#x})->uxLength')) < 1024 else None
            break
tcpip_mbox = int(ev('(unsigned int)gateway_tcpip_mbox'))
if tcpip_mbox:
    i = tcpip_mbox - INDEX_OFFSET
    # Opaque handles are small pool indices; privileged callers may hold pointers.
    internal = (int(ev(f'(unsigned int)xKernelObjectPool[{i}].xInternalObjectHandle'))
                if 0 <= i < 128 else tcpip_mbox)
    if internal:
        describe_queue(internal, 'tcpip mailbox')
