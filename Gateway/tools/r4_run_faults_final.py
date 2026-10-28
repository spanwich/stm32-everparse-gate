#!/usr/bin/env python3
"""Rebuild and run the five R4 MPU probes against the final task layout.

Each probe is a distinct image. Faults are expected, so board_test's
nonzero exit and curl's timeout are saved as evidence rather than hidden.
"""
from pathlib import Path
import argparse
import json
import re
import subprocess
import tempfile

root=Path(__file__).resolve().parents[2]
header=root/'Gateway/Inc/paper_experiment.h'
evidence=root/'Gateway/Validation/paper-evidence-r4-2026-09-29'
cli='/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.cubeprogrammer.linux64_2.2.300.202508131133/tools/bin/STM32_Programmer_CLI'
nm='/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin/arm-none-eabi-nm'
p=argparse.ArgumentParser()
p.add_argument('--faults',nargs='+',type=int,choices=(1,2,3,4,5),default=(1,2,3,4,5))
a=p.parse_args()
original=header.read_text()

def run(*command,check=True):
    result=subprocess.run(command,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if check and result.returncode:
        raise RuntimeError(f'{command!r} exited {result.returncode}: '+
                           result.stdout.decode(errors='replace')[-1000:])
    return result

try:
    for fault in a.faults:
        name=f'fault-{fault}-final-layout'
        directory=evidence/name
        directory.mkdir(parents=True,exist_ok=True)
        content,count=re.subn(r'(#define GATEWAY_R4_FAULT_INJECT )\d+',
                              lambda match:match[1]+str(fault),original)
        assert count==1
        header.write_text(content)
        run('python3','Gateway/tools/configure_project.py')
        with tempfile.TemporaryDirectory(prefix='r4-fault-build-') as build:
            result=run('python3','Gateway/tools/build_firmware.py','--output',build)
            (directory/'build-command.log').write_bytes(result.stdout)
            run('python3','Gateway/tools/r4_stage_variant.py',name,'--fault',str(fault),
                '--build-log',str(Path(build)/'build.log'))
        elf=directory/'policy_gate.elf'
        board=run('python3','Gateway/tools/board_test.py','--elf',str(elf),
                  '--flash','--output',str(directory/'board'),'--seconds','15',
                  '--expected-selftests','322',check=False)
        (directory/'board-command.log').write_bytes(board.stdout)
        if fault==2:
            trigger=run('python3','Gateway/tools/paper_capture_command.py',
                '--output',str(directory/'trigger'),'--','curl','--max-time','4',
                '--silent','--show-error','-H',
                'Authorization: Bearer pg-lab-operator',
                'http://192.168.40.128/api/status',check=False)
            (directory/'trigger-command.log').write_bytes(trigger.stdout)
        symbols=run(nm,str(elf)).stdout.decode()
        match=re.search(r'^([0-9a-fA-F]+)\s+[bB]\s+gateway_fault_record$',
                        symbols,re.MULTILINE)
        assert match
        fault_address='0x'+match[1]
        swd=run(cli,'-c','port=SWD','sn=066FFF555567894967085545',
                'mode=HOTPLUG','freq=1000','-r32',fault_address,'32',
                '-r32','0xE000ED28','24')
        (directory/'fault-registers.log').write_bytes(swd.stdout)
        details={'probe':fault,'elf':str(elf),'board_exit_code':board.returncode,
                 'fault_record_address':fault_address,
                 'serial_log':str(directory/'board/uart.log'),
                 'swd_log':str(directory/'fault-registers.log')}
        (directory/'probe.json').write_text(json.dumps(details,indent=2)+'\n')
        print('R4 final-layout fault probe:',fault,'board exit',board.returncode,
              'SWD saved',flush=True)
finally:
    header.write_text(original)
    run('python3','Gateway/tools/configure_project.py')
