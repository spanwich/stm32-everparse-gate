#!/usr/bin/env python3
"""Collect existing successful runs; this command does not perform validation."""
import argparse,hashlib,json,pathlib,re,shutil,subprocess
root=pathlib.Path(__file__).resolve().parents[2];v=root/'Verification';e=v/'evidence'
p=argparse.ArgumentParser()
p.add_argument('--host',required=True,type=pathlib.Path)
p.add_argument('--auth-off',required=True,type=pathlib.Path)
p.add_argument('--build',required=True,type=pathlib.Path)
a=p.parse_args()
summary={'baseline':subprocess.check_output(['git','rev-parse','main'],cwd=root,text=True).strip(),
         'branch':subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip(),
         'hardware_tested':False,'deployed':False,'results':{},'firmware':{}}
for key,source in [('host',a.host/'tests.log'),('host-auth-off',a.auth_off/'tests.log')]:
    txt=source.read_text();match=re.search(r'\[CORE SELFTEST\] PASS (\d+)/(\d+)',txt)
    assert match and match[1]==match[2] and 'FAIL' not in txt
    summary['results'][key]=int(match[1]);shutil.copyfile(source,e/(key+'.log'))
text=(a.build/'build.log').read_text()
assert text.count('Gateway post-link checks PASS')>=2 and not re.search(r'\b(?:error|warning):',text)
shutil.copyfile(a.build/'build.log',e/'firmware-build.log')
compiler=pathlib.Path('/opt/st/stm32cubeide_2.0.0/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.13.3.rel1.linux64_1.0.100.202509120712/tools/bin')
for config in ['Debug','Release']:
    elf=root/config/'policy_gate.elf';stack=root/config/'gateway.stack.json'
    sizes=subprocess.check_output([str(compiler/'arm-none-eabi-size'),str(elf)],text=True).splitlines()[1].split()
    summary['firmware'][config]={'sha256':hashlib.sha256(elf.read_bytes()).hexdigest(),
        'text':int(sizes[0]),'data':int(sizes[1]),'bss':int(sizes[2]),
        'known_frame_chain_bytes':json.loads(stack.read_text())['known_frame_chain_bytes']}
    shutil.copyfile(stack,e/(config.lower()+'-stack.json'))
summary['results']['kernel_cases']=int(re.search(r'(\d+) cases:',(e/'kernel-tests.log').read_text())[1])
summary['results']['tlc_distinct_states']=int(re.search(r'(\d+) distinct states found',(e/'tlc-none.log').read_text())[1])
for name in ['Types','Scan','Method','Path','Header','Bearer','Complete']:
    assert 'All verification conditions discharged successfully' in (e/('replay-HTTP.Extract.'+name+'.fst.log')).read_text()
assert 'All verification conditions discharged successfully' in (e/'replay-IPC.Extract.fst.log').read_text()
for name in ['Mediation.Format.fst','Mediation.Wrapper.fst']:
    assert 'All verification conditions discharged successfully' in (e/(name+'.log')).read_text()
for name in ['ignore_deny','wrong_kind','alter_request','alter_candidate','bad_copy']:
    assert 'Assertion failed' in (e/('negative-'+name+'.log')).read_text()
assert 'All verification conditions discharged successfully' in (e/'negative-repeat_invoke.log').read_text()
for name in ['bypass','ignore_deny','wrong_request','wrong_candidate','stale','replay']:
    assert 'is violated' in (e/('tlc-'+name+'.log')).read_text()
summary['results'].update(extractor_modules_replayed=8,new_proved_modules=2,
    trusted_interfaces_checked=1,tlc_mutations_detected=6,proof_mutations_rejected=5,
    duplicate_invocation_proof_gap=True)
summary['source_sha256']={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
    for top in ['Gateway/Core','Gateway/Inc','Gateway/SelfTest','Gateway/Generated/Mediation','Verification/lowstar','Verification/tla']
    for p in sorted((root/top).rglob('*')) if p.is_file()}
(v/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary['results'],indent=2))
