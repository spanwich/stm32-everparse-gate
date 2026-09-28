#!/usr/bin/env python3
"""Mutation experiment: proof failures are required; replay is an explicit gap."""
import hashlib, json, os, pathlib, shutil, subprocess, tempfile
root=pathlib.Path(__file__).resolve().parents[1]
fstar=os.environ.get('FSTAR','/home/iamfo470/phd/everparse/opt/FStar/bin/fstar.exe')
lock=json.loads((root/'toolchain.lock.json').read_text())
z3=os.environ.get('Z3',lock['z3']['path'])
for name,path in [('fstar',fstar),('z3',z3)]:
 assert hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()==lock[name]['sha256'], 'Tool identity mismatch: '+name
mutations={
 'ignore_deny':('Mediation.Wrapper.fst','if ok then','if true then',False),
 'wrong_kind':('Mediation.Wrapper.fst','E.invoke k n r p l ctx','E.invoke 1uy n r p l ctx',False),
 'alter_request':('Mediation.Wrapper.fst','let status=E.invoke','let _ = B.upd r 1ul 0uy in\n   let status=E.invoke',False),
 'alter_candidate':('Mediation.Wrapper.fst','let status=E.invoke','let _ = B.upd r 175ul 0uy in\n   let status=E.invoke',False),
 'bad_copy':('Mediation.Format.fst','B.upd e i v;','B.upd e i 0uy;',False),
 'repeat_invoke':('Mediation.Wrapper.fst','let status=E.invoke','let _ = E.invoke k n r p l ctx in\n   let status=E.invoke',True),
}
for name,(file,old,new,expected_pass) in mutations.items():
 with tempfile.TemporaryDirectory(prefix='mediation-negative-') as tmp:
    tmp=pathlib.Path(tmp)
    for p in (root/'lowstar').glob('*fst*'): shutil.copyfile(p,tmp/p.name)
    path=tmp/file; text=path.read_text(); assert text.count(old)==1
    path.write_text(text.replace(old,new))
    cmd=[fstar,'--smt',z3,'--include',str(tmp),'--split_queries','always',
         '--z3smtopt','(set-option :smt.arith.solver 2)',str(tmp/file)]
    r=subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    (root/'evidence'/('negative-'+name+'.log')).write_text(r.stdout)
    if expected_pass:
        assert r.returncode==0 and 'All verification conditions discharged successfully' in r.stdout,r.stdout
        print(name, 'ACCEPTED: current contracts do not prove invocation count',flush=True)
    else:
        assert r.returncode!=0 and 'Assertion failed' in r.stdout,r.stdout
        print(name,'proof rejected mutation',flush=True)
