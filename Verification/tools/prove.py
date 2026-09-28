#!/usr/bin/env python3
"""Proof check first, extract second. Never use --lax or admit SMT failures."""
import argparse, hashlib, json, os, pathlib, shutil, subprocess, tempfile
root = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--fstar', default=os.environ.get('FSTAR', '/home/iamfo470/phd/everparse/opt/FStar/bin/fstar.exe'))
p.add_argument('--karamel', default=os.environ.get('KRML_HOME', '/home/iamfo470/phd/everparse/opt/karamel'))
p.add_argument('--z3', default=os.environ.get('Z3', '/home/iamfo470/phd/everparse/opt/z3/z3-4.13.3'))
p.add_argument('--extract', action='store_true')
p.add_argument('--replay', action='store_true')
a = p.parse_args()
lock=json.loads((root/'toolchain.lock.json').read_text())
for name,path in [('fstar',a.fstar),('karamel',a.karamel+'/krml'),('z3',a.z3)]:
    assert hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()==lock[name]['sha256'], 'Tool identity mismatch: '+name

with tempfile.TemporaryDirectory(prefix='mediation-proof-') as tmp:
    flags = [a.fstar, '--smt', a.z3, '--split_queries', 'always', '--z3smtopt', '(set-option :smt.arith.solver 2)', '--cache_checked_modules', '--cache_dir', tmp,
             '--include', str(root/'lowstar'), '--include', a.karamel+'/krmllib', '--include', a.karamel+'/krmllib/obj']
    def run(cmd, log, env=None):
        r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        (root/'evidence'/log).write_text(r.stdout)
        if r.returncode: raise SystemExit(r.stdout)
        print(log, 'PASS', flush=True)
    if a.replay:
        # R1 imports the paper extractor, whose Complete module needs the
        # paper's F*/Z3 release. The old pinned F* still checks retained IPC.
        subprocess.run(['python3', str(root/'tools/prove_reference_extractor.py')], check=True)
        specs=root.parent/'Gateway/Provenance/specifications'
        modules=['HTTP.Extract.Types.fst','IPC.Extract.fst']
        # Sequential checks make dependency .checked files available for extraction.
        for name in modules:
            run(flags+['--include',str(specs),str(specs/name)], 'replay-'+name+'.log')
    modules=['Mediation.Format.fst','Mediation.Extern.fsti','Mediation.Wrapper.fst']
    for name in modules:
        run(flags+[str(root/'lowstar'/name)], name+'.log')
    if a.extract:
        if (root/'generated').exists(): shutil.rmtree(root/'generated')
        (root/'generated').mkdir()
        run(flags+['--odir',tmp,'--codegen','krml','--extract','Mediation']+[str(root/'lowstar'/n) for n in modules], 'extract-fstar.log')
        env=dict(os.environ, KRML_HOME=a.karamel)
        run([a.karamel+'/krml','-skip-compilation','-skip-linking','-tmpdir',str(root/'generated'),
             '-bundle','Mediation.Format=Mediation.Format','-bundle','Mediation.Wrapper=Mediation.Wrapper',
             tmp+'/out.krml'], 'extract-karamel.log', env)
        target=root.parent/'Gateway/Generated/Mediation'
        target.mkdir(parents=True,exist_ok=True)
        for old in target.rglob('*'):
            if old.is_file(): old.unlink()
        for source in (root/'generated').rglob('*'):
            if source.suffix in ('.c','.h'):
                dest=target/source.relative_to(root/'generated')
                dest.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(source,dest)
    if a.extract:
        versions={}
        for name,cmd in [('fstar',[a.fstar,'--version']),('karamel',[a.karamel+'/krml','-version'])]:
            versions[name]=subprocess.check_output(cmd,text=True).strip()
        versions['solver']=lock['z3']
        versions['solver_option']=lock['solver_option']
        versions['sources']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((root/'lowstar').glob('*fst*'))}
        versions['generated']={str(p.relative_to(root.parent)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((root.parent/'Gateway/Generated/Mediation').rglob('*')) if p.is_file()}
        (root/'evidence/proof-manifest.json').write_text(json.dumps(versions,indent=2)+'\n')
