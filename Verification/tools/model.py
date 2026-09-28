#!/usr/bin/env python3
"""Run the finite model and require each deliberately faulty variant to fail."""
import argparse, hashlib, json, os, pathlib, subprocess, tempfile
root = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--jar', default=os.environ.get('TLA_JAR', '/home/iamfo470/.cache/sel4-multikernel/tla/tla2tools-v1.7.4.jar'))
a = p.parse_args()
lock=json.loads((root/'toolchain.lock.json').read_text())
assert hashlib.sha256(pathlib.Path(a.jar).read_bytes()).hexdigest()==lock['tlc']['sha256'], 'TLC binary identity mismatch'
for mutation in ['none', 'bypass', 'ignore_deny', 'wrong_request', 'wrong_candidate', 'stale', 'replay']:
    with tempfile.TemporaryDirectory(prefix='mediation-tlc-') as tmp:
        cfg = pathlib.Path(tmp)/'run.cfg'
        (pathlib.Path(tmp)/'Mediation.tla').write_text((root/'tla/Mediation.tla').read_text())
        cfg.write_text(f'CONSTANT Mutation = "{mutation}"\nSPECIFICATION Spec\nINVARIANT Mediated Once PolicyCommit\nCHECK_DEADLOCK FALSE\n')
        cmd = ['java', '-XX:+UseParallelGC', '-Xmx1g', '-cp', a.jar, 'tlc2.TLC', '-workers', '1', '-seed', '1',
               '-metadir', tmp+'/states', '-config', 'run.cfg', 'Mediation']
        r = subprocess.run(cmd, cwd=tmp, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        (root/'evidence'/f'tlc-{mutation}.log').write_text(r.stdout)
        if mutation == 'none':
            assert r.returncode == 0 and 'No error has been found' in r.stdout, r.stdout
        else:
            assert r.returncode != 0 and 'is violated' in r.stdout, r.stdout
        print(mutation, 'PASS' if mutation == 'none' else 'counterexample detected', flush=True)
