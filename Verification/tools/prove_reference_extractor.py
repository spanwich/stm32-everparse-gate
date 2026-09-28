#!/usr/bin/env python3
"""Replay the paper-reference extractor with its own pinned EverParse release.

The R1 C files are imported byte-for-byte; this command checks their retained
F* sources without modifying generated output or claiming a new extraction.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
release = Path('/home/iamfo470/phd/everparse_v2025.10.06_Linux_x86_64/everparse')
fstar = release / 'bin/fstar.exe'
solver = release / 'lib/fstar/z3-4.13.3/bin/z3'
lock = json.loads((root / 'Verification/toolchain.lock.json').read_text())
for name, binary in (('paper_reference_fstar', fstar), ('paper_reference_z3', solver)):
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == lock[name]['sha256'], name
specs = root / 'Gateway/Provenance/specifications'
evidence = root / 'Verification/evidence'
names = ['HTTP.Extract.' + part + '.fst' for part in
         ('Types', 'Scan', 'Method', 'Path', 'Header', 'Bearer', 'Complete')]
manifest = json.loads((root / 'Gateway/Provenance/manifest.json').read_text())
for name in names:
    target = 'Gateway/Provenance/specifications/' + name
    item = next(entry for entry in manifest['files'] if entry['destination'] == target)
    assert hashlib.sha256((specs / name).read_bytes()).hexdigest() == item['source_sha256']
with tempfile.TemporaryDirectory(prefix='policy-gate-reference-proof-') as location:
    scratch = Path(location)
    for name in names:
        shutil.copy2(specs / name, scratch / name)
    command = [str(fstar), '--smt', str(solver), '--cache_checked_modules', '--cache_dir', str(scratch),
               '--split_queries', 'always', '--include', str(release / 'krmllib'),
               '--include', str(release / 'krmllib/obj'), *names]
    run = subprocess.run(command, cwd=scratch, text=True, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    (evidence / 'reference-extractor-replay.log').write_text(run.stdout)
    assert run.returncode == 0 and 'All verification conditions discharged successfully' in run.stdout
receipt = {
    'reference_release': 'v2025.10.06',
    'fstar_sha256': hashlib.sha256(fstar.read_bytes()).hexdigest(),
    'fstar_version': subprocess.check_output([str(fstar), '--version'], text=True).strip(),
    'z3_sha256': hashlib.sha256(solver.read_bytes()).hexdigest(),
    'z3_version': subprocess.check_output([str(solver), '-version'], text=True).strip(),
    'source_sha256': {name: hashlib.sha256((specs / name).read_bytes()).hexdigest()
                      for name in names},
    'log_sha256': hashlib.sha256((evidence / 'reference-extractor-replay.log').read_bytes()).hexdigest(),
    'result': 'all verification conditions discharged',
}
(evidence / 'reference-extractor-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
print('Paper-reference extractor F* replay PASS')
