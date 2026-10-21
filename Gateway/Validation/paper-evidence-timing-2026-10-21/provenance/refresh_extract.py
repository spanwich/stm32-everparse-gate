#!/usr/bin/env python3
"""Copy provenance scripts into the STM32 evidence directory, rewrite its SHA256SUMS,
mirror it (without ELF images and build logs) into the paper's evidence/f767-timing and rewrite that
SHA256SUMS (README.md and SHA256SUMS excluded, as generate_f767_timing.py expects)."""
import hashlib, shutil, subprocess
from pathlib import Path
SRC = Path('/home/iamfo470/stm32-projects/policy_gate/Gateway/Validation/paper-evidence-timing-2026-10-21')
DST = Path('/home/iamfo470/phd/papers/drafts/access-control-as-constraints-s-and-p/evidence/f767-timing')
TMP = Path('/home/iamfo470/.claude/jobs/d4a23072/tmp/pgtim')
for name in ('build_timing.py', 'run_a12.sh', 'run_norank.sh', 'summarize_variants.py', 'summarize_timing.py',
             'a2_run_probes.py', 'apply_itcm_probes.py', 'memops_test.c', 'refresh_extract.py'):
    shutil.copy2(TMP / name, SRC / 'provenance' / name)


def sums(root, skip):
    lines = []
    for p in sorted(root.rglob('*')):
        rel = str(p.relative_to(root))
        if p.is_file() and rel not in skip:
            lines.append(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}')
    (root / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
    return len(lines)


print('stm32', sums(SRC, {'SHA256SUMS'}))
subprocess.run(['rsync', '-a', '--exclude', 'policy_gate.elf', '--exclude', 'build.log', '--exclude', 'SHA256SUMS',
                str(SRC) + '/', str(DST) + '/'], check=True)
for stale in DST.rglob('build.log'):   # build logs stay in the STM32 repository
    stale.unlink()
print('paper', sums(DST, {'SHA256SUMS', 'README.md'}))
