#!/usr/bin/env python3
"""Copy Gateway/tools to a scratch directory, changing only paths (as the
2026-10-11 campaign's /tmp/pgtools): repository root and Gateway directory become
absolute, quoted 'Gateway/tools/...' references point at the copy, and the
hard-coded D1 evidence directory becomes the A1v directory."""
from pathlib import Path
import re, shutil, sys
root = Path('/home/iamfo470/stm32-projects/policy_gate')
dst = Path(sys.argv[1]).resolve()
evidence = sys.argv[2]
if dst.exists():
    shutil.rmtree(dst)
shutil.copytree(root / 'Gateway/tools', dst, ignore=shutil.ignore_patterns('__pycache__'))
for path in sorted(dst.glob('*.py')):
    text = path.read_text()
    new = text.replace('Path(__file__).resolve().parents[2]', f"Path('{root}')")
    new = new.replace('Path(__file__).resolve().parents[1]', f"Path('{root}/Gateway')")
    new = re.sub(r"""(['"])Gateway/tools/""", lambda m: m[1] + str(dst) + '/', new)
    new = re.sub(r'paper-evidence-d1-2026-09-30', evidence, new)
    if new != text:
        path.write_text(new)
        print('rewrote', path.name)
