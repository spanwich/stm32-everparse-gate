#!/usr/bin/env python3
"""Write or verify a reproducible SHA256SUMS for a paper-evidence bundle."""
import argparse
import hashlib
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument('bundle', type=Path)
parser.add_argument('--verify', action='store_true')
args = parser.parse_args()
bundle = args.bundle.resolve()
receipt = bundle / 'SHA256SUMS'
entries = []
for path in sorted(bundle.rglob('*')):
    if not path.is_file() or path == receipt:
        continue
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    entries.append(f'{digest.hexdigest()}  {path.relative_to(bundle)}')
content = '\n'.join(entries) + '\n'
if args.verify:
    assert receipt.read_text() == content, 'evidence hash mismatch or file set changed'
    print(f'PASS: {len(entries)} files match {receipt}')
else:
    receipt.write_text(content)
    print(f'Wrote {len(entries)} file hashes to {receipt}')
