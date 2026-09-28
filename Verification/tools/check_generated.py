#!/usr/bin/env python3
"""Integrity check, NOT a replacement for proof replay or compiler validation."""
import hashlib,json,pathlib
root=pathlib.Path(__file__).resolve().parents[1]
m=json.loads((root/'evidence/proof-manifest.json').read_text())
for name,digest in m['sources'].items():
    assert hashlib.sha256((root/'lowstar'/name).read_bytes()).hexdigest()==digest,'Proof source changed: '+name
actual={str(p.relative_to(root.parent)) for p in (root.parent/'Gateway/Generated/Mediation').rglob('*') if p.is_file()}
assert actual==set(m['generated']),'Generated file set changed'
for name,digest in m['generated'].items():
    assert hashlib.sha256((root.parent/name).read_bytes()).hexdigest()==digest,'Generated C changed: '+name
print('Mediation proof-source/generated-C integrity PASS (not fresh proof verification)')
