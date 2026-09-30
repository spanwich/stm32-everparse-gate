#!/usr/bin/env python3
"""Build the separate one-shot NET fault image; restore the primary header."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile

root=Path(__file__).resolve().parents[2]
header=root/'Gateway/Inc/paper_experiment.h'
p=argparse.ArgumentParser()
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
original=header.read_text()
try:
    changed,n=re.subn(r'(#define GATEWAY_D1_FAULT_ONCE )0',
                      lambda m:m[1]+'1',original)
    assert n==1
    header.write_text(changed)
    with tempfile.TemporaryDirectory(prefix='policy-d1-reset-build-') as temp:
        with (out/'build-command.log').open('wb') as log:
            subprocess.run(['python3','Gateway/tools/build_firmware.py',
                            '--output',temp],cwd=root,stdout=log,
                           stderr=subprocess.STDOUT,check=True)
        shutil.copy2(Path(temp)/'build.log',out/'build.log')
    elf=root/'Debug/policy_gate.elf'
    shutil.copy2(elf,out/'policy_gate.elf')
    manifest={'variant':'D1 one-shot NET policy write, IWDG reset',
              'base_git_commit':subprocess.check_output(
                  ['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
              'elf_sha256':hashlib.sha256(elf.read_bytes()).hexdigest(),
              'source_sha256':{str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest()
                               for f in [header,root/'Gateway/Network/gateway_r4_boundary.c',
                                         root/'Gateway/Platform/gateway_platform.c',
                                         root/'STM32F767ZITX_FLASH.ld']}}
    (out/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(manifest['elf_sha256'])
finally:
    header.write_text(original)

