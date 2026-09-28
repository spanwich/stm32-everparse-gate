#!/usr/bin/env python3
import pathlib, subprocess, tempfile
root=pathlib.Path(__file__).resolve().parents[2]
g=root/'Gateway'; out=pathlib.Path(tempfile.mkdtemp(prefix='mediation-kernel-'))
sources=list((g/'Generated/Mediation').glob('*.c'))+list((g/'Generated/Policy').glob('*.c'))
sources += [g/'Core/gateway_mediation_validator.c',root/'Verification/tools/test_kernel.c']
cmd=['gcc','-std=gnu11','-Os','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',
     '-I'+str(g/'Generated/Mediation'),'-I'+str(g/'Generated/Extractor/krml_include')]+list(map(str,sources))+['-o',str(out/'test')]
subprocess.run(cmd,check=True)
r=subprocess.run([str(out/'test')],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
(root/'Verification/evidence/kernel-tests.log').write_text(r.stdout)
print(r.stdout,end='');raise SystemExit(r.returncode)
