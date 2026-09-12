#!/usr/bin/env python3
"""Deterministically embed the maintained HTML. --check rejects stale output."""
from pathlib import Path
import argparse
p=argparse.ArgumentParser(); p.add_argument('--check',action='store_true'); a=p.parse_args()
g=Path(__file__).resolve().parents[1]
text='/* Generated from Gateway/Web assets by embed_dashboard.py. */\n'
for name,symbol in [('dashboard.html','gateway_dashboard'),('dashboard.js','gateway_dashboard_js')]:
 data=(g/'Web'/name).read_bytes()
 assert len(data)<=16384, 'Static asset exceeds bounded flash response size'
 text+='static const unsigned char '+symbol+'[] = {\n'
 text+='\n'.join('    '+','.join(str(b) for b in data[i:i+24])+',' for i in range(0,len(data),24))
 text+='\n};\n'
 print(name,len(data),'bytes')
out=g/'Web/dashboard_html.h'
if a.check: assert out.read_text()==text, 'Run Gateway/tools/embed_dashboard.py'
elif not out.exists() or out.read_text()!=text: out.write_text(text)
print('Dashboard embedding PASS')
