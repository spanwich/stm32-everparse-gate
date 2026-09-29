#!/usr/bin/env python3
"""Repeat a content-length HTTPConnection read to revisit the R1 soak stall."""
from pathlib import Path
import argparse
import csv
import http.client
import time

p = argparse.ArgumentParser()
p.add_argument('--count', type=int, default=1000)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.parent.mkdir(parents=True, exist_ok=True)
with a.output.open('w', newline='') as stream:
    writer = csv.writer(stream)
    writer.writerow(('index', 'status', 'body_bytes', 'latency_ms', 'error'))
    for index in range(a.count):
        start = time.monotonic()
        status, body, error = 0, b'', ''
        conn = http.client.HTTPConnection('192.168.40.128', 80, timeout=8)
        try:
            conn.request('GET', '/api/status', headers={
                'Authorization': 'Bearer pg-lab-operator'})
            response = conn.getresponse()
            status, body = response.status, response.read()
            assert status == 200 and body == b'{"status":"ok","role":"OPERATOR"}'
        except Exception as exc:
            error = type(exc).__name__ + ': ' + str(exc)
        finally:
            conn.close()
        writer.writerow((index, status, len(body),
                         round((time.monotonic() - start) * 1000, 3), error))
        if index % 100 == 0:
            stream.flush()
            print(index, 'requests', flush=True)
        if error:
            raise SystemExit(f'failed at {index}: {error}')
print(f'PASS {a.count} HTTPConnection requests')
