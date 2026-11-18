"""Run every emulator test suite and check the committed binary hashes.

    uv run --with unicorn==2.1.4 python test.py

The suites load the compiled EFI images into the Unicorn CPU emulator with
simulated UEFI services and a model of the EC. Nothing touches real hardware.
"""
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
failed = False
for line in (ROOT / 'SHA256SUMS.txt').read_text().splitlines():
    expected, name = line.split()
    actual = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
    print(f'{"OK  " if actual == expected else "FAIL"} {name}', flush=True)
    failed |= actual != expected
for tool in ('EcQuery', 'EcRead', 'EcEnable'):
    print(f'--- {tool} emulator tests', flush=True)
    r = subprocess.run([sys.executable, str(ROOT / 'tools' / tool / 'emulate.py')])
    failed |= r.returncode != 0
sys.exit(1 if failed else 0)
