"""Rebuild the three EFI tools and compare them with the committed binaries.

    python build.py --zig PATH/TO/zig --include PATH/TO/edk2/MdePkg/Include [--install]

Requires Zig 0.13.0 and MdePkg/Include from EDK II edk2-stable202408.
Binaries are written to build/. The comparison ignores only the 4-byte PE
TimeDateStamp, which lld sets from the build time. With --install the
rebuilt binaries replace the committed ones in tools/.
Nothing here executes an EFI image.
"""
import argparse
import hashlib
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOLS = ('EcQuery', 'EcRead', 'EcEnable')
CFLAGS = ['-target', 'x86_64-pc-windows-msvc', '-Dstatic_assert=_Static_assert',
          '-ffreestanding', '-fshort-wchar', '-mno-red-zone', '-fno-stack-protector',
          '-fno-builtin', '-O1', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter']


def without_timestamp(data):
    b = bytearray(data)
    pe = struct.unpack_from('<I', b, 0x3C)[0]
    assert b[pe:pe + 4] == b'PE\0\0', 'not a PE image'
    b[pe + 8:pe + 12] = b'\0\0\0\0'
    return bytes(b)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--zig', required=True, help='Zig 0.13.0 executable')
    p.add_argument('--include', required=True, help='EDK II edk2-stable202408 MdePkg/Include')
    p.add_argument('--install', action='store_true', help='copy rebuilt binaries into tools/')
    a = p.parse_args()
    inc = Path(a.include).resolve()
    version = subprocess.run([a.zig, 'version'], capture_output=True, text=True, check=True).stdout.strip()
    if version != '0.13.0':
        sys.exit(f'Zig 0.13.0 required, found {version}')
    ok = True
    for tool in TOOLS:
        src = ROOT / 'tools' / tool
        out = ROOT / 'build' / tool
        out.mkdir(parents=True, exist_ok=True)
        objs = []
        for name in (tool, 'MinimalRuntime'):
            obj = out / f'{name}.obj'
            subprocess.run([a.zig, 'clang', *CFLAGS, f'-I{inc}', f'-I{inc / "X64"}', '-c',
                            str(src / f'{name}.c'), '-o', str(obj)], check=True)
            objs.append(str(obj))
        efi = out / f'{tool}.efi'
        subprocess.run([a.zig, 'lld-link', '/entry:UefiMain', '/subsystem:efi_application',
                        '/nodefaultlib', '/machine:x64', '/dynamicbase', f'/out:{efi}', *objs], check=True)
        built, committed = efi.read_bytes(), (src / f'{tool}.efi').read_bytes()
        same = without_timestamp(built) == without_timestamp(committed)
        ok &= same or a.install
        print(f'{tool}.efi  sha256 {hashlib.sha256(built).hexdigest()}  '
              f'{"matches committed binary (timestamp ignored)" if same else "DIFFERS from committed binary"}')
        if a.install:
            shutil.copyfile(efi, src / f'{tool}.efi')
    if a.install:
        print('Installed rebuilt binaries into tools/. Update SHA256SUMS.txt and re-run the tests.')
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
