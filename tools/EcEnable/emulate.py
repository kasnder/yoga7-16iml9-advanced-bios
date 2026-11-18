"""Run the compiled EcEnable.efi in Unicorn with synthetic UEFI services and a
stateful model of the NWEC27WW 0x40/0x41/0x42 handlers. NO REAL EC ACCESS."""
import struct, json, hashlib, sys
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_INSN
from unicorn.x86_const import *

P = Path(__file__).with_name('EcEnable.efi')
b = P.read_bytes(); pe = struct.unpack_from('<I', b, 60)[0]; opt = pe + 24
base = struct.unpack_from('<Q', b, opt + 24)[0]; entry = struct.unpack_from('<I', b, opt + 16)[0]
size = struct.unpack_from('<I', b, opt + 56)[0]; hs = struct.unpack_from('<I', b, opt + 60)[0]
sections = []
for i in range(struct.unpack_from('<H', b, pe + 6)[0]):
    p = opt + struct.unpack_from('<H', b, pe + 20)[0] + 40 * i
    vs, va, rs, rp = struct.unpack_from('<IIII', b, p + 8); sections.append((va, rp, rs))

ERR = 1 << 63
CRB_GUID = bytes.fromhex('af49c7c2d6124a48a39a81d1c1f04eed')
LIVE = bytes([0]) + b'\xff' * 1023            # EC01FC00-00.bin captured 2026-11-18
ENABLED = bytes([0xCF]) + b'\xff' * 1023
TPL_APP, TPL_NOTIFY = 4, 16


def run(name, **c):
    load = c.get('load', base)
    u = Uc(UC_ARCH_X86, UC_MODE_64); u.mem_map(load, (size + 4095) & ~4095); u.mem_write(load, b[:hs])
    for va, rp, rs in sections:
        if rs: u.mem_write(load + va, b[rp:rp + rs])
    if load != base:
        reloc, length = struct.unpack_from('<II', b, opt + 112 + 8 * 5); assert reloc and length
        pos = 0
        while pos < length:
            page, block = struct.unpack('<II', u.mem_read(load + reloc + pos, 8)); assert block >= 8
            for off in range(8, block, 2):
                item = struct.unpack('<H', u.mem_read(load + reloc + pos + off, 2))[0]
                if item >> 12 == 0: continue
                assert item >> 12 == 10
                at = load + page + (item & 4095); v = struct.unpack('<Q', u.mem_read(at, 8))[0]
                u.mem_write(at, struct.pack('<Q', v + load - base))
            pos += block
    u.mem_map(0x100000, 0x100000); u.mem_map(0x300000, 0x10000); u.mem_map(0x400000, 0x10000)
    wq = lambda a, v: u.mem_write(a, struct.pack('<Q', v))
    rq = lambda a: struct.unpack('<Q', u.mem_read(a, 8))[0]
    reg = u.reg_read

    def str16(a):
        out = []
        for i in range(2048):
            n = struct.unpack('<H', u.mem_read(a + 2 * i, 2))[0]
            if not n: return ''.join(out)
            out.append(chr(n))
        raise AssertionError('unterminated string')

    st, bs, rt, cin, cout, smb = 0x300000, 0x301000, 0x302000, 0x303000, 0x304000, 0x305000
    s = dict(tpl=TPL_APP, max_tpl=TPL_APP, keys=list(c.get('keys', '')), lag=0)
    callbacks = {}; outputs = []; reads = []; writes = []; var_ops = []
    flash = bytearray(c.get('flash', LIVE)); ram = 0xCF if flash[0] == 0xCF else 0
    ec = dict(ram=ram, queue=[])
    var = dict(value=c.get('var'))                 # None or (attributes, bytes)

    def cb(offset, fn):
        a = 0x400000 + offset; u.mem_write(a, b'\xc3'); callbacks[a] = fn; return a

    def app_tpl(what):
        assert s['tpl'] == TPL_APP, (what + ' at raised TPL', s['tpl'])

    def output(): app_tpl('console output'); outputs.append(str16(reg(UC_X86_REG_RDX))); return 0

    def raise_tpl():
        new = reg(UC_X86_REG_RCX); assert new >= s['tpl'] and new == TPL_NOTIFY, new
        old = s['tpl']; s['tpl'] = new; s['max_tpl'] = max(s['max_tpl'], new); return old

    def restore_tpl():
        old = reg(UC_X86_REG_RCX); assert old <= s['tpl']; s['tpl'] = old; return 0

    def key():
        if not s['keys']: return ERR | 6
        u.mem_write(reg(UC_X86_REG_RDX), struct.pack('<HH', 0, ord(s['keys'].pop(0)))); return 0

    def wait(): wq(reg(UC_X86_REG_R8), 0); return 0

    def locate():
        wq(reg(UC_X86_REG_R8), smb); return 0

    bios = bytearray(26); bios[0] = 0; bios[1] = 26; bios[5] = 1; bios[22] = 1; bios[23] = 27
    bios += c.get('bios', 'NWCN27WW').encode() + b'\0\0'
    model = bytearray(27); model[0] = 1; model[1] = 27; model[4] = 1; model[5] = 2
    model += b'LENOVO\0' + c.get('model', '83DL').encode() + b'\0\0'
    u.mem_write(0x306000, bytes(bios)); u.mem_write(0x307000, bytes(model)); cursor = [0]

    def next_smb():
        if cursor[0] >= 2: return ERR | 14
        wq(reg(UC_X86_REG_R9), [0x306000, 0x307000][cursor[0]]); cursor[0] += 1
        u.mem_write(reg(UC_X86_REG_RDX), struct.pack('<H', cursor[0])); return 0

    def check_var_args():
        app_tpl('variable service')
        assert str16(reg(UC_X86_REG_RCX)) == 'CrbItem'
        assert bytes(u.mem_read(reg(UC_X86_REG_RDX), 16)) == CRB_GUID

    def get_variable():
        check_var_args(); var_ops.append('get')
        if var['value'] is None: return ERR | 14
        attr, data = var['value']; cap = rq(reg(UC_X86_REG_R9)); wq(reg(UC_X86_REG_R9), len(data))
        if len(data) > cap: return ERR | 5
        if reg(UC_X86_REG_R8): u.mem_write(reg(UC_X86_REG_R8), struct.pack('<I', attr))
        u.mem_write(rq(reg(UC_X86_REG_RSP) + 40), data); return 0

    def set_variable():
        check_var_args()
        attr, n = reg(UC_X86_REG_R8), reg(UC_X86_REG_R9)
        data = bytes(u.mem_read(rq(reg(UC_X86_REG_RSP) + 40), n)) if n else b''
        var_ops.append(('set', attr, data.hex()))
        if c.get('var_protected'): return ERR | 8
        if n == 0:
            if var['value'] is None: return ERR | 14
            var['value'] = None; return 0
        var['value'] = (attr, bytes([0x17]) if c.get('var_readback_bad') else data); return 0

    def stall(): return 0

    wq(st + 48, cin); wq(st + 64, cout); wq(st + 88, rt); wq(st + 96, bs)
    wq(cout + 8, cb(0x100, output)); wq(cin + 8, cb(0x200, key)); wq(cin + 16, 0x1234)
    wq(bs + 24, cb(0x900, raise_tpl)); wq(bs + 32, cb(0xa00, restore_tpl))
    wq(bs + 96, cb(0x400, wait)); wq(bs + 248, cb(0x500, stall)); wq(bs + 320, cb(0x300, locate))
    wq(rt + 72, cb(0x600, get_variable)); wq(rt + 88, cb(0x800, set_variable))
    wq(smb + 24, cb(0x700, next_smb))

    def hook(u, a, n, d):
        if a == 0x40f000: u.emu_stop(); return
        if a in callbacks:
            res = callbacks[a](); u.reg_write(UC_X86_REG_RAX, res)
            sp = reg(UC_X86_REG_RSP); u.reg_write(UC_X86_REG_RIP, rq(sp)); u.reg_write(UC_X86_REG_RSP, sp + 8)

    def ins(u, port, n, d):
        assert n == 1 and port in (0x66, 0x62)
        assert s['tpl'] == TPL_NOTIFY, ('EC port read outside TPL_NOTIFY', s['tpl'])
        reads.append(port)
        if port == 0x62:
            assert ec['queue'], 'data read without response'
            return ec['queue'].pop(0)
        if not writes and c.get('busy'): return 1
        if c.get('stuck_after') == len(writes): return 2
        if s['lag']: s['lag'] -= 1; return 2
        return 1 if ec['queue'] else 0

    def outs(u, port, n, v, d):
        assert (port, n) == (0x66, 1)
        assert s['tpl'] == TPL_NOTIFY, ('EC port write outside TPL_NOTIFY', s['tpl'])
        assert v in (0x40, 0x41, 0x42), ('forbidden EC command', hex(v))
        writes.append(v)
        cmds = [w for w in writes if w != 0x41]
        assert cmds.count(0x40) <= 1 and cmds.count(0x42) <= 1 and len(cmds) <= 1, writes
        if v == 0x41:
            if not c.get('no_reply'):
                ec['queue'].append(c.get('query_override', 0xEE if ec['ram'] == 0xCF else 0))
            return
        target = 0xCF if v == 0x40 else 0
        if not c.get('ignore_cmd') and ec['ram'] != target:
            ec['ram'] = target                       # RAM first, as traced
            flash[:] = b'\xff' * 1024                 # D7 1 KiB erase
            if not c.get('skip_program'): flash[0] = target
        s['lag'] = c.get('cmd_lag', 0)
        if c.get('unexpected_reply'): ec['queue'].append(0x5A)

    u.hook_add(UC_HOOK_CODE, hook); u.hook_add(UC_HOOK_INSN, ins, None, 1, 0, UC_X86_INS_IN)
    u.hook_add(UC_HOOK_INSN, outs, None, 1, 0, UC_X86_INS_OUT)
    sp = 0x1ff008; wq(sp, 0x40f000); u.reg_write(UC_X86_REG_RSP, sp)
    u.reg_write(UC_X86_REG_RCX, 0x123); u.reg_write(UC_X86_REG_RDX, st)
    u.emu_start(load + entry, 0, count=50000000)
    text = ''.join(outputs)
    assert reg(UC_X86_REG_RIP) == 0x40f000, (name, 'did not terminate', text[-1500:])
    result = reg(UC_X86_REG_RAX)
    assert result == c.get('expect', 0), (name, hex(result), hex(c.get('expect', 0)), text)
    assert s['tpl'] == TPL_APP, (name, 'TPL not restored')
    if writes: assert s['max_tpl'] == TPL_NOTIFY
    if 'writes' in c: assert writes == c['writes'], (name, [hex(w) for w in writes])
    if 'flash_after' in c: assert bytes(flash) == c['flash_after'], (name, flash[:4].hex())
    if 'var_after' in c: assert var['value'] == c['var_after'], (name, var['value'])
    for t in c.get('contains', []): assert t in text, (name, t, text)
    return {'test': name, 'status': hex(result), 'ec_commands': [hex(w) for w in writes],
            'IN_count': len(reads), 'flash_1FC00_first': hex(flash[0]),
            'flash_rest_ff': bytes(flash[1:]) == b'\xff' * 1023, 'ram_flag': hex(ec['ram']),
            'variable_ops': var_ops, 'variable_after': None if var['value'] is None else
            [hex(var['value'][0]), var['value'][1].hex()], 'output': text}


SET = (7, b'\x16')
NO_IO = dict(writes=[], var_after=None, flash_after=LIVE)
cases = [
    ('status_query', dict(keys='S', writes=[0x41], var_after=None, flash_after=LIVE, contains=['gate disabled'])),
    ('cancel', dict(keys='x', expect=ERR | 21, **NO_IO)),
    ('lowercase_e', dict(keys='e', expect=ERR | 21, **NO_IO)),
    ('no_key', dict(keys='', expect=ERR | 21, **NO_IO)),
    ('enable_not_confirmed', dict(keys='En', expect=ERR | 21, **NO_IO)),
    ('disable_not_confirmed', dict(keys='Dy', expect=ERR | 21, **NO_IO)),
    ('wrong_model', dict(keys='EY', model='83DJ', expect=ERR | 3, **NO_IO)),
    ('wrong_bios', dict(keys='EY', bios='NWCN28WW', expect=ERR | 3, **NO_IO)),
    ('enable_normal', dict(keys='EY', writes=[0x41, 0x41, 0x40, 0x41], var_after=SET, flash_after=ENABLED,
                           contains=['CrbItem set to 0x16', 'EcRead.efi'])),
    ('enable_relocated', dict(keys='EY', load=0x60000000, writes=[0x41, 0x41, 0x40, 0x41], var_after=SET,
                              flash_after=ENABLED)),
    ('enable_slow_ec_2s', dict(keys='EY', cmd_lag=20000, writes=[0x41, 0x41, 0x40, 0x41], flash_after=ENABLED)),
    ('enable_already_enabled', dict(keys='EY', flash=ENABLED, var=SET, writes=[0x41], var_after=SET,
                                    flash_after=ENABLED, contains=['0x40 NOT sent'])),
    ('enable_ec_on_variable_absent', dict(keys='EY', flash=ENABLED, writes=[0x41], var_after=SET,
                                          flash_after=ENABLED)),
    ('enable_variable_set_ec_off', dict(keys='EY', var=SET, writes=[0x41, 0x41, 0x40, 0x41], var_after=SET,
                                        flash_after=ENABLED)),
    ('enable_variable_unexpected_value', dict(keys='EY', var=(7, b'\x17'), expect=ERR | 15, writes=[],
                                              var_after=(7, b'\x17'), flash_after=LIVE)),
    ('enable_variable_unexpected_attrs', dict(keys='EY', var=(3, b'\x16'), expect=ERR | 15, writes=[],
                                              var_after=(3, b'\x16'), flash_after=LIVE)),
    ('enable_variable_unexpected_size', dict(keys='EY', var=(7, b'\x16\x00'), expect=ERR | 15, writes=[],
                                             flash_after=LIVE)),
    ('enable_variable_write_protected', dict(keys='EY', var_protected=True, expect=ERR | 8, writes=[0x41],
                                             var_after=None, flash_after=LIVE, contains=['EC NOT touched'])),
    ('enable_variable_readback_bad', dict(keys='EY', var_readback_bad=True, expect=ERR | 33, writes=[0x41],
                                          flash_after=LIVE, contains=['EC NOT touched'])),
    ('enable_ec_busy', dict(keys='EY', busy=True, expect=ERR | 6, writes=[], var_after=None, flash_after=LIVE)),
    ('enable_query_unexpected', dict(keys='EY', query_override=0x55, expect=ERR | 24, writes=[0x41],
                                     var_after=None, flash_after=LIVE, contains=['NO further EC commands'])),
    ('enable_query_timeout', dict(keys='EY', no_reply=True, expect=ERR | 18, writes=[0x41], var_after=None,
                                  flash_after=LIVE)),
    ('enable_command_stuck', dict(keys='EY', stuck_after=3, expect=ERR | 18, writes=[0x41, 0x41, 0x40], var_after=SET,
                                  contains=['NO further EC commands'])),
    ('enable_unexpected_reply', dict(keys='EY', unexpected_reply=True, expect=ERR | 24, writes=[0x41, 0x41, 0x40],
                                     contains=['NO further EC commands'])),
    ('enable_ignored_by_ec', dict(keys='EY', ignore_cmd=True, expect=ERR | 7, writes=[0x41, 0x41, 0x40, 0x41],
                                  flash_after=LIVE, contains=['Do not repeat 0x40'])),
    ('enable_program_skipped', dict(keys='EY', skip_program=True, writes=[0x41, 0x41, 0x40, 0x41],
                                    flash_after=b'\xff' * 1024, contains=['does NOT prove', 'EcRead.efi'])),
    ('disable_restores_live_sector', dict(keys='DY', flash=ENABLED, var=SET, writes=[0x41, 0x42, 0x41],
                                          var_after=None, flash_after=LIVE, contains=['CrbItem deleted'])),
    ('disable_already_disabled', dict(keys='DY', writes=[0x41], var_after=None, flash_after=LIVE,
                                      contains=['0x42 NOT sent', 'already absent'])),
    ('disable_variable_only', dict(keys='DY', var=SET, writes=[0x41], var_after=None, flash_after=LIVE)),
    ('disable_foreign_variable_kept', dict(keys='DY', flash=ENABLED, var=(7, b'\x17'), expect=ERR | 15,
                                           writes=[0x41, 0x42, 0x41], var_after=(7, b'\x17'), flash_after=LIVE)),
    ('disable_command_stuck', dict(keys='DY', flash=ENABLED, var=SET, stuck_after=2, expect=ERR | 18,
                                   writes=[0x41, 0x42], var_after=SET)),
    ('disable_ignored_by_ec', dict(keys='DY', flash=ENABLED, var=SET, ignore_cmd=True, expect=ERR | 7,
                                   writes=[0x41, 0x42, 0x41], var_after=SET, contains=['Do not repeat 0x42'])),
]
only = sys.argv[1:]
results = [run(n, **c) for n, c in cases if not only or n in only]
out = {'sha256': hashlib.sha256(b).hexdigest(),
       'method': 'Actual EFI x64 binary in Unicorn; synthetic UEFI services and stateful EC gate model; NO REAL EC ACCESS',
       'results': results}
if not only: Path(__file__).with_name('emulation-results.json').write_text(json.dumps(out, indent=2) + '\n')
print('PASS:', len(results), 'compiled-image emulation scenarios; no real hardware I/O')
