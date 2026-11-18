import struct, json, hashlib, sys
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_INSN
from unicorn.x86_const import *
P=Path(__file__).with_name('EcQuery.efi')
b=P.read_bytes(); pe=struct.unpack_from('<I',b,60)[0]; opt=pe+24
base=struct.unpack_from('<Q',b,opt+24)[0]; entry=struct.unpack_from('<I',b,opt+16)[0]
size=struct.unpack_from('<I',b,opt+56)[0]; hs=struct.unpack_from('<I',b,opt+60)[0]
sections=[]
for i in range(struct.unpack_from('<H',b,pe+6)[0]):
 p=opt+struct.unpack_from('<H',b,pe+20)[0]+40*i
 vs,va,rs,rp=struct.unpack_from('<IIII',b,p+8);sections.append((va,rp,rs))
ERR=1<<63
def run(name,**c):
 load=c.get('load',base)
 u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(load,(size+4095)&~4095);u.mem_write(load,b[:hs])
 for va,rp,rs in sections:
  if rs:u.mem_write(load+va,b[rp:rp+rs])
 if load!=base:
  reloc,length=struct.unpack_from('<II',b,opt+112+8*5);assert reloc and length
  pos=0
  while pos<length:
   page,block=struct.unpack('<II',u.mem_read(load+reloc+pos,8));assert block>=8
   for off in range(8,block,2):
    item=struct.unpack('<H',u.mem_read(load+reloc+pos+off,2))[0]
    typ=item>>12
    if typ==0:continue
    assert typ==10
    at=load+page+(item&4095);v=struct.unpack('<Q',u.mem_read(at,8))[0]
    u.mem_write(at,struct.pack('<Q',v+load-base))
   pos+=block
 u.mem_map(0x100000,0x100000);u.mem_map(0x300000,0x10000);u.mem_map(0x400000,0x10000)
 def wq(a,v):u.mem_write(a,struct.pack('<Q',v))
 def rq(a):return struct.unpack('<Q',u.mem_read(a,8))[0]
 def reg(r):return u.reg_read(r)
 def str16(a):
  out=[]
  for i in range(2048):
   n=struct.unpack('<H',u.mem_read(a+2*i,2))[0]
   if not n:return ''.join(out)
   out.append(chr(n))
  raise AssertionError('unterminated string')
 st=0x300000;bs=0x301000;rt=0x302000;cin=0x303000;cout=0x304000;smb=0x305000
 callbacks={};outputs=[];reads=[];writes=[];calls=[];status_count=0
 def cb(offset,fn):
  a=0x400000+offset;u.mem_write(a,b'\xc3');callbacks[a]=fn;return a
 def output():outputs.append(str16(reg(UC_X86_REG_RDX)));return 0
 def locate():
  if c.get('no_smb'):return ERR|14
  wq(reg(UC_X86_REG_R8),smb);return 0
 bios=bytearray(26);bios[0]=0;bios[1]=26;bios[5]=1;bios[22]=1;bios[23]=27
 bios+=c.get('bios','NWCN27WW').encode()+b'\0\0'
 model=bytearray(27);model[0]=1;model[1]=27;model[4]=1;model[5]=2
 model+=b'LENOVO\0'+c.get('model','83DL').encode()+b'\0\0'
 u.mem_write(0x306000,bytes(bios));u.mem_write(0x307000,bytes(model));cursor=0
 def next_smb():
  nonlocal cursor
  if cursor>=2:return ERR|14
  wq(reg(UC_X86_REG_R9),[0x306000,0x307000][cursor]);cursor+=1
  u.mem_write(reg(UC_X86_REG_RDX),struct.pack('<H',cursor));return 0
 def variable():
  assert str16(reg(UC_X86_REG_RCX))=='CrbItem'
  assert bytes(u.mem_read(reg(UC_X86_REG_RDX),16))==bytes.fromhex('af49c7c2d6124a48a39a81d1c1f04eed')
  s=c.get('variable_status',0)
  if s:return s
  data=c.get('data',b'\x17');capacity=rq(reg(UC_X86_REG_R9));wq(reg(UC_X86_REG_R9),len(data))
  if len(data)>capacity:return ERR|5
  u.mem_write(reg(UC_X86_REG_R8),struct.pack('<I',7))
  u.mem_write(rq(reg(UC_X86_REG_RSP)+40),data);return 0
 def key():
  if c.get('key_error'):return ERR|6
  u.mem_write(reg(UC_X86_REG_RDX),struct.pack('<HH',0,ord(c.get('key','Q'))));return 0
 def wait():wq(reg(UC_X86_REG_R8),0);return 0
 wq(st+48,cin);wq(st+64,cout);wq(st+88,rt);wq(st+96,bs)
 wq(cout+8,cb(0x100,output));wq(cin+8,cb(0x200,key));wq(cin+16,0x1234)
 wq(bs+320,cb(0x300,locate));wq(bs+96,cb(0x400,wait));wq(bs+248,cb(0x500,lambda:0))
 wq(rt+72,cb(0x600,variable));wq(smb+24,cb(0x700,next_smb))
 def hook(u,a,n,d):
  if a==0x40f000:u.emu_stop();return
  if a in callbacks:
   calls.append(a);res=callbacks[a]();u.reg_write(UC_X86_REG_RAX,res)
   sp=reg(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RIP,rq(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 def ins(u,port,n,d):
  nonlocal status_count
  assert n==1 and port in (0x66,0x62),(port,n)
  reads.append(port)
  if port==0x62:return c.get('response',0xEE)
  status_count+=1
  if not writes:
   if c.get('busy') or (c.get('race') and status_count==101):return 3
   return 0
  return 0 if c.get('timeout') else 1
 def outs(u,port,n,value,d):
  assert (port,n,value)==(0x66,1,0x41),(port,n,value)
  writes.append((port,value));assert len(writes)==1
 u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_INSN,ins,None,1,0,UC_X86_INS_IN)
 u.hook_add(UC_HOOK_INSN,outs,None,1,0,UC_X86_INS_OUT)
 sp=0x1ff008;wq(sp,0x40f000);u.reg_write(UC_X86_REG_RSP,sp)
 u.reg_write(UC_X86_REG_RCX,0x123);u.reg_write(UC_X86_REG_RDX,st)
 u.emu_start(load+entry,0,count=10000000)
 assert reg(UC_X86_REG_RIP)==0x40f000,(name,'Did not terminate',hex(reg(UC_X86_REG_RIP)),''.join(outputs)[-2000:],len(reads),len(writes),len(calls))
 result=reg(UC_X86_REG_RAX);text=''.join(outputs)
 expected=c.get('expect',0);assert result==expected,(name,hex(result),hex(expected),text)
 assert len(writes)==c.get('writes',1),(name,writes,text)
 if c.get('no_io'):assert not reads and not writes
 if c.get('busy') or c.get('race') or c.get('timeout'):assert 0x62 not in reads
 if 'contains' in c:assert c['contains'] in text,(name,text)
 return {'test':name,'status':hex(result),'IN_count':len(reads),'OUT_count':len(writes),'output':text}
cases=[
 ('enabled',{}),('disabled',{'response':0}),
 ('unexpected_response',{'response':0x55,'expect':ERR|7}),
 ('cancel',{'key':'x','expect':ERR|21,'writes':0,'no_io':True}),
 ('lowercase_q',{'key':'q','expect':ERR|21,'writes':0,'no_io':True}),
 ('key_error',{'key_error':True,'expect':ERR|21,'writes':0,'no_io':True}),
 ('wrong_model',{'model':'83DJ','expect':ERR|3,'writes':0,'no_io':True}),
 ('wrong_bios',{'bios':'NWCN99WW','expect':ERR|3,'writes':0,'no_io':True}),
 ('no_smbios',{'no_smb':True,'expect':ERR|3,'writes':0,'no_io':True}),
 ('busy',{'busy':True,'expect':ERR|6,'writes':0}),
 ('busy_at_send',{'race':True,'expect':ERR|6,'writes':0}),
 ('timeout',{'timeout':True,'expect':ERR|18}),
 ('absent_variable',{'variable_status':ERR|14,'contains':'Variable absent'}),
 ('denied_variable',{'variable_status':ERR|26,'contains':'Not a successful snapshot'}),
 ('oversize_variable',{'data':b'\x17'*1025,'contains':'Not a successful snapshot'}),
 ('variable_bytes',{'data':b'\x16\x00\xff','contains':'16 00 FF'}),
 ('relocated_image',{'load':0x60000000}),
]
results=[run(n,**c) for n,c in cases]
out={'sha256':hashlib.sha256(b).hexdigest(),'method':'Unicorn CPU emulation of actual EFI binary with synthetic UEFI services and emulated IN/OUT; no hardware I/O','results':results}
Path(__file__).with_name('emulation-results.json').write_text(json.dumps(out,indent=2))
print('PASS:',len(results),'compiled-image emulation scenarios; no real hardware I/O')
