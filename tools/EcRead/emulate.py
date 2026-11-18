import struct, json, hashlib, sys
from pathlib import Path
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_INSN
from unicorn.x86_const import *
P=Path(__file__).with_name('EcRead.efi')
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
 tpl=4;max_tpl=4;stalls=0;lag=0;rx_lag=0;latency=c.get('latency',0)
 check_tpl=c.get('check_tpl',True)
 def cb(offset,fn):
  a=0x400000+offset;u.mem_write(a,b'\xc3');callbacks[a]=fn;return a
 def output():
  if check_tpl:assert tpl==4,('console output at raised TPL',tpl)
  outputs.append(str16(reg(UC_X86_REG_RDX)));return 0
 def raise_tpl():
  nonlocal tpl,max_tpl
  new=reg(UC_X86_REG_RCX);assert new>=tpl and new in (8,16,31),('bad RaiseTPL',new,tpl)
  old=tpl;tpl=new;max_tpl=max(max_tpl,new);return old
 def restore_tpl():
  nonlocal tpl
  old=reg(UC_X86_REG_RCX);assert old<=tpl,('bad RestoreTPL',old,tpl)
  tpl=old;return 0
 def stall():
  nonlocal stalls
  stalls+=1;return 0
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
  u.mem_write(reg(UC_X86_REG_RDX),struct.pack('<HH',0,ord(c.get('key','R'))));return 0
 def wait():wq(reg(UC_X86_REG_R8),0);return 0
 wq(st+48,cin);wq(st+64,cout);wq(st+88,rt);wq(st+96,bs)
 wq(cout+8,cb(0x100,output));wq(cin+8,cb(0x200,key));wq(cin+16,0x1234)
 wq(bs+320,cb(0x300,locate));wq(bs+96,cb(0x400,wait));wq(bs+248,cb(0x500,stall))
 wq(bs+24,cb(0xf00,raise_tpl));wq(bs+32,cb(0xf10,restore_tpl))
 wq(rt+72,cb(0x600,variable));wq(smb+24,cb(0x700,next_smb))
 def hook(u,a,n,d):
  if a==0x40f000:u.emu_stop();return
  if a in callbacks:
   calls.append(a);res=callbacks[a]();u.reg_write(UC_X86_REG_RAX,res)
   sp=reg(UC_X86_REG_RSP);u.reg_write(UC_X86_REG_RIP,rq(sp));u.reg_write(UC_X86_REG_RSP,sp+8)
 # Mock file system; all callbacks are emulated, never real hardware/filesystem.
 loaded=0x308000;fs=0x309000;root=0x30a000;file=0x30b000
 wq(loaded+24,0x456)
 util=False;follow=False;pending=None;opcode=None;addr=[];pos=0;passno=0
 queue=[];saved=None;saved_name=None;created=[];exits=0;spi=[]
 expected=bytes.fromhex('020070020022220235502202051e023556222202055502355c22220205b60235')
 sector=bytes((i*37+11)&255 for i in range(1024))
 if c.get('blank'):sector=bytes([255])*1024
 def handle():
  if c.get('no_fs'):return ERR|3
  wq(reg(UC_X86_REG_R8),loaded if reg(UC_X86_REG_RCX)==0x123 else fs);return 0
 def volume():wq(reg(UC_X86_REG_RDX),root);return c.get('volume_error',0)
 def fopen():
  nonlocal saved_name
  name=str16(reg(UC_X86_REG_R8));mode=reg(UC_X86_REG_R9)
  assert not util,'file access before exit'
  if check_tpl:assert tpl==4,('file access at raised TPL',tpl)
  if mode==1:
   if c.get('all_exist') or (c.get('exists') and name.endswith('-00.bin')):
    wq(reg(UC_X86_REG_RDX),file);return 0
   return ERR|14
  assert mode==0x8000000000000003
  if c.get('readonly'):return ERR|8
  saved_name=name;created.append(name);wq(reg(UC_X86_REG_RDX),file);return 0
 def fwrite():
  nonlocal saved
  assert not util and exits==1
  n=rq(reg(UC_X86_REG_RDX));assert n==1024
  saved=bytes(u.mem_read(reg(UC_X86_REG_R8),n));assert saved==sector
  if c.get('short_write'):wq(reg(UC_X86_REG_RDX),n-1)
  return 0
 wq(bs+152,cb(0x800,handle));wq(fs+8,cb(0x900,volume))
 wq(root+8,cb(0xa00,fopen));wq(root+16,cb(0xb00,lambda:0))
 wq(file+16,cb(0xc00,lambda:0));wq(file+40,cb(0xd00,fwrite))
 wq(file+80,cb(0xe00,lambda:c.get('flush_error',0)))
 def ins(u,port,n,d):
  nonlocal status_count,lag,rx_lag
  assert n==1 and port in (0x66,0x62)
  if check_tpl:assert tpl==16,('EC port read outside TPL_NOTIFY',tpl)
  reads.append(port)
  if port==0x62:
   assert queue,'read without emulated response'
   return queue.pop(0)
  status_count+=1
  if not writes:
   if c.get('busy') or (c.get('race') and status_count==101):return 3
   return 0
  if c.get('stuck_after')==len(writes):return 2
  if lag:lag-=1;return 2
  if queue and rx_lag:rx_lag-=1;return 0
  return 1 if queue else 0
 def outs(u,port,n,v,d):
  nonlocal util,follow,pending,opcode,addr,pos,passno,exits
  nonlocal lag,rx_lag
  assert (port,n)==(0x66,1)
  if check_tpl:assert tpl==16,('EC port write outside TPL_NOTIFY',tpl)
  writes.append((port,v));lag=latency;rx_lag=latency
  if not util:
   assert v==0xdc and len(writes)==1
   util=True
   if not c.get('ack_timeout'):queue.append(c.get('ack',0x33))
   return
  if pending:
   if pending=='op':
    assert v in (0x9f,0x0b,5),('forbidden SPI command',hex(v))
    opcode=v;spi.append(v);pos=0;addr=[]
   else:
    assert opcode==0x0b
    addr.append(v)
    if len(addr)==4:
     a=(addr[0]<<16)|(addr[1]<<8)|addr[2]
     assert a in (0,0x1fc00) and addr[3]==0
     if a==0x1fc00:passno+=1
   pending=None;return
  assert v in (1,2,3,4,5,0xfc),('unexpected utility command',hex(v))
  if v==1:follow=True;opcode=None;addr=[];pos=0
  elif v==2:assert follow;pending='op'
  elif v==3:assert follow;pending='byte'
  elif v==4:
   assert follow
   if c.get('read_timeout') and opcode==0x0b:return
   if opcode==0x9f:byte=c.get('id',bytes.fromhex('fffffe'))[pos]
   else:
    assert opcode==0x0b and len(addr)==4
    a=(addr[0]<<16)|(addr[1]<<8)|addr[2]
    byte=(expected if a==0 else sector)[pos]
    if (c.get('bad_header') and a==0 and pos==0) or (c.get('mismatch') and passno==2 and pos==17):byte^=1
   queue.append(byte);pos+=1
  elif v==5:follow=False
  elif v==0xfc:
   assert not follow
   util=False;exits+=1
 u.hook_add(UC_HOOK_CODE,hook);u.hook_add(UC_HOOK_INSN,ins,None,1,0,UC_X86_INS_IN)
 u.hook_add(UC_HOOK_INSN,outs,None,1,0,UC_X86_INS_OUT)
 sp=0x1ff008;wq(sp,0x40f000);u.reg_write(UC_X86_REG_RSP,sp)
 u.reg_write(UC_X86_REG_RCX,0x123);u.reg_write(UC_X86_REG_RDX,st)
 u.emu_start(load+entry,0,count=200000000)
 assert reg(UC_X86_REG_RIP)==0x40f000,(name,'Did not terminate',hex(reg(UC_X86_REG_RIP)),''.join(outputs)[-2000:],len(reads),len(writes),len(calls))
 result=reg(UC_X86_REG_RAX);text=''.join(outputs)
 if check_tpl:assert tpl==4,('TPL not restored',tpl)
 if check_tpl and writes:assert max_tpl==16,('EC session not at TPL_NOTIFY',max_tpl)
 expected=c.get('expect',0);assert result==expected,(name,hex(result),hex(expected),text)
 if c.get('no_io'):assert not reads and not writes
 if c.get('save',True):
  assert saved==sector and saved_name==('EC01FC00-01.bin' if c.get('exists') else 'EC01FC00-00.bin')
 else:
  if not c.get('short_write') and not c.get('flush_error'):assert saved is None
 if c.get('no_exit'):assert exits==0
 elif writes:assert exits==1
 if c.get('contains'):assert c['contains'] in text
 return {'test':name,'status':hex(result),'IN_count':len(reads),'OUT_count':len(writes),
         'SPI_opcodes':[hex(v) for v in spi],'exit_commands':exits,'saved_name':saved_name,'stalls':stalls,'max_tpl':max_tpl,'output':text}
cases=[
 ('normal',{}),('blank_sector',{'blank':True}),('existing_file',{'exists':True}),
 ('relocated',{'load':0x60000000}),
 ('cancel',{'key':'x','expect':ERR|21,'save':False,'no_io':True}),
 ('lowercase_r',{'key':'r','expect':ERR|21,'save':False,'no_io':True}),
 ('key_error',{'key_error':True,'expect':ERR|21,'save':False,'no_io':True}),
 ('wrong_model',{'model':'83DJ','expect':ERR|3,'save':False,'no_io':True}),
 ('model_suffix_rejected',{'model':'83DLxxxx','expect':ERR|3,'save':False,'no_io':True}),
 ('wrong_bios',{'bios':'NWCN99WW','expect':ERR|3,'save':False,'no_io':True}),
 ('bios_suffix_rejected',{'bios':'NWCN27WWx','expect':ERR|3,'save':False,'no_io':True}),
 ('no_smbios',{'no_smb':True,'expect':ERR|3,'save':False,'no_io':True}),
 ('no_filesystem',{'no_fs':True,'expect':ERR|3,'save':False,'no_io':True}),
 ('volume_error',{'volume_error':ERR|7,'expect':ERR|7,'save':False,'no_io':True}),
 ('busy',{'busy':True,'expect':ERR|6,'save':False}),
 ('entry_race',{'race':True,'expect':ERR|6,'save':False}),
 ('ack_timeout',{'ack_timeout':True,'expect':ERR|7,'save':False,'no_exit':True}),
 ('bad_ack',{'ack':0x55,'expect':ERR|7,'save':False,'no_exit':True}),
 ('unknown_id',{'id':bytes.fromhex('ffffff'),'expect':ERR|3,'save':False}),
 ('header_mismatch',{'bad_header':True,'expect':ERR|33,'save':False}),
 ('sector_mismatch',{'mismatch':True,'expect':ERR|33,'save':False}),
 ('read_timeout',{'read_timeout':True,'expect':ERR|7,'save':False,'no_exit':True}),
 ('readonly_volume',{'readonly':True,'expect':ERR|8,'save':False}),
 ('all_names_used',{'all_exist':True,'expect':ERR|11,'save':False}),
 ('short_write',{'short_write':True,'expect':ERR|7,'save':False}),
 ('flush_error',{'flush_error':ERR|7,'expect':ERR|7,'save':False}),
]
for n in (1,2,3,4,8,9,10,11,12,13,14,15,16,17,18,40,80,100,1100,2125):
 cases.append(('post_write_timeout_'+str(n),{'stuck_after':n,'expect':ERR|(18 if n==2125 else 7),'save':False,'no_exit':True}))
cases.append(('exit_acceptance_timeout',{'stuck_after':2126,'expect':ERR|18,'save':False}))
for n in (5,20,60):cases.append(('slow_ec_latency_'+str(n),{'latency':n}))
cases.append(('slow_ec_budget_exhausted',{'latency':2400,'expect':ERR|7,'save':False,'no_exit':True,
              'contains':'EC exit NOT confirmed'}))
only=sys.argv[1:]
results=[run(n,**c) for n,c in cases if not only or n in only]
out={'sha256':hashlib.sha256(b).hexdigest(),'method':'Actual EFI x64 binary in Unicorn; synthetic UEFI services and stateful protocol model; NO REAL EC ACCESS','results':results}
if not only:Path(__file__).with_name('emulation-results.json').write_text(json.dumps(out,indent=2))
print('PASS:',len(results),'compiled-image emulation scenarios; no real hardware I/O')
