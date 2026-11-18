// Independently implemented from protocol observations in NWEC27WW and
// tomios/ITE_ECTool and hz12opensource/zenbook-q410-powerfix.
// No erase, programming, write-enable, status-write, unlock or variable writes.
#include <Uefi.h>
#include <IndustryStandard/SmBios.h>
#include <Protocol/Smbios.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include <Library/BaseLib.h>
#include <Library/IoLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include "Target.inc"
#include "Expected.inc"
STATIC EFI_GUID LoadedGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
STATIC EFI_GUID FsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
STATIC EFI_GUID * volatile LoadedGuidPointer = &LoadedGuid;
STATIC UINT8 First[1024], Second[1024], Header[32], Id[3];
// Each wait is bounded to 2500 polls (about 250 ms). The aggregate budget is
// only a backstop against a wedged-but-responsive EC: a normal capture is about
// 4300 handshakes, so it must tolerate several 100 us stalls per handshake.
// Exhausting it mid-session strands the EC in the utility, so keep it generous.
#define CAPTURE_BUDGET 300000
#define EXIT_BUDGET 50000
STATIC UINTN Budget;
STATIC BOOLEAN EnterSent, Synced, Pending, ExitFailed;
STATIC UINT8 SafePayload;

// All physical writes go to the command port, including SPI/address payloads.
// An ambiguous post-write timeout stops further commands: blindly retrying a
// two-stage protocol could interpret an exit byte as a SPI opcode or payload.
STATIC EFI_STATUS Idle(VOID) {
  UINTN I;
  for (I=0; I<2500 && Budget; ++I) {
    if (!(IoRead8(0x66)&2)) return EFI_SUCCESS;
    --Budget; gBS->Stall(100);
  }
  return EFI_TIMEOUT;
}
STATIC EFI_STATUS Send(UINT8 V) {
  EFI_STATUS S=Idle();
  if (EFI_ERROR(S)) return S;
  IoWrite8(0x66,V);
  if (V==0xDC && !EnterSent) EnterSent=TRUE;
  S=Idle();
  if (EFI_ERROR(S)) Synced=FALSE;
  return S;
}
STATIC EFI_STATUS Receive(UINT8 *V) {
  UINTN I; UINT8 S;
  for (I=0; I<2500 && Budget; ++I) {
    S=IoRead8(0x66);
    if ((S&3)==1) { *V=IoRead8(0x62); return EFI_SUCCESS; }
    --Budget; gBS->Stall(100);
  }
  // A delayed response could contaminate another transaction.
  Synced=FALSE;
  return EFI_TIMEOUT;
}
#define STEP(X) do { EFI_STATUS StepStatus=(X); if(EFI_ERROR(StepStatus)) return StepStatus; } while(0)
STATIC EFI_STATUS Pair(UINT8 Prefix,UINT8 Payload) {
  STEP(Send(Prefix));
  Pending=TRUE; SafePayload=(Prefix==2)?5:0;
  STEP(Send(Payload));
  Pending=FALSE;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS ReadByte(UINT8 *V) { STEP(Send(4)); return Receive(V); }
STATIC EFI_STATUS ReadId(VOID) {
  UINTN I;
  STEP(Send(1)); STEP(Pair(2,0x9F));
  for(I=0;I<3;++I) STEP(ReadByte(&Id[I]));
  return Send(5);
}
STATIC EFI_STATUS ReadRange(UINT32 Address,UINT8 *Buffer,UINTN Size) {
  UINTN I;
  // No arbitrary caller-controlled ranges: exactly header or final 1 KiB.
  if (!((Address==0 && Size==32)||(Address==0x1FC00 && Size==1024))) return EFI_INVALID_PARAMETER;
  STEP(Send(1)); STEP(Pair(2,0x0B));
  STEP(Pair(3,(UINT8)(Address>>16)));
  STEP(Pair(3,(UINT8)(Address>>8)));
  STEP(Pair(3,(UINT8)Address)); STEP(Pair(3,0));
  for(I=0;I<Size;++I) STEP(ReadByte(&Buffer[I]));
  return Send(5);
}
STATIC EFI_STATUS Leave(VOID) {
  EFI_STATUS S;
  if (!EnterSent) return EFI_SUCCESS;
  if (!Synced) return EFI_DEVICE_ERROR;
  Budget=EXIT_BUDGET;
  if(Pending) {
    S=Send(SafePayload); if(EFI_ERROR(S)) return S;
    Pending=FALSE;
  }
  // No forced reset 0xFE. 0xFC still enters initialization on NWEC27WW.
  S=Send(5); if(EFI_ERROR(S)) return S;
  gBS->Stall(1000000);
  S=Send(0xFC); if(EFI_ERROR(S)) return S;
  gBS->Stall(200000);
  EnterSent=FALSE;
  return EFI_SUCCESS; // Command accepted, NOT proof of resumed EC services.
}
STATIC EFI_STATUS CaptureLocked(VOID) {
  UINTN I; UINT8 Ack;
  EFI_STATUS S,ExitStatus;
  Budget=CAPTURE_BUDGET; Synced=TRUE; EnterSent=FALSE; Pending=FALSE; ExitFailed=FALSE;
  // Refuse pending output rather than draining someone else's transaction.
  for(I=0;I<100;++I) {
    if(IoRead8(0x66)&3) return EFI_NOT_READY;
    gBS->Stall(100);
  }
  if(IoRead8(0x66)&3) return EFI_NOT_READY;
  S=Send(0xDC);
  if(!EFI_ERROR(S)) S=Receive(&Ack);
  if(!EFI_ERROR(S) && Ack!=0x33) { Synced=FALSE; S=EFI_DEVICE_ERROR; }
  if(!EFI_ERROR(S)) S=ReadId();
  // Conservative allowlist from the reference's reported internal-flash ID.
  // This does NOT identify the precise EC silicon or measure erase geometry.
  if(!EFI_ERROR(S) && !(Id[0]==0xFF && Id[1]==0xFF && Id[2]==0xFE)) S=EFI_UNSUPPORTED;
  if(!EFI_ERROR(S)) S=ReadRange(0,Header,32);
  if(!EFI_ERROR(S)) for(I=0;I<32;++I) if(Header[I]!=Expected[I]) {S=EFI_COMPROMISED_DATA;break;}
  if(!EFI_ERROR(S)) S=ReadRange(0x1FC00,First,1024);
  if(!EFI_ERROR(S)) S=ReadRange(0x1FC00,Second,1024);
  if(!EFI_ERROR(S)) for(I=0;I<1024;++I) if(First[I]!=Second[I]) {S=EFI_COMPROMISED_DATA;break;}
  ExitStatus=Leave();
  if(EFI_ERROR(ExitStatus)) { ExitFailed=TRUE; return ExitStatus; }
  return S;
}
// TPL_NOTIFY masks every firmware event notification (driver timers that may
// poll the EC on 62/66) for the whole utility session, while the timer tick
// and Stall keep working. It cannot mask SMM. Console output and file I/O
// happen only after the previous TPL is restored.
STATIC EFI_STATUS Capture(VOID) {
  EFI_TPL OldTpl;
  EFI_STATUS S;
  OldTpl=gBS->RaiseTPL(TPL_NOTIFY);
  S=CaptureLocked();
  gBS->RestoreTPL(OldTpl);
  if(ExitFailed) Print(L"EC exit NOT confirmed; no file saved. Do not retry automatically.\n");
  return S;
}
STATIC UINT32 Crc(CONST UINT8 *P,UINTN N) {
  UINT32 C=0xFFFFFFFF; UINTN I,J;
  for(I=0;I<N;++I) { C^=P[I]; for(J=0;J<8;++J) C=(C>>1)^((C&1)?0xEDB88320:0); }
  return ~C;
}
STATIC EFI_STATUS Save(EFI_FILE_PROTOCOL *Root) {
  CHAR16 Name[]=L"EC01FC00-00.bin";
  EFI_FILE_PROTOCOL *F; EFI_STATUS S,CloseStatus; UINTN I,N;
  for(I=0;I<100;++I) {
    Name[9]=(CHAR16)(L'0'+I/10); Name[10]=(CHAR16)(L'0'+I%10);
    S=Root->Open(Root,&F,Name,EFI_FILE_MODE_READ,0);
    if(!EFI_ERROR(S)) { F->Close(F); continue; }
    if(S!=EFI_NOT_FOUND) return S;
    S=Root->Open(Root,&F,Name,EFI_FILE_MODE_READ|EFI_FILE_MODE_WRITE|EFI_FILE_MODE_CREATE,0);
    if(EFI_ERROR(S)) return S;
    N=1024; S=F->Write(F,&N,First);
    if(!EFI_ERROR(S) && N!=1024) S=EFI_DEVICE_ERROR;
    if(!EFI_ERROR(S)) S=F->Flush(F);
    CloseStatus=F->Close(F);
    if(!EFI_ERROR(S)) S=CloseStatus;
    if(!EFI_ERROR(S)) Print(L"Saved EC01FC00-%02u.bin on the EFI application's volume.\n",(UINT32)I);
    else Print(L"File write failed; a partial file may remain.\n");
    return S;
  }
  return EFI_VOLUME_FULL;
}
EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle,EFI_SYSTEM_TABLE *SystemTable) {
  EFI_STATUS S; EFI_INPUT_KEY Key; UINTN Index;
  EFI_LOADED_IMAGE_PROTOCOL *Loaded;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs; EFI_FILE_PROTOCOL *Root;
  gST=SystemTable;gBS=SystemTable->BootServices;gRT=SystemTable->RuntimeServices;
  Print(L"NWCN27WW experimental flash reader: OFFLINE TESTED ONLY.\n");
  if(!TargetMatches()) return EFI_UNSUPPORTED;
  S=gBS->HandleProtocol(ImageHandle,LoadedGuidPointer,(VOID **)&Loaded);
  if(EFI_ERROR(S)) return S;
  S=gBS->HandleProtocol(Loaded->DeviceHandle,&FsGuid,(VOID **)&Fs);
  if(EFI_ERROR(S)) return S;
  S=Fs->OpenVolume(Fs,&Root); if(EFI_ERROR(S)) return S;
  Print(L"Reads flash ID, 32-byte header and sector 01FC00..01FFFF twice.\n");
  Print(L"No host flash-write commands. EC servicing pauses; exit initializes EC.\n");
  Print(L"Read-only host commands do not prevent firmware's own storage maintenance.\n");
  Print(L"No EC ports accessed yet. Uppercase R starts; any other key cancels.\n");
  S=gBS->WaitForEvent(1,&gST->ConIn->WaitForKey,&Index);
  if(!EFI_ERROR(S)) S=gST->ConIn->ReadKeyStroke(gST->ConIn,&Key);
  if(EFI_ERROR(S)||Key.UnicodeChar!=L'R') {Root->Close(Root);return EFI_ABORTED;}
  S=Capture();
  Print(L"JEDEC response %02x %02x %02x; capture status %r\n",(UINT32)Id[0],(UINT32)Id[1],(UINT32)Id[2],S);
  if(!EFI_ERROR(S)) {
    Print(L"Two reads match. CRC32 %08x (file integrity only).\n",Crc(First,1024));
    Print(L"Exit command accepted; normal EC service resumption is not verified.\n");
    S=Save(Root);
  }
  Root->Close(Root);
  return S;
}
