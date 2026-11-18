// Query-only application. See BUILD-AND-TEST.txt for validation limits.
#include <Uefi.h>
#include <IndustryStandard/SmBios.h>
#include <Protocol/Smbios.h>
#include <Library/BaseLib.h>
#include <Library/IoLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

STATIC EFI_GUID mCrbGuid = {0xc2c749af,0x12d6,0x484a,{0xa3,0x9a,0x81,0xd1,0xc1,0xf0,0x4e,0xed}};
// Keep a real relocation so UEFI loaders can relocate this image explicitly.
STATIC EFI_GUID * volatile mCrbGuidPointer = &mCrbGuid;

STATIC CONST CHAR8 *SmbString(EFI_SMBIOS_TABLE_HEADER *H, UINT8 Index) {
  CONST CHAR8 *P = (CONST CHAR8 *)H + H->Length;
  UINTN N = 1, Budget = 4096;
  if (Index == 0) return "";
  while (Budget > 1 && *P != 0) {
    if (N == Index) return P;
    while (Budget > 1 && *P != 0) { ++P; --Budget; }
    ++P; --Budget; ++N;
  }
  return "";
}

STATIC BOOLEAN TargetMatches(VOID) {
  EFI_SMBIOS_PROTOCOL *Smb;
  EFI_SMBIOS_HANDLE Handle = SMBIOS_HANDLE_PI_RESERVED;
  EFI_SMBIOS_TABLE_HEADER *H;
  EFI_STATUS S;
  BOOLEAN BiosOk = FALSE, ModelOk = FALSE;
  S = gBS->LocateProtocol(&gEfiSmbiosProtocolGuid, NULL, (VOID **)&Smb);
  if (EFI_ERROR(S)) { Print(L"SMBIOS unavailable: %r\n", S); return FALSE; }
  while (!EFI_ERROR(Smb->GetNext(Smb, &Handle, NULL, &H, NULL))) {
    if (H->Type == SMBIOS_TYPE_BIOS_INFORMATION && H->Length >= sizeof(SMBIOS_TABLE_TYPE0)) {
      SMBIOS_TABLE_TYPE0 *T = (SMBIOS_TABLE_TYPE0 *)H;
      CONST CHAR8 *V = SmbString(H, T->BiosVersion);
      Print(L"BIOS: %a; SMBIOS EC revision: %u.%u (not independent EC verification)\n",
            V, T->EmbeddedControllerFirmwareMajorRelease, T->EmbeddedControllerFirmwareMinorRelease);
      BiosOk = AsciiStrnCmp(V, "NWCN27WW", 8) == 0;
    }
    if (H->Type == SMBIOS_TYPE_SYSTEM_INFORMATION && H->Length >= sizeof(SMBIOS_TABLE_TYPE1)) {
      SMBIOS_TABLE_TYPE1 *T = (SMBIOS_TABLE_TYPE1 *)H;
      CONST CHAR8 *P = SmbString(H, T->ProductName);
      CONST CHAR8 *M = SmbString(H, T->Manufacturer);
      Print(L"Manufacturer: %a; Product: %a\n", M, P);
      ModelOk = AsciiStrCmp(M, "LENOVO") == 0 && AsciiStrnCmp(P, "83DL", 4) == 0;
    }
  }
  return BiosOk && ModelOk;
}

STATIC VOID ReadCrb(VOID) {
  UINT8 Data[1024];
  UINTN Size = sizeof(Data), I;
  UINT32 Attr = 0;
  EFI_STATUS S = gRT->GetVariable(L"CrbItem", mCrbGuidPointer, &Attr, &Size, Data);
  Print(L"CrbItem GUID: %g\nStatus: %r\n", mCrbGuidPointer, S);
  if (S == EFI_NOT_FOUND) { Print(L"Variable absent; not equivalent to a stored 0x17.\n"); return; }
  if (EFI_ERROR(S)) { Print(L"Not a successful snapshot; required/reported size %u.\n", (UINT32)Size); return; }
  Print(L"Attributes: 0x%08x; size: %u; bytes:", Attr, (UINT32)Size);
  for (I = 0; I < Size; ++I) Print(L" %02x", (UINT32)Data[I]);
  Print(L"\n");
}

// No generic command function: the only host write is literal command 0x41.
// Readiness checks cannot exclude SMM/firmware races. Pre-OS use only.
STATIC EFI_STATUS QueryOnce(VOID) {
  UINTN I;
  UINT8 S, Response;
  // Require 10 ms continuously idle. Abort without draining pending output.
  for (I = 0; I < 100; ++I) {
    S = IoRead8(0x66);
    if ((S & 3) != 0) {
      Print(L"Abort before command: EC busy/pending output (status %02x).\n", (UINT32)S);
      return EFI_NOT_READY;
    }
    gBS->Stall(100);
  }
  // Recheck immediately before submitting the sole command.
  if ((IoRead8(0x66) & 3) != 0) return EFI_NOT_READY;
  IoWrite8(0x66, 0x41);
  for (I = 0; I < 10000; ++I) {
    S = IoRead8(0x66);
    if ((S & 3) == 1) {
      Response = IoRead8(0x62);
      Print(L"EC query response: 0x%02x\n", (UINT32)Response);
      if (Response == 0xEE) Print(L"RAM gate reports ENABLED; flash persistence NOT verified.\n");
      else if (Response == 0) Print(L"RAM gate reports NOT ENABLED; exact stored byte unknown.\n");
      else { Print(L"Unexpected response; do not retry automatically.\n"); return EFI_DEVICE_ERROR; }
      return EFI_SUCCESS;
    }
    gBS->Stall(100);
  }
  Print(L"Timeout. Command may still have executed; pending response may remain.\n");
  Print(L"Do not retry or issue another EC command.\n");
  return EFI_TIMEOUT;
}

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
  EFI_INPUT_KEY Key;
  EFI_STATUS S;
  UINTN Index;
  BOOLEAN Match;
  (VOID)ImageHandle;
  // Direct freestanding entry: initialize table pointers explicitly.
  gST = SystemTable;
  gBS = SystemTable->BootServices;
  gRT = SystemTable->RuntimeServices;
  Print(L"NWCN27WW query-only diagnostic: not hardware validated.\n");
  Match = TargetMatches();
  ReadCrb();
  if (!Match) { Print(L"Target mismatch/unknown: no EC ports accessed.\n"); return EFI_UNSUPPORTED; }
  Print(L"No EC I/O has occurred. Any key exits; uppercase Q requests ONE query.\n");
  Print(L"Q sends command 41; no flash utility, unlock, variable writes or reset.\n");
  S = gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index);
  if (EFI_ERROR(S)) return S;
  S = gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
  if (EFI_ERROR(S) || Key.UnicodeChar != L'Q') return EFI_ABORTED;
  return QueryOnce();
}
