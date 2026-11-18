// NWCN27WW advanced-menu gate tool. See README.txt for limits.
// Host writes: EC commands 0x41 (query), 0x40 (enable, at most once) and
// 0x42 (disable, at most once); UEFI variable CrbItem only. No flash utility,
// no DC/FC/FE, no other variables, no SMI.
#include <Uefi.h>
#include <IndustryStandard/SmBios.h>
#include <Protocol/Smbios.h>
#include <Library/BaseLib.h>
#include <Library/IoLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include "Target.inc"

STATIC EFI_GUID mCrbGuid = {0xc2c749af,0x12d6,0x484a,{0xa3,0x9a,0x81,0xd1,0xc1,0xf0,0x4e,0xed}};
STATIC EFI_GUID * volatile mCrbGuidPointer = &mCrbGuid;
STATIC CHAR16 mCrbName[] = L"CrbItem";
#define CRB_ATTR (EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_BOOTSERVICE_ACCESS|EFI_VARIABLE_RUNTIME_ACCESS)
#define CRB_UNLOCK 0x16

typedef enum { CrbAbsent, CrbUnlock, CrbOther, CrbError } CRB_STATE;

// ---------------------------------------------------------------- variable
STATIC CRB_STATE ReadCrb(BOOLEAN Verbose) {
  UINT8 Data[64];
  UINTN Size = sizeof(Data), I;
  UINT32 Attr = 0;
  EFI_STATUS S = gRT->GetVariable(mCrbName, mCrbGuidPointer, &Attr, &Size, Data);
  if (S == EFI_NOT_FOUND) { if (Verbose) Print(L"CrbItem: absent\n"); return CrbAbsent; }
  if (EFI_ERROR(S)) { Print(L"CrbItem read failed: %r\n", S); return CrbError; }
  if (Verbose || !(Size == 1 && Attr == CRB_ATTR && Data[0] == CRB_UNLOCK)) {
    Print(L"CrbItem: attributes 0x%08x, size %u, bytes:", Attr, (UINT32)Size);
    for (I = 0; I < Size; ++I) Print(L" %02x", (UINT32)Data[I]);
    Print(L"\n");
  }
  if (Size == 1 && Attr == CRB_ATTR && Data[0] == CRB_UNLOCK) return CrbUnlock;
  return CrbOther;
}

// ---------------------------------------------------------------- EC transport
// All port access runs at TPL_NOTIFY (see EcSession*). No Print in here.
// After any post-write timeout or unexpected byte, Stuck is set and no
// further EC command is sent: the EC state is then unknown.
STATIC BOOLEAN Stuck;

STATIC EFI_STATUS WaitIdle(VOID) {
  UINTN I;
  for (I = 0; I < 100; ++I) {           // 10 ms continuously idle, no drain
    if (IoRead8(0x66) & 3) return EFI_NOT_READY;
    gBS->Stall(100);
  }
  return (IoRead8(0x66) & 3) ? EFI_NOT_READY : EFI_SUCCESS;
}

STATIC EFI_STATUS Query(UINT8 *R) {
  UINTN I; UINT8 St;
  EFI_STATUS S;
  if (Stuck) return EFI_DEVICE_ERROR;
  S = WaitIdle();
  if (EFI_ERROR(S)) return S;
  IoWrite8(0x66, 0x41);
  for (I = 0; I < 50000; ++I) {          // up to about 5 s
    St = IoRead8(0x66);
    if ((St & 3) == 1) {
      *R = IoRead8(0x62);
      if (*R == 0xEE || *R == 0x00) return EFI_SUCCESS;
      Stuck = TRUE; return EFI_PROTOCOL_ERROR;
    }
    gBS->Stall(100);
  }
  Stuck = TRUE;
  return EFI_TIMEOUT;
}

// The native 0x40/0x42 handlers send no reply. Completion is inferred from
// the input buffer clearing, a fixed settle delay and a later 0x41 query.
STATIC EFI_STATUS GateCommand(UINT8 C) {
  UINTN I;
  EFI_STATUS S;
  if (C != 0x40 && C != 0x42) return EFI_INVALID_PARAMETER;
  if (Stuck) return EFI_DEVICE_ERROR;
  S = WaitIdle();
  if (EFI_ERROR(S)) return S;
  IoWrite8(0x66, C);
  for (I = 0; I < 50000 && (IoRead8(0x66) & 2); ++I) gBS->Stall(100);
  if (IoRead8(0x66) & 2) { Stuck = TRUE; return EFI_TIMEOUT; }
  gBS->Stall(1000000);                    // erase + one-byte program settle
  if (IoRead8(0x66) & 1) { Stuck = TRUE; return EFI_PROTOCOL_ERROR; }
  return EFI_SUCCESS;
}

// Each session: query, optional single command, re-query. Returns the
// before/after query bytes (0xFF when not obtained).
STATIC EFI_STATUS EcSession(UINT8 Command, UINT8 SkipIf, UINT8 *Before, UINT8 *After, BOOLEAN *Sent) {
  EFI_TPL Old;
  EFI_STATUS S;
  *Before = 0xFF; *After = 0xFF; *Sent = FALSE;
  Old = gBS->RaiseTPL(TPL_NOTIFY);
  S = Query(Before);
  if (!EFI_ERROR(S) && Command != 0 && *Before != SkipIf) {
    *Sent = TRUE;
    S = GateCommand(Command);
    if (!EFI_ERROR(S)) S = Query(After);
  }
  gBS->RestoreTPL(Old);
  return S;
}

STATIC VOID ReportEc(EFI_STATUS S, UINT8 Before, UINT8 After, BOOLEAN Sent, UINT8 Command) {
  if (Before != 0xFF) Print(L"EC query before: 0x%02x (%a)\n", (UINT32)Before, Before == 0xEE ? "gate enabled" : "gate disabled");
  if (Sent) Print(L"Sent EC command 0x%02x once.\n", (UINT32)Command);
  if (After != 0xFF) Print(L"EC query after: 0x%02x\n", (UINT32)After);
  if (S == EFI_NOT_READY) Print(L"EC busy or pending output: command not sent. Stop; do not drain or retry.\n");
  else if (Stuck) {
    Print(L"EC did not respond as expected (%r). Send NO further EC commands.\n", S);
    Print(L"Shut down; if fans/keyboard/charging misbehave, hold power 15-20 s.\n");
  } else if (EFI_ERROR(S)) Print(L"EC step failed: %r\n", S);
}

// ---------------------------------------------------------------- actions
STATIC EFI_STATUS Enable(CRB_STATE Crb) {
  EFI_STATUS S; UINT8 Before, After, Value = CRB_UNLOCK; BOOLEAN Sent;
  if (Crb != CrbAbsent && Crb != CrbUnlock) {
    Print(L"CrbItem has an unexpected value or could not be read. Nothing changed.\n");
    return EFI_ACCESS_DENIED;
  }
  // Baseline query first: refuse unexpected EC behaviour before any write.
  S = EcSession(0, 0, &Before, &After, &Sent);
  ReportEc(S, Before, After, Sent, 0);
  if (EFI_ERROR(S)) return S;
  // Variable before EC: a write-protected variable stops before EC flash work.
  if (Crb == CrbAbsent) {
    S = gRT->SetVariable(mCrbName, mCrbGuidPointer, CRB_ATTR, 1, &Value);
    if (EFI_ERROR(S)) { Print(L"CrbItem write failed: %r. EC NOT touched.\n", S); return S; }
    if (ReadCrb(FALSE) != CrbUnlock) { Print(L"CrbItem read-back mismatch. EC NOT touched.\n"); return EFI_COMPROMISED_DATA; }
    Print(L"CrbItem set to 0x16 (attributes 0x07) and read back.\n");
  } else Print(L"CrbItem already 0x16.\n");
  if (Before == 0xEE) { Print(L"EC gate already enabled; 0x40 NOT sent.\n"); return EFI_SUCCESS; }
  S = EcSession(0x40, 0xEE, &Before, &After, &Sent);
  ReportEc(S, Before, After, Sent, 0x40);
  if (EFI_ERROR(S)) return S;
  if (Sent && After != 0xEE) { Print(L"Gate did not report enabled. Do not repeat 0x40.\n"); return EFI_DEVICE_ERROR; }
  Print(L"RAM gate enabled. This does NOT prove the flash byte was written.\n");
  Print(L"Next: run EcRead.efi and expect CF followed by 1023 x FF.\n");
  return EFI_SUCCESS;
}

STATIC EFI_STATUS Disable(CRB_STATE Crb) {
  EFI_STATUS S; UINT8 Before, After; BOOLEAN Sent;
  S = EcSession(0x42, 0x00, &Before, &After, &Sent);
  ReportEc(S, Before, After, Sent, 0x42);
  if (EFI_ERROR(S)) return S;
  if (Sent && After != 0x00) { Print(L"Gate did not report disabled. Do not repeat 0x42.\n"); return EFI_DEVICE_ERROR; }
  if (!Sent) Print(L"EC gate already disabled; 0x42 NOT sent.\n");
  if (Crb == CrbAbsent) { Print(L"CrbItem already absent.\n"); return EFI_SUCCESS; }
  if (Crb != CrbUnlock) { Print(L"CrbItem is not this tool's 0x16 value; left unchanged.\n"); return EFI_ACCESS_DENIED; }
  S = gRT->SetVariable(mCrbName, mCrbGuidPointer, CRB_ATTR, 0, NULL);
  if (EFI_ERROR(S)) { Print(L"CrbItem delete failed: %r\n", S); return S; }
  if (ReadCrb(FALSE) != CrbAbsent) { Print(L"CrbItem still present after delete.\n"); return EFI_COMPROMISED_DATA; }
  Print(L"CrbItem deleted (restores the recorded original absence).\n");
  return EFI_SUCCESS;
}

STATIC CHAR16 GetKey(VOID) {
  EFI_INPUT_KEY Key; UINTN Index;
  if (EFI_ERROR(gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index))) return 0;
  if (EFI_ERROR(gST->ConIn->ReadKeyStroke(gST->ConIn, &Key))) return 0;
  return Key.UnicodeChar;
}

EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
  EFI_STATUS S; CRB_STATE Crb; CHAR16 K;
  UINT8 Before, After; BOOLEAN Sent;
  gST = SystemTable; gBS = SystemTable->BootServices; gRT = SystemTable->RuntimeServices;
  Print(L"NWCN27WW advanced-menu gate tool: OFFLINE TESTED ONLY.\n");
  if (!TargetMatches()) { Print(L"Target mismatch: nothing accessed.\n"); return EFI_UNSUPPORTED; }
  Crb = ReadCrb(TRUE);
  Print(L"No EC ports accessed yet.\n");
  Print(L"  S  query gate only (EC 0x41)\n");
  Print(L"  E  enable: set CrbItem=0x16, then EC 0x40 once\n");
  Print(L"  D  disable: EC 0x42 once, then delete CrbItem\n");
  Print(L"Uppercase only; any other key exits.\n");
  K = GetKey();
  if (K == L'S') {
    S = EcSession(0, 0, &Before, &After, &Sent);
    ReportEc(S, Before, After, Sent, 0);
    return S;
  }
  if (K != L'E' && K != L'D') return EFI_ABORTED;
  Print(L"%a writes EC flash and a UEFI variable. Uppercase Y confirms.\n", K == L'E' ? "Enable" : "Disable");
  if (GetKey() != L'Y') { Print(L"Cancelled; nothing changed.\n"); return EFI_ABORTED; }
  return K == L'E' ? Enable(Crb) : Disable(Crb);
}
