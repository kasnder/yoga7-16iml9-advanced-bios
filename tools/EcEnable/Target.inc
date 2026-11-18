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
      BiosOk = AsciiStrCmp(V, "NWCN27WW") == 0;
    }
    if (H->Type == SMBIOS_TYPE_SYSTEM_INFORMATION && H->Length >= sizeof(SMBIOS_TABLE_TYPE1)) {
      SMBIOS_TABLE_TYPE1 *T = (SMBIOS_TABLE_TYPE1 *)H;
      CONST CHAR8 *P = SmbString(H, T->ProductName);
      CONST CHAR8 *M = SmbString(H, T->Manufacturer);
      Print(L"Manufacturer: %a; Product: %a\n", M, P);
      ModelOk = AsciiStrCmp(M, "LENOVO") == 0 && AsciiStrCmp(P, "83DL") == 0;
    }
  }
  return BiosOk && ModelOk;
}

