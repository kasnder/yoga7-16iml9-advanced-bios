// Minimal freestanding implementation of the library functions used by EcQuery.
// Uses official EDK II ABI definitions. This runtime itself performs no allocation, disk or variable writes.
#include <Uefi.h>
#include <Protocol/Smbios.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/IoLib.h>
EFI_SYSTEM_TABLE *gST;
EFI_BOOT_SERVICES *gBS;
EFI_RUNTIME_SERVICES *gRT;
EFI_GUID gEfiSmbiosProtocolGuid = EFI_SMBIOS_PROTOCOL_GUID;
INTN EFIAPI AsciiStrnCmp(CONST CHAR8 *A, CONST CHAR8 *B, UINTN N) {
  while (N && *A && *A == *B) { ++A; ++B; --N; }
  return N ? (UINT8)*A - (UINT8)*B : 0;
}
INTN EFIAPI AsciiStrCmp(CONST CHAR8 *A, CONST CHAR8 *B) {
  while (*A && *A == *B) { ++A; ++B; }
  return (UINT8)*A - (UINT8)*B;
}
UINT8 EFIAPI IoRead8(UINTN Port) {
  UINT8 V;
  __asm__ volatile ("inb %w1, %0" : "=a"(V) : "d"((UINT16)Port));
  return V;
}
UINT8 EFIAPI IoWrite8(UINTN Port, UINT8 V) {
  __asm__ volatile ("outb %0, %w1" : : "a"(V), "d"((UINT16)Port));
  return V;
}
STATIC VOID Put(CHAR16 C) {
  CHAR16 B[3] = {C, 0, 0};
  if (C == L'\n') { B[0] = L'\r'; B[1] = L'\n'; }
  gST->ConOut->OutputString(gST->ConOut, B);
}
STATIC VOID Number(UINT64 V, UINTN Base, UINTN Width) {
  CHAR16 B[32]; UINTN N = 0;
  do { B[N++] = L"0123456789ABCDEF"[V % Base]; V /= Base; } while (V && N < 32);
  while (Width > N) { Put(L'0'); --Width; }
  while (N) Put(B[--N]);
}
// Implements only the formats used by this application; status is numeric hex.
UINTN EFIAPI Print(CONST CHAR16 *F, ...) {
  VA_LIST A; VA_START(A, F);
  while (*F) {
    UINTN Width = 0;
    if (*F != L'%') { Put(*F++); continue; }
    ++F;
    while (*F >= L'0' && *F <= L'9') { Width = Width*10 + (*F++ - L'0'); }
    switch (*F++) {
      case L'a': {
        CONST CHAR8 *P = VA_ARG(A, CONST CHAR8 *); UINTN N = 0;
        while (*P && N++ < 256) Put((UINT8)*P++); break;
      }
      case L'u': Number(VA_ARG(A, UINT32), 10, Width); break;
      case L'x': Number(VA_ARG(A, UINT32), 16, Width); break;
      case L'r': Put(L'0'); Put(L'x'); Number(VA_ARG(A, EFI_STATUS), 16, 16); break;
      case L'g': {
        CONST EFI_GUID *G = VA_ARG(A, CONST EFI_GUID *); UINTN I;
        Number(G->Data1,16,8); Put(L'-'); Number(G->Data2,16,4); Put(L'-');
        Number(G->Data3,16,4); Put(L'-');
        for (I=0; I<8; ++I) { if (I==2) Put(L'-'); Number(G->Data4[I],16,2); }
        break;
      }
      case L'%': Put(L'%'); break;
      default: Put(L'?'); break;
    }
  }
  VA_END(A); return 0;
}
