# How it works

This is the mechanism found by static analysis of the Lenovo BIOS update for **NWCN27WW** and its embedded EC image **NWEC27WW** (`ec.bin`, 131,072 bytes at offset `0x1E6BB0` of the unpacked `WinNWCN27WW.fd`, SHA256 `2e8bf4b759ca98fafd3727213a1ca08a974f79d147865ae18acf8360326fde92`). The offsets below apply to that firmware version only. All numbers are hexadecimal.

Most of this is inferred from the firmware code. The flag-sector contents below and the enable result were also observed on a real laptop.

## Two conditions must hold

`H2OFormBrowserDxe` (FFS GUID `9E5DAEB4-4B91-4466-9EBE-81C7E4401E6D`) implements the menu filter at PE RVA `0x3187C..0x31A6B`:

1. It reads the one-byte UEFI variable `CrbItem` (vendor GUID `C2C749AF-12D6-484A-A39A-81D1C1F04EED`). If the read fails, it uses `0x17`.
2. It sends EC command `0x41` through the command/status port `0x66` and data port `0x62`. Unless the query succeeds and returns `0xEE`, the selector is forced to `0x17`.

Only the selector value `0x16` bypasses the OEM menu filter, so the menus need **both** `CrbItem = 0x16` and an enabled EC gate. Setting the variable alone does nothing while the EC answers `0x00`.

The firmware's own variable writer (in `BootOrderSmm`, software SMI `0xCA`, which itself requires the EC to answer `0xEE`) stores `CrbItem` with attributes `0x07` (non-volatile, boot-service and runtime access). EcEnable uses the same attributes.

The unfiltered menu list includes the full Advanced and Power formsets. That doesn't mean every setting in them works or is safe on this laptop. The older Yoga unlock method (writing a CMOS index) isn't the mechanism used here.

## EC commands and storage

The EC's OEM command dispatcher at `0xB077` in `ec.bin` maps three commands:

| Command | Handler | Effect |
| --- | --- | --- |
| `0x40` | `0xAC1D` | If the RAM flag `XDATA[0x836F]` isn't already `0xCF`: set it to `0xCF`, erase flash at `0x01FC00`, then program one byte `0xCF` there |
| `0x41` | `0xAC3F` | Reply `0xEE` if the RAM flag is `0xCF`, otherwise `0x00`. No flash access. |
| `0x42` | `0xAC50` | If the RAM flag isn't already `0x00`: clear it, erase at `0x01FC00`, then program one byte `0x00` |

- **Erase size:** the erase opcode is `0xD7`, which in the ITE reference tools erases 1 KiB, here `0x01FC00..0x01FFFF`, the last KiB of the 128 KiB image. The erase size wasn't measured on the laptop, but the before and after dumps fit it: everything after the first byte was `FF` both times.
- **Persistence:** the startup routine `0xAC71` reloads the RAM flag from flash `0x01FC00`, so the state survives an EC restart.
- **No reply:** the `0x40` and `0x42` handlers send no reply. They poll the flash with no timeout and with EC interrupts disabled.
- **`EE` isn't proof:** the RAM flag changes **before** the flash operation, so `0xEE` alone doesn't prove the flash write happened.
- **Skipped write:** a guard on `XDATA[0x81D0]` bit 7 can skip the program step after the erase has already happened. The sector would then read all `FF`, which the EC treats as disabled. That's why the usage guide checks the sector with EcRead after enabling.

## Flag sector contents

| State | Sector `0x01FC00..0x01FFFF` |
| --- | --- |
| Update image as shipped | `FF` + 1023 × `00` (never matched the live laptop) |
| Live, before enabling (tested laptop) | `00` + 1023 × `FF`, the same as what `0x42` writes |
| Live, after `0x40` | `CF` + 1023 × `FF` |

The tested laptop's sector didn't match the update image, so the EC had rewritten it at some point. Its "before" state is exactly what `0x42` writes, so disabling should restore the sector byte for byte. This hasn't been observed on hardware yet.

## After a reboot

On the tested laptop the menus are hidden again after a reboot. `CrbItem` keeps its value `0x16`, but the EC answers `0x41` with `0x00` again, so the EC side is reset. It isn't known yet what resets it. Two possibilities:

- **Only the EC's RAM flag is cleared** at boot. The flag sector would then still hold `CF`.
- **Something sends the equivalent of `0x42`** at boot, rewriting the sector to `00`.

Running `EcRead.efi` after a reboot would tell the two apart. Either way the gate is effectively per boot.

To show the menus again, run `E` then `Y`. With `CrbItem` already `0x16`, it leaves the variable alone and sends `0x40` once. Each `0x40` erases and rewrites the 1 KiB flag sector. Embedded flash tolerates only a limited number of erase cycles, and the endurance of this EC's flash isn't known, so re-enable when you need the menus rather than on every boot.

After a reboot, `D` finds the gate already at `0x00`, so it sends no EC command and only deletes `CrbItem`.

## How the tools talk to the EC

All EC access uses the standard ACPI EC interface on ports `0x66` (command and status) and `0x62` (data). Before sending a command the tools require the EC to be idle for 10 ms, and they never drain bytes they didn't ask for. Every wait has a time limit. Port access happens at `TPL_NOTIFY`, which blocks UEFI timer callbacks from other firmware drivers, though not System Management Mode. After any unexpected byte or timeout following a write, the tools send nothing more.

- **EcQuery** sends `0x41` once.
- **EcEnable** checks and sets `CrbItem` first, so a firmware that write-protects the variable stops the tool before any flash command. It then sends `0x41`, `0x40` once, and `0x41` again.
- **EcRead** uses the ITE EC's built-in flash utility, as documented by [ITE_ECTool](https://github.com/tomios/ITE_ECTool) and [zenbook-q410-powerfix](https://github.com/hz12opensource/zenbook-q410-powerfix):
  1. Enter with `DC` and expect `33` back.
  2. Read the chip ID with `9F` and accept only `FF FF FE`.
  3. Check the first 32 bytes of flash against the NWEC27WW image.
  4. Read `0x01FC00..0x01FFFF` twice with `0B` and compare the two reads.
  5. Leave with `05` then `FC`.

  The EC stops its normal work while in this mode. `FC` restarts its firmware initialisation, which can itself update flash metadata.

## Mirroring and checksums

The ITE header at `0x40..0x4F` of the image is consistent with mirroring a 121 KiB prefix (to `0x1E3FF`) from the BIOS flash, under the Zenbook project's interpretation. That range excludes the flag sector. No checksum covering the flag sector was found. Neither point has been confirmed on the live laptop. Lenovo's initialisation can conditionally write zero to the mirror-size byte at `0x4D`.

