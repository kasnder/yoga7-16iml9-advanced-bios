# Usage guide

Step-by-step instructions for enabling, checking and undoing the hidden Advanced and Power menus.

> [!WARNING]
> Only tested on **one** Lenovo Yoga 7 2-in-1 16IML9 (type **83DL**) with BIOS **NWCN27WW** and EC firmware **NWEC27WW 01.27**. If your machine type or BIOS version differs, stop here. You can check both in BIOS Setup (F2) on the Information page, or in Windows with `msinfo32`.

The disable path (`D`) has only been tested in the emulator so far.

## Before you start

> [!CAUTION]
> **Use at your own risk.** These tools write to your EC's flash and a UEFI variable, and the unlocked menus expose settings that can leave the laptop unbootable. Nobody can help you recover it, and there is no warranty.
>
> **Having a hardware flash programmer is recommended**, and you should know how to use it before you start:
> - a **SPI flash programmer** (for example a CH341A with a SOIC-8 clip), to rewrite the BIOS chip if a setting stops the laptop booting;
> - an **ITE EC programmer** (for example [I2C-Pico-USB-ITE-EC-prog](https://github.com/JohnDoe150489/I2C-Pico-USB-ITE-EC-prog)), in case the EC's own flash is ever damaged.
>
> Neither recovery route has been tried on this laptop. Back up the BIOS chip with the programmer before you change any setting.


- **BitLocker:** have your Windows recovery key ready (aka.ms/myrecoverykey or your Microsoft account). Turning off Secure Boot can make Windows ask for it.
- **Power:** charge the battery and keep the charger connected. The EC erases and rewrites its own flash during `E` and `D`.
- **Time:** allow 15 minutes and don't interrupt the tools while they run.

## 1. Prepare a USB stick

You need a FAT32 USB stick with a UEFI Shell and the three tools. Formatting erases the stick.

1. **Format it as FAT32.** On macOS, find the stick with `diskutil list`; `disk4` below is only an example:

   ```bash
   diskutil eraseDisk FAT32 EFISHELL MBRFormat /dev/disk4
   ```

   On Windows, use Explorer's *Format…* with *FAT32*; on Linux, `mkfs.vfat -F 32`.

2. **Add a UEFI Shell.** The newest official prebuilt shell is `ShellBinPkg.zip` from the EDK II release [edk2-stable202002](https://github.com/tianocore/edk2/releases/tag/edk2-stable202002). Copy `UefiShell/X64/Shell.efi` from it to the stick as `EFI/BOOT/BOOTX64.EFI`.

3. **Copy the tools** to the root of the stick: `tools/EcQuery/EcQuery.efi`, `tools/EcRead/EcRead.efi` and `tools/EcEnable/EcEnable.efi`. Check them against [SHA256SUMS.txt](../SHA256SUMS.txt):

   ```bash
   shasum -a 256 /Volumes/EFISHELL/*.efi
   ```

   EcRead saves its dump to the same stick, so the stick must be writable.

## 2. Boot the UEFI Shell

1. **Turn Secure Boot off.** Press F2 at the Lenovo logo (or use the Novo button → BIOS Setup), then go to Security → Secure Boot → Disabled. Save and exit.
2. **Boot the stick.** Press F12 (Fn+F12 if needed) at the logo and choose the USB stick.
3. **Find the stick's volume** in the shell:

   ```text
   map -r
   fs0:
   ls
   ```

   Try `fs1:`, `fs2:` and so on until `ls` lists the `.efi` files.

## 3. Check the starting state

```text
EcEnable.efi
```

Press uppercase **S**. Expected on a laptop that has never been unlocked:

```text
CrbItem: absent
EC query before: 0x00 (gate disabled)
```

If `CrbItem` shows a value, note the bytes and attributes it prints before going further.

## 4. Back up the flag sector

```text
EcRead.efi
```

Press uppercase **R**. A clean run prints `Two reads match` and saves `EC01FC00-00.bin` at the root of the stick. Copy that file somewhere safe; it is your backup of the sector the tools change. On a laptop that has never been unlocked, expect `00` followed by 1023 × `FF`.

If it prints `EC exit NOT confirmed`, don't run anything else; see [If something goes wrong](#if-something-goes-wrong).

## 5. Enable

```text
EcEnable.efi
```

Press uppercase **E**, then uppercase **Y** to confirm. Any other key cancels without changing anything. Expected:

```text
EC query before: 0x00 (gate disabled)
CrbItem set to 0x16 (attributes 0x07) and read back.
EC query before: 0x00 (gate disabled)
Sent EC command 0x40 once.
EC query after: 0xEE
RAM gate enabled. This does NOT prove the flash byte was written.
Next: run EcRead.efi and expect CF followed by 1023 x FF.
```

The tool waits about a second after `0x40` while the EC erases and rewrites the sector.

## 6. Verify the flash

```text
EcRead.efi
```

Press uppercase **R**. It saves the next free file name, such as `EC01FC00-01.bin`. Check it on another computer:

```bash
xxd EC01FC00-01.bin | head -2
```

| Sector content | Meaning |
| --- | --- |
| `CF` followed by 1023 × `FF` | The enable persisted. Continue. |
| 1024 × `FF` | The EC erased the sector but skipped the write. The gate will read as disabled after the next EC restart. Don't run `E` again until you understand why. |
| Anything else | Stop and keep the file. |

## 7. Look at the menus

```text
reset
```

Press F2 at the Lenovo logo. The Advanced and Power menus should now be visible.

They stay visible for this boot only. After the next reboot `CrbItem` is still set, but the EC's gate reads `0x00` again, so the menus are hidden. To show them again, boot the shell, run `EcEnable.efi` and press `E` then `Y`. It keeps the variable and sends `0x40` once, which rewrites the EC's flag sector, so do this when you need the menus rather than on every boot. See [HOW-IT-WORKS.md](HOW-IT-WORKS.md#after-a-reboot).

- **Look first and change nothing,** then exit without saving.
- **Later, change one setting at a time** and write down each change. Wrong CPU, memory or power settings can stop the laptop booting, and loading defaults isn't proven to recover it on this machine.
- **Turn Secure Boot back on** (F2 → Security) once you no longer need the shell.

## Undo

A reboot already hides the menus, because the EC's gate resets. Undoing removes the `CrbItem` variable as well and, if the gate is still enabled, disables it.

Boot the shell again with Secure Boot off, then:

```text
EcEnable.efi
```

Press uppercase **D**, then uppercase **Y**. Expected:

```text
EC query before: 0xEE (gate enabled)
Sent EC command 0x42 once.
EC query after: 0x00
CrbItem deleted (restores the recorded original absence).
```

If you have rebooted since enabling, the gate already reads `0x00`. `D` then prints `0x42 NOT sent` and only deletes `CrbItem`.

Then run `EcRead.efi` and compare the new dump with your backup from step 4:

```bash
cmp EC01FC00-00.bin EC01FC00-02.bin && echo identical
```

If your backup was `00` followed by 1023 × `FF`, that is exactly what the disable command writes, so the two should be identical. If your backup was different, `D` gives you a disabled gate but not a byte-identical sector.

`D` deletes `CrbItem` only if it holds the tool's exact value `0x16`. Otherwise it leaves the variable alone and tells you. Disabling the menus does **not** undo settings you changed while they were visible.

## Messages that mean stop

| Message | What happened | What to do |
| --- | --- | --- |
| `Target mismatch: nothing accessed.` | Not an 83DL with BIOS NWCN27WW | Nothing changed. Don't use these tools on this machine. |
| `CrbItem has an unexpected value or could not be read. Nothing changed.` | The variable holds something this tool didn't write | Note the bytes shown and stop. |
| `CrbItem write failed: … EC NOT touched.` | The firmware protects the variable | Nothing on the EC changed. The method doesn't work as is on your firmware. |
| `CrbItem read-back mismatch. EC NOT touched.` | The variable didn't store as written | Stop and note the output. |
| `EC busy or pending output: command not sent.` | The EC was busy before any command | Nothing was sent. Reboot before trying again. |
| `EC did not respond as expected (…). Send NO further EC commands.` | Timeout or unexpected byte after a write | See below. |
| `Gate did not report enabled. Do not repeat 0x40.` | The EC ignored `0x40` | Don't retry. Run EcRead and look at the sector. |
| `Gate did not report disabled. Do not repeat 0x42.` | The EC ignored `0x42` | Don't retry. Run EcRead and look at the sector. |

Never run `E` or `D` repeatedly to "fix" a result. Each run erases and rewrites the sector.

## If something goes wrong

- **EC unresponsive** (no keyboard, fans stuck, no charging): shut down. Unplug the charger and hold the power button for 15–20 s, wait a minute, then start the laptop. If it still misbehaves, the internal battery has to be disconnected, which means opening the bottom cover.
- **Laptop won't boot after a setting change:** this is outside what these tools can fix. Try Lenovo's own recovery options first. Otherwise, restore your backup of the BIOS chip with a SPI flash programmer.
- **EC flash damaged** (the EC no longer starts at all): only an external ITE EC programmer can rewrite it.

## What the tools never do

- `EcEnable` sends only EC commands `0x41` (query), `0x40` (at most once) and `0x42` (at most once), on ports `0x66`/`0x62`.
- `EcEnable` never enters the EC flash utility, sends SPI flash commands or triggers SMIs.
- `EcRead` uses only the SPI read-ID (`9F`) and fast-read (`0B`) commands. It never erases or programs flash itself, though the EC's own restart on exit may update its metadata.
- No tool writes a UEFI variable other than `CrbItem`, and none touches an EC port before you press its uppercase start key.
