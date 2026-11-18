# Yoga 7 2-in-1 16IML9: show the hidden BIOS menus

UEFI tools that make the hidden **Advanced** and **Power** menus appear in the BIOS Setup of the Lenovo Yoga 7 2-in-1 16IML9, using the firmware's own unlock mechanism. No BIOS image is modified or flashed.

> [!WARNING]
> **Only tested on one laptop with one firmware version:** machine type **83DL**, BIOS **NWCN27WW**, EC firmware **NWEC27WW 01.27**.
>
> It has not been tried on any other model or BIOS version. Lenovo can change the mechanism in any BIOS update. The tools check the model and BIOS version and refuse to run anywhere else; please don't remove that check. You can see your machine type and BIOS version in BIOS Setup (F2) or in Windows with `msinfo32`.

## Is this for me?

You need:

- a Yoga 7 2-in-1 16IML9 (type 83DL) on BIOS NWCN27WW;
- a USB stick you can format;
- your BitLocker recovery key, if Windows uses BitLocker, because Secure Boot has to be off while you run the tools.

Be aware that many of the unlocked settings can stop the laptop from booting, and loading defaults isn't guaranteed to fix that. Only change settings you understand, one at a time.

## Quick start

The full guide, with the expected output of every step, is in [docs/USAGE.md](docs/USAGE.md). In short:

1. **Prepare a USB stick.** Format a stick as FAT32 and copy on a UEFI Shell as `EFI/BOOT/BOOTX64.EFI`. Copy `EcEnable.efi` and `EcRead.efi` to its root.
2. **Turn off Secure Boot** (F2 → Security) and boot the stick from the F12 menu.
3. **Back up the flag sector.** Run `EcRead.efi` and press `R`. Keep the `EC01FC00-00.bin` it saves.
4. **Enable.** Run `EcEnable.efi`, press `E`, then `Y`. It should end with `EC query after: 0xEE`.
5. **Check.** Run `EcRead.efi` again. The new file should start with `CF`, followed by `FF`s.
6. **Open Setup.** Type `reset`, then press F2 at the Lenovo logo. The Advanced and Power menus are now visible.

To hide them again, run `EcEnable.efi` and press `D`, then `Y`.

## Known issues

- **The menus disappear after a reboot.** On the tested laptop they're visible on the first boot after enabling and gone after the next reboot. It isn't known yet which of the two conditions (below) is being reset. Running `EcEnable.efi` and pressing `S` after a reboot shows the state of both. If you can see what changes, please open an issue with that output.
- **The disable path (`D`) is untested on hardware.** It has only been tested in the emulator.

## How it works

The BIOS Setup shows the hidden menus only when **both** of these hold:

1. **The UEFI variable is set.** `CrbItem` (GUID `C2C749AF-12D6-484A-A39A-81D1C1F04EED`) must hold the single byte `0x16`.
2. **The EC reports enabled.** The embedded controller (EC) must answer its query command `0x41` with `0xEE`.

The EC firmware has built-in commands for the second condition. `0x40` writes `0xCF` into a 1 KiB flag sector of the EC's flash; `0x42` writes `0x00` there. `EcEnable.efi` sets the variable and sends `0x40` once. Disabling sends `0x42` and deletes the variable.

Details and firmware offsets: [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md).

## The tools

| Tool | Purpose | Changes anything? |
| --- | --- | --- |
| [`EcEnable.efi`](tools/EcEnable/) | `S` shows the state, `E` then `Y` enables, `D` then `Y` disables | `CrbItem` and the EC flag sector |
| [`EcRead.efi`](tools/EcRead/) | Saves the EC's 1 KiB flag sector to the USB stick, to back it up or check it | Only writes the dump file. The EC pauses fans, charging and keyboard for a few seconds. |
| [`EcQuery.efi`](tools/EcQuery/) | Shows the model, BIOS, `CrbItem` and the EC's answer to `0x41` | No |

All three are unsigned x64 UEFI applications that run from a UEFI Shell. They do nothing until you press an uppercase key. Download them from this repository and check them against [SHA256SUMS.txt](SHA256SUMS.txt).

## Safety

- **Limited EC access:** `EcEnable` sends only the EC commands `0x40`, `0x41` and `0x42`, with at most one write command per run. It writes the variable first, so firmware that protects `CrbItem` stops it before the EC is touched. After any timeout or unexpected reply, it sends nothing more.
- **Read-only flash access:** `EcRead` uses only flash read commands. While it runs, the EC stops its normal work for a few seconds. If the EC ever stays unresponsive, hold the power button for 15–20 s; if that fails, disconnect the internal battery.
- **Power during writes:** keep the charger connected while enabling or disabling. A power cut during the EC's flash write leaves the sector blank, which reads as disabled.
- **Settings stay changed:** disabling the menus doesn't undo settings you changed while they were visible.

## Building and testing

The binaries can be rebuilt from source, giving byte-identical code. You need [Zig 0.13.0](https://ziglang.org/download/#release-0.13.0) (used as the C compiler) and the `MdePkg/Include` folder from [EDK II](https://github.com/tianocore/edk2) `edk2-stable202408`. EDK II is the open-source UEFI reference implementation; only its header files are used.

```bash
python build.py --zig /path/to/zig --include /path/to/edk2/MdePkg/Include
```

That builds into `build/` and checks the result against the committed binaries, ignoring only the build timestamp.

The tests run the compiled binaries in the [Unicorn](https://github.com/unicorn-engine/unicorn) CPU emulator, with simulated UEFI services and a model of the EC. They never touch real hardware:

```bash
uv run --with unicorn==2.1.4 python test.py
```

CI runs both on every push.

## Licence and disclaimer

[MIT](LICENSE). The binaries are compiled against EDK II headers, which are under the BSD-2-Clause-Patent licence ([notice](THIRD-PARTY-NOTICES-EDK2.txt)).

This project isn't affiliated with or endorsed by Lenovo or ITE. Lenovo and Yoga are trademarks of Lenovo. No Lenovo firmware is included. The software comes with no warranty, and you use it at your own risk.

## Credits

This project builds directly on other people's work:

- **[hz12opensource/zenbook-q410-powerfix](https://github.com/hz12opensource/zenbook-q410-powerfix)** was the main inspiration. Its reverse engineering of an ITE IT5571 EC showed how to talk to the EC's built-in flash utility from the host. EcRead's protocol follows its `ecflash/ec_isp.c`, and its mirroring and recovery notes shaped the safety design.
- **[tomios/ITE_ECTool](https://github.com/tomios/ITE_ECTool)** documents the same ITE flash-utility protocol in its `ITEFlash` UEFI tool.
- **[Chromium EC `iteflash`](https://chromium.googlesource.com/chromiumos/platform/ec/+/main/util/iteflash.cc)** confirmed the meaning of the ITE flash commands, including the 1 KiB erase.
- **[metacrito/yoga-bios-unlock](https://github.com/metacrito/yoga-bios-unlock)**, **[Matthias Hauber's Yoga Slim 7 write-up](https://matthiashauber.de/Hardware/Lenovo%20Yoga%20Slim%207/BIOS%20unlock/)** and the **[original Zhihu article](https://zhuanlan.zhihu.com/p/184982689)** described earlier Yoga BIOS unlocks and were the starting point for looking at this model. Their CMOS-index method isn't the mechanism used here.
- **[EDK II](https://github.com/tianocore/edk2)** provides the UEFI headers and the UEFI Shell, **[Zig](https://ziglang.org)** the compiler, and **[Unicorn](https://github.com/unicorn-engine/unicorn)** the emulator used for the tests.

No code was copied from these projects; the tools are independent implementations. Pinned versions and file hashes of the protocol sources are in [REFERENCES.md](REFERENCES.md).
