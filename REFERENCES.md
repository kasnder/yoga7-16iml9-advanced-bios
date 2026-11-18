# References

## EC protocol and research

- [tomios/ITE_ECTool](https://github.com/tomios/ITE_ECTool): ITE UEFI flashing utility; source of the flash-utility protocol (pinned file: `ITEFlash/ITEFlash.c` at [`b8d3f85`](https://raw.githubusercontent.com/tomios/ITE_ECTool/b8d3f85f4470af79c743c9618db95d6b10268147/ITEFlash/ITEFlash.c), SHA256 `402907a736948d6fcb99436a8cccf63362f0b97f13ee1930b7218eaf3d09d9de`). It includes write operations.
- [hz12opensource/zenbook-q410-powerfix](https://github.com/hz12opensource/zenbook-q410-powerfix): ASUS Zenbook IT5571 EC research, flash protocol and mirroring analysis (pinned file: `ecflash/ec_isp.c` at [`ff08708`](https://raw.githubusercontent.com/hz12opensource/zenbook-q410-powerfix/ff0870853cfdd52dd858727d609f2d8a07a46a24/ecflash/ec_isp.c), SHA256 `f02094acd0ffc2c5a9e6731bffbdfa745cad3471f008ea11f035b946d38578a0`). Different hardware: its recovery behaviour isn't established for this Lenovo.
- [Chromium EC iteflash](https://chromium.googlesource.com/chromiumos/platform/ec/+/main/util/iteflash.cc): ITE debug and flashing reference, including the `D7` 1 KiB erase.
- [JohnDoe150489/I2C-Pico-USB-ITE-EC-prog](https://github.com/JohnDoe150489/I2C-Pico-USB-ITE-EC-prog): external ITE programmer.
- [minortex/ec_reverse](https://github.com/minortex/ec_reverse): EC reverse-engineering on other systems.

## Earlier Yoga unlock work

- [metacrito/yoga-bios-unlock](https://github.com/metacrito/yoga-bios-unlock)
- [Matthias Hauber: Lenovo Yoga Slim 7 BIOS unlock](https://matthiashauber.de/Hardware/Lenovo%20Yoga%20Slim%207/BIOS%20unlock/)
- [Original Zhihu article](https://zhuanlan.zhihu.com/p/184982689)

These cover older Yoga firmware and use a different (CMOS index) method, which isn't the mechanism used here.

## Build and test dependencies

- [EDK II](https://github.com/tianocore/edk2), tag `edk2-stable202408` (headers only). Source archive `edk2-edk2-stable202408.zip` SHA256 `02668de8b74133c51802e303cd35e28c8075d3e9c9c3e71f52dd4bc3a45db95f`.
- [Zig 0.13.0](https://ziglang.org/download/#release-0.13.0), used as the clang/lld cross-compiler.
- [Unicorn Engine](https://github.com/unicorn-engine/unicorn) 2.1.4, CPU emulator for the tests.
- [UEFI Shell](https://github.com/tianocore/edk2/releases/tag/edk2-stable202002) from `ShellBinPkg.zip`, to run the tools.
