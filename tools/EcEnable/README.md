# EcEnable.efi

Enables or disables the hidden Advanced and Power menus. See [docs/USAGE.md](../../docs/USAGE.md) for the full procedure.

| Keys | Action |
| --- | --- |
| **S** | Query the gate only (`0x41`) |
| **E**, then **Y** | Enable: set `CrbItem = 0x16` (attributes `0x07`) and read it back, then send EC `0x40` once and expect `0xEE` |
| **D**, then **Y** | Disable: send EC `0x42` once and expect `0x00`, then delete `CrbItem` if it holds exactly `0x16` |
| anything else | Exit without changes |

Safeguards:

- **Platform:** it requires exactly `LENOVO`, `83DL` and `NWCN27WW` in SMBIOS.
- **Variable check:** it refuses to enable if `CrbItem` holds anything other than nothing or this tool's exact value.
- **Variable first:** it writes and reads back the variable before any EC flash command, so a write-protected variable stops it early.
- **Commands:** it sends only `0x40`, `0x41` and `0x42`, with at most one `0x40` or `0x42` per run. Port access runs at `TPL_NOTIFY`.
- **Stops on errors:** after a timeout or unexpected byte following a write, it sends nothing more.

An `0xEE` reply proves only the EC's RAM flag. Check the flash with `EcRead.efi` afterwards: expect `CF` followed by 1023 × `FF`.

The EC gate resets on reboot while `CrbItem` stays set, so the menus show for one boot. Run `E` again to show them again; see [Known issues](../../README.md#known-issues). Disable has only been tested in the emulator.

- Source: `EcEnable.c`, `MinimalRuntime.c`, `Target.inc`.
- Tests: `emulate.py`, 32 scenarios. The EC model follows the traced handlers: RAM flag first, then a 1 KiB erase, then a one-byte write. The tests also model a skipped write, an EC that ignores the command and a stuck or silent EC.
