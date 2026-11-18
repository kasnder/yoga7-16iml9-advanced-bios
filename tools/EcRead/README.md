# EcRead.efi

Saves the EC's 1 KiB flag sector (`0x01FC00..0x01FFFF`) to the USB stick, so you can back it up before enabling and check it afterwards.

On uppercase **R** it:

1. checks the EC is idle, then enters the EC's built-in flash utility (`DC`, expects `33`);
2. reads the flash ID and accepts only `FF FF FE` (ITE internal flash);
3. reads flash bytes `0..31` and checks them against the NWEC27WW image (`Expected.inc`);
4. reads the sector twice and requires both reads to match;
5. leaves the utility (`05`, a 1 s pause, `FC`);
6. only then writes `EC01FC00-00.bin` (or the next free number, up to `-99`) to the root of the volume it was started from, and prints a CRC32 of the data.

It uses only the SPI read commands `9F` and `0B`. It never erases or programs flash itself, but:

- **the EC stops its normal work** (fans, charging, keyboard) while in the utility, for a few seconds;
- **leaving restarts the EC's firmware initialisation**, which can update its own flash metadata;
- after a timeout or unexpected reply it sends nothing more and prints `EC exit NOT confirmed`. The EC may then stay in the utility until a power cycle: hold the power button 15–20 s, and if that fails, disconnect the battery.

Port access runs at `TPL_NOTIFY`. Each wait is limited to 250 ms, with an overall limit of about 30 s.

Expected contents: `00` + 1023 × `FF` when disabled, `CF` + 1023 × `FF` when enabled.

- Source: `EcRead.c`, `MinimalRuntime.c`, `Target.inc` (platform check), `Expected.inc` (32 bytes of the NWEC27WW image header).
- Tests: `emulate.py`, 51 scenarios, including slow and stuck EC models.
