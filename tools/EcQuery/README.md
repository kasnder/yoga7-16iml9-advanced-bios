# EcQuery.efi

Read-only diagnostic. It prints the SMBIOS model, BIOS version and EC revision, and the `CrbItem` variable (or its absence). On uppercase **Q** it sends EC command `0x41` once and prints the reply:

| Reply | Meaning |
| --- | --- |
| `0xEE` | Gate enabled (EC RAM flag is `0xCF`) |
| `0x00` | Gate disabled |
| Anything else, or a timeout | Stop; don't retry straight away |

Any other key exits without touching the EC. It writes nothing. Its platform check accepts names that *start* with `LENOVO`/`83DL`/`NWCN27WW`; the tools that write anything require exact matches.

`EcEnable.efi` key **S** does the same query, so you only need EcQuery if you want to see the SMBIOS details.

- Source: `EcQuery.c`, `MinimalRuntime.c` (minimal `Print`, port I/O and string helpers instead of the EDK II libraries).
- Tests: `emulate.py`, 17 scenarios.
