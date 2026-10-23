# HardwareInfo roadmap

## Next

- **Physical disks**: model, serial, interface (NVMe/SATA/USB),
  size, and health via IOCTL_STORAGE_QUERY_PROPERTY + SMART status
  — the logical-volume view in v0.1 can't tell two partitions on
  one SSD from two drives.
- **RAM modules**: capacity/speed/manufacturer per slot via SMBIOS
  tables (GetSystemFirmwareTable) — also upgrades the board section
  from registry data to the full SMBIOS record.
- **GPU details**: dedicated VRAM and driver version via DXGI
  adapter enumeration.

## Later

- Temperatures/voltages are vendor-specific and often need a kernel
  driver — likely to stay out; will document rather than fake.
- TPM presence/version, Secure Boot state, firmware mode
  (UEFI/Legacy) — a natural "platform readiness" section.
- Battery health (designed vs full-charge capacity) via the battery
  device IOCTLs.

## Non-goals

- No writes, ever. Inventory only.
