# HardwareInfo

A hardware inventory of the machine — CPU, OS, memory, RAM modules,
logical + physical disks, GPUs, monitors, network adapters, battery
(+ wear), motherboard/BIOS, platform readiness (TPM / Secure Boot /
firmware mode) — as structured JSON behind one clean C ABI. Pure
Rust, zero dependencies, hand-declared Win32 bindings. Library #8 in
the Windows DLL Collection.

Read-only by design: HardwareInfo only ever queries. Each section
is an independent probe, so a caller never pays for inventory it
doesn't need — and one probe's failure never poisons the others.

## ABI (`include/hardwareinfo.h`, prefix `hw_`)

| Function | Returns |
|---|---|
| `hw_cpu_json()` | `{"brand","vendor","architecture","physical_cores","logical_processors","max_mhz","features":[…]}` |
| `hw_os_json()` | `{"product_name","display_version","edition","build","ubr","computer_name","architecture"}` |
| `hw_memory_json()` | `{"total_phys_bytes","avail_phys_bytes","total_pagefile_bytes","avail_pagefile_bytes","load_percent"}` |
| `hw_ram_json()` | Array of `{"slot","bank","manufacturer","part_number","serial","capacity_bytes","speed_mts","configured_speed_mts","type","form_factor","data_width_bits","total_width_bits"}` per installed module (SMBIOS). |
| `hw_disks_json()` | Array of `{"letter","type","label","filesystem","total_bytes","free_bytes"}` per logical drive. |
| `hw_physical_disks_json()` | Array of `{"index","model","vendor","revision","serial","interface","media","removable","size_bytes","health"}` per physical drive. |
| `hw_gpus_json()` | Array of `{"name","device","vendor_id","device_id","dedicated_video_memory_bytes","dedicated_system_memory_bytes","shared_system_memory_bytes","driver_version","luid"}` (mirroring drivers skipped). |
| `hw_monitors_json()` | Array of `{"name","width","height","primary"}`. |
| `hw_network_json()` | Array of `{"name","description","mac","type","up","ipv4":[],"ipv6":[]}`. |
| `hw_battery_json()` | `{"present","ac_online","charging","percent"}` (−1 = unknown percentage). |
| `hw_batteries_json()` | Array of `{"name","manufacturer","chemistry","rechargeable","designed_capacity_mwh","full_charge_capacity_mwh","health_percent","cycle_count"}` per battery device. |
| `hw_board_json()` | `{"system_manufacturer","system_product","board_manufacturer","board_product","bios_vendor","bios_version","bios_date","system_version","system_serial","board_version","board_serial","system_uuid"}` |
| `hw_platform_json()` | `{"firmware_type","secure_boot_enabled","tpm_present","tpm_version","tpm_device"}` |
| `hw_system_json()` | All thirteen sections in one object; on Windows a failed section appears as `{"error": "…"}` in place of its data. |
| `hw_version*`, `hw_last_error*`, `hw_free_string` | Version info, thread-local errors, disposal. |

## How the data is gathered

- **CPU**: brand/vendor/clock from the registry processor key,
  physical core count by walking `GetLogicalProcessorInformationEx`
  core entries (not just dividing logical by two), logical count and
  architecture from `GetNativeSystemInfo`, and the feature list
  (SSE4.2 → AVX-512F, AES, FMA, BMI, POPCNT…) from CPUID via the
  standard detection macros.
- **OS**: build from `RtlGetVersion` (never the manifest-shimmed
  version APIs), product/edition/display-version/UBR from the
  registry, computer name from the OS.
- **RAM modules**: SMBIOS type 17 (Memory Device) structures from
  `GetSystemFirmwareTable('RSMB')` — slot/bank locators, capacity
  (including the extended-size escape), rated and configured speed,
  type, form factor, and widths. Empty slots are skipped. Parsing
  is pure (`src/smbios.rs`) and unit-tested against synthetic
  tables on any OS.
- **Disks**: logical volumes — type, volume label, filesystem, and
  free/total space per letter — plus the physical view: per-drive
  vendor/model/revision/serial and bus (`nvme`/`sata`/`usb`/…) from
  `IOCTL_STORAGE_QUERY_PROPERTY`, total size from drive geometry,
  SSD/HDD from the seek-penalty descriptor, and the SMART
  failure-prediction verdict (`ok` / `failure_predicted` /
  `unknown`). All query-only IOCTLs; drives that can't be opened
  are skipped (a zero-access fallback handle covers the
  unelevated case for the `FILE_ANY_ACCESS` queries).
- **GPUs**: display adapters from `EnumDisplayDevices`, enriched
  with DXGI data matched by card name — dedicated/shared memory,
  vendor/device IDs, LUID — and the driver version from the
  display device's registry key (which also supplies a VRAM
  fallback). Enrichment is best-effort: a card Windows enumerates
  is reported with or without DXGI.
- **Network**: `GetAdaptersAddresses` with MAC, adapter kind
  (ethernet/wireless/loopback/tunnel), operational state, and all
  unicast IPv4/IPv6 addresses.
- **Board/BIOS**: SMBIOS types 0/1/2 (BIOS, System, Baseboard),
  including serials and the system UUID; the registry BIOS key —
  the same data firmware reports to Windows — fills any gaps and
  carries the section alone when the firmware table is unreadable.
- **Batteries**: per-device wear data from the battery class
  driver — devices enumerated with SetupDi
  (`GUID_DEVINTERFACE_BATTERY`), then `IOCTL_BATTERY_QUERY_TAG` +
  `IOCTL_BATTERY_QUERY_INFORMATION` for designed vs full-charge
  capacity (mWh), cycle count, chemistry, name, and manufacturer.
  `health_percent` is the plain full/designed ratio (−1 when a
  capacity is reported unknown).
- **Platform readiness**: firmware mode from `GetFirmwareType`,
  Secure Boot state from the `SecureBoot\State` registry value
  Windows itself maintains, and TPM presence/version from the
  Security devices setup class (the description Windows reports,
  e.g. "Trusted Platform Module 2.0").

Struct layouts and linked-list offsets (SYSTEM_INFO, the adapter
chain, SMBIOS structures, the storage descriptor) are used only
where the ABI is documented and stable across x86_64 and ARM64
Windows. SMBIOS and storage-descriptor parsing is length-gated
and bounds-checked: truncated or malformed firmware data degrades
to missing fields, never to a guess.

## Verification

- Unit tests cover the JSON shapes and escaping, the pure parsers
  (synthetic SMBIOS tables, storage descriptor, seek-penalty and
  geometry buffers, DXGI name matching, BATTERY_INFORMATION and
  the health-ratio math), and the off-Windows contract (every
  probe is a precise `NOT_SUPPORTED`) — all runnable on any OS.
- **CI (`tests/roundtrip.rs`, Windows)**: runs every probe against
  the CI machine and asserts the invariants that hold on any real
  Windows box — a named CPU with ≥1 logical processor, a Windows OS
  with a real build number, nonzero physical memory, a `C:` drive
  with capacity, a `PhysicalDrive0` with nonzero size, populated
  RAM modules with real capacity, well-formed arrays for
  GPU/monitor/network/batteries, a platform section, and a system
  document containing all sections.
- Gate (WinDevKit `tools/gate.sh`): fmt, clippy on host **and**
  `x86_64-pc-windows-msvc` with `-D warnings`, full tests — green.
  All extern blocks carry their `#[link(name = "...")]` (kernel32,
  user32, advapi32, iphlpapi, ntdll, dxgi, setupapi).

Honest limits: reported values are what Windows reports. Disk
health is the SMART failure-prediction verdict only, battery
health is the capacities the battery itself reports, and the TPM
version is the one its Windows device description states. Full
SMART attribute tables and temperatures/voltages are not in v0.3
(see ROADMAP).

## License

MIT © 2026 sean.
