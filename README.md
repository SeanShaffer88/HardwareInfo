# HardwareInfo

A hardware inventory of the machine — CPU, OS, memory, disks, GPUs,
monitors, network adapters, battery, motherboard/BIOS — as
structured JSON behind one clean C ABI. Pure Rust, zero
dependencies, hand-declared Win32 bindings. Library #8 in the
Windows DLL Collection.

Read-only by design: HardwareInfo only ever queries. Each section
is an independent probe, so a caller never pays for inventory it
doesn't need — and one probe's failure never poisons the others.

## ABI (`include/hardwareinfo.h`, prefix `hw_`)

| Function | Returns |
|---|---|
| `hw_cpu_json()` | `{"brand","vendor","architecture","physical_cores","logical_processors","max_mhz","features":[…]}` |
| `hw_os_json()` | `{"product_name","display_version","edition","build","ubr","computer_name","architecture"}` |
| `hw_memory_json()` | `{"total_phys_bytes","avail_phys_bytes","total_pagefile_bytes","avail_pagefile_bytes","load_percent"}` |
| `hw_disks_json()` | Array of `{"letter","type","label","filesystem","total_bytes","free_bytes"}` per logical drive. |
| `hw_gpus_json()` | Array of `{"name","device"}` (mirroring drivers skipped). |
| `hw_monitors_json()` | Array of `{"name","width","height","primary"}`. |
| `hw_network_json()` | Array of `{"name","description","mac","type","up","ipv4":[],"ipv6":[]}`. |
| `hw_battery_json()` | `{"present","ac_online","charging","percent"}` (−1 = unknown percentage). |
| `hw_board_json()` | `{"system_manufacturer","system_product","board_manufacturer","board_product","bios_vendor","bios_version","bios_date"}` |
| `hw_system_json()` | All nine sections in one object; on Windows a failed section appears as `{"error": "…"}` in place of its data. |
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
- **Disks**: logical volumes — type, volume label, filesystem, and
  free/total space per letter.
- **Network**: `GetAdaptersAddresses` with MAC, adapter kind
  (ethernet/wireless/loopback/tunnel), operational state, and all
  unicast IPv4/IPv6 addresses.
- **Board/BIOS**: the registry BIOS key — the same data firmware
  reports to Windows.

Struct layouts and linked-list offsets (SYSTEM_INFO, the adapter
chain) are used only where the ABI is documented and stable across
x86_64 and ARM64 Windows.

## Verification

- Unit tests cover the JSON shapes and escaping, and the
  off-Windows contract (every probe is a precise `NOT_SUPPORTED`).
- **CI (`tests/roundtrip.rs`, Windows)**: runs every probe against
  the CI machine and asserts the invariants that hold on any real
  Windows box — a named CPU with ≥1 logical processor, a Windows OS
  with a real build number, nonzero physical memory, a `C:` drive
  with capacity, well-formed arrays for GPU/monitor/network, and a
  system document containing all sections.
- Gate (WinDevKit `tools/gate.sh`): fmt, clippy on host **and**
  `x86_64-pc-windows-msvc` with `-D warnings`, full tests — green.
  All extern blocks carry their `#[link(name = "...")]` (kernel32,
  user32, advapi32, iphlpapi, ntdll).

Honest limits: reported values are what Windows reports. GPU VRAM,
physical-disk SMART data, RAM module details, and temperatures are
not in v0.1 (see ROADMAP).

## License

MIT © 2026 Sean Shaffer.
