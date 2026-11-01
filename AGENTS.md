# HardwareInfo — agent notes

- Every extern block MUST carry #[link(name = "...")] (kernel32 /
  user32 / advapi32 / iphlpapi / ntdll / dxgi). Clippy and check cannot
  catch a missing one; CI's Windows link can.
- Read-only is the product: no setters, no IOCTLs that mutate, ever.
  The storage IOCTLs used (QUERY_PROPERTY, GET_DRIVE_GEOMETRY_EX,
  GET_LENGTH_INFO, PREDICT_FAILURE) are queries — keep it that way.
  PREDICT_FAILURE is a verdict, not full SMART; never present it as
  more than ok / failure_predicted / unknown.
- Adapter-chain parsing uses documented x64/ARM64 offsets into
  IP_ADAPTER_ADDRESSES (FriendlyName 72, Description 64, MAC at 80
  len 88, IfType 100, OperStatus 104; unicast Address sockaddr at
  +16, Next at +8). These offsets are ABI-stable for 64-bit
  Windows; re-verify against iphlpapi headers before trusting them
  on a new field, and never extend them to 32-bit targets without
  a separate layout.
- SYSTEM_INFO is read from a byte buffer at documented offsets
  (arch @0, processors @32) to avoid union repr hazards.
- SMBIOS parsing lives in src/smbios.rs and is PURE (no platform
  calls) so synthetic tables test it on any OS — keep it there.
  Formatted fields are length-gated (type 17 extended size @0x1C
  only when the structure covers it; extended speeds @0x54/0x58
  are SMBIOS 3.3+). Size word: 0 = empty slot (skip), 0x7FFF =
  extended size in MB, 0xFFFF = unknown, bit 15 = KB granularity.
- STORAGE_DEVICE_DESCRIPTOR parsing is pure in src/lib.rs
  (string offsets @12/16/20/24, BusType @28, removable @10).
  PhysicalDrive open order matters: GENERIC_READ (elevated) then
  zero-access fallback for the FILE_ANY_ACCESS queries; drives
  that don't open are skipped, never an error.
- DXGI is hand-rolled COM: vtable slots EnumAdapters1 = 12
  (IDXGIFactory1) and GetDesc1 = 10 (IDXGIAdapter1), Release = 2;
  IID_IDXGIFactory1 is in platform.rs. Re-verify against dxgi.h
  before trusting a new slot. Enrichment is best-effort — a DXGI
  or registry failure must never fail hw_gpus_json (v0.1 contract).
- Section independence is a contract: hw_system_json isolates
  per-section errors as {"error": ...} — don't make one probe's
  failure fail the document. Off-Windows the aggregate fails
  wholesale by design (platform_available gate).
- Values are "what Windows reports" — never invent VRAM, temps, or
  SMART data the APIs didn't return.
- Gate: WinDevKit tools/gate.sh (fmt + clippy -D warnings BOTH
  targets + FULL tests).
