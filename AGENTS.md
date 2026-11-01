# HardwareInfo — agent notes

- Every extern block MUST carry #[link(name = "...")] (kernel32 /
  user32 / advapi32 / iphlpapi / ntdll / dxgi / setupapi / cfgmgr32 /
  winmm / winspool). Clippy and
  check cannot catch a missing one; CI's Windows link can.
- Read-only is the product: no setters, no IOCTLs that mutate, ever.
  The storage IOCTLs used (QUERY_PROPERTY, GET_DRIVE_GEOMETRY_EX,
  GET_LENGTH_INFO, PREDICT_FAILURE) are queries — keep it that way.
  PREDICT_FAILURE is a verdict; the SMART tables behind
  hw_smart_json are receive/read queries only (ATA features
  0xD0/0xD1 via SMART_RCV_DRIVE_DATA, NVMe log page 02h via the
  protocol-specific query) — never send a SMART command that
  changes drive state (no ENABLE/DISABLE, no offline tests). Battery IOCTLs
  (QUERY_TAG, QUERY_INFORMATION) are queries too — never touch
  BATTERY_SET_* levels.
- SetupDi records are byte buffers with house cbSizes: 32 for both
  SP_DEVICE_INTERFACE_DATA and SP_DEVINFO_DATA on 64-bit, and 8 for
  the W interface-detail record (path WCHARs at offset 4). SetupDi
  serves battery enumeration (GUID_DEVINTERFACE_BATTERY), TPM
  presence (Security devices class), and the full PnP inventory
  (hw_devices_json: DIGCF_ALLCLASSES + per-property two-call
  reads; DevInst is the u32 @20 in SP_DEVINFO_DATA, fed to
  CM_Get_DevNode_Status for problem_code/DN_STARTED — null when
  that fails, never a guess). Vendor/device ids come ONLY from
  VID_/VEN_ + PID_/DEV_ tags literally in the first hardware ID
  (device_ids_from_hardware_id, pure in src/lib.rs). TPM version comes ONLY
  from the reported device description text — don't infer it.
  BATTERY_INFORMATION offsets (Technology @4, Chemistry @8,
  Designed @12, Full @16, Cycles @32; 0xFFFFFFFF = unknown) and
  the health ratio are pure in src/lib.rs — keep them testable.
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
- SMART parsing is pure in src/lib.rs: ATA records at offset 2,
  30 x 12 bytes (threshold byte @slot+1 in the thresholds block),
  raw is 48-bit; NVMe health-log counters are 128-bit (low 64
  kept), temperature u16le Kelvin @1. Attribute names cover ONLY
  the documented generic set in smart_attribute_name — unknown
  ids stay blank, never guessed. smart_disks opens RW then R
  then 0 (SMART paths historically want RW handles); the
  commands stay read-only regardless. Secure Boot capability is
  Some(true) when enabled, else the SecureBoot UEFI variable
  under a just-for-the-call SE_SYSTEM_ENVIRONMENT enable —
  AdjustTokenPrivileges "succeeds" without the privilege held,
  so the ERROR_NOT_ALL_ASSIGNED (1300) check is load-bearing;
  indeterminate stays None (JSON null), never a guess.
- Wave caps parsing is pure in src/lib.rs (shared WAVEOUTCAPSW /
  WAVEINCAPSW prefix: wMid @0, wPid @2, version @4 high/low byte
  major.minor, szPname WCHAR[32] @8, wChannels @76) — names are
  capped at 31 chars by the API itself; don't "upgrade" them from
  registry guesses. PRINTER_INFO_2 is walked with pointer-sized
  offsets (13 pointer fields, then 8 u32s: Attributes @+0,
  Status @+20, cJobs @+24); its strings are absolute pointers
  into the EnumPrinters buffer and are bounds-checked back into
  that buffer (packed_wide_string) before any read.
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
