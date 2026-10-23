# HardwareInfo — agent notes

- Every extern block MUST carry #[link(name = "...")] (kernel32 /
  user32 / advapi32 / iphlpapi / ntdll). Clippy and check cannot
  catch a missing one; CI's Windows link can.
- Read-only is the product: no setters, no IOCTLs that mutate, ever.
- Adapter-chain parsing uses documented x64/ARM64 offsets into
  IP_ADAPTER_ADDRESSES (FriendlyName 72, Description 64, MAC at 80
  len 88, IfType 100, OperStatus 104; unicast Address sockaddr at
  +16, Next at +8). These offsets are ABI-stable for 64-bit
  Windows; re-verify against iphlpapi headers before trusting them
  on a new field, and never extend them to 32-bit targets without
  a separate layout.
- SYSTEM_INFO is read from a byte buffer at documented offsets
  (arch @0, processors @32) to avoid union repr hazards.
- Section independence is a contract: hw_system_json isolates
  per-section errors as {"error": ...} — don't make one probe's
  failure fail the document. Off-Windows the aggregate fails
  wholesale by design (platform_available gate).
- Values are "what Windows reports" — never invent VRAM, temps, or
  SMART data the APIs didn't return.
- Gate: WinDevKit tools/gate.sh (fmt + clippy -D warnings BOTH
  targets + FULL tests).
