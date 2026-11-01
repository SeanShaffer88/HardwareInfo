# HardwareInfo roadmap

## Next

- **Platform readiness**: TPM presence/version, Secure Boot state,
  firmware mode (UEFI/Legacy) — a natural "is this machine ready
  for X" section to sit beside the inventory probes.
- **Battery health**: designed vs full-charge capacity via the
  battery device IOCTLs, beside the charge percentage v0.1 reports.

## Later

- Full SMART attribute tables (v0.2 ships the failure-prediction
  verdict only) — attribute meanings are vendor-specific, so this
  needs a careful "raw values, no invented labels" design.
- Temperatures/voltages are vendor-specific and often need a kernel
  driver — likely to stay out; will document rather than fake.

## Non-goals

- No writes, ever. Inventory only.
