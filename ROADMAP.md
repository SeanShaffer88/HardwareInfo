# HardwareInfo roadmap

## Next

- **Full SMART attribute tables**: raw attribute id/value/worst/
  threshold per ATA drive plus the NVMe health log — v0.2 ships
  the failure-prediction verdict only. Attribute meanings are
  vendor-specific, so the design rule stays "raw reported values,
  no invented labels beyond the documented generic set".

## Later

- Temperatures/voltages are vendor-specific and often need a kernel
  driver — likely to stay out; will document rather than fake.
- Secure Boot *capability* (vs currently-enabled state, v0.3) needs
  the firmware environment variable, which requires the
  SE_SYSTEM_ENVIRONMENT privilege — only if it can degrade
  honestly unelevated.

## Non-goals

- No writes, ever. Inventory only.
