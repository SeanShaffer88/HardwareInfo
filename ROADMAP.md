# HardwareInfo roadmap

v0.4 shipped the roadmap's two open items: full SMART tables
(`hw_smart_json` — raw ATA attributes plus the NVMe health log,
no invented labels beyond the documented generic set) and Secure
Boot capability (`secure_boot_capable`, tri-state with an honest
`null` when the firmware variable can't be read unelevated).

## Later

- Temperatures/voltages beyond what a device itself reports are
  vendor-specific and often need a kernel driver — likely to
  stay out; will document rather than fake.

## Non-goals

- No writes, ever. Inventory only.
