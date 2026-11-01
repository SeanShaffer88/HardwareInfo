# HardwareInfo roadmap

v0.5 rounded out the peripheral view: full PnP device inventory
(`hw_devices_json` — every present device with class, enumerator,
hardware IDs, literal vendor/device ids, and the devnode problem
code), wave audio devices (`hw_audio_json`), and printers
(`hw_printers_json`).

## Later

- Audio endpoint state and defaults (which endpoint is default,
  active/disabled/unplugged) need the MMDevice COM API rather
  than the legacy wave caps — possible future upgrade of
  `hw_audio_json`, keeping the same fields plus only what the OS
  reports.
- Temperatures/voltages beyond what a device itself reports are
  vendor-specific and often need a kernel driver — likely to
  stay out; will document rather than fake.

## Non-goals

- No writes, ever. Inventory only.
