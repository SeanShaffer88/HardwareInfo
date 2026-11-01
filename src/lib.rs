//! HardwareInfo — a hardware inventory of the machine (CPU, OS,
//! memory, RAM modules, logical + physical disks, GPUs, monitors,
//! network adapters, battery, motherboard/BIOS) as structured JSON
//! behind one clean C ABI, in pure Rust with zero dependencies and
//! hand-declared Win32 bindings.
//!
//! Read-only by design: the library only ever queries. Every section
//! is independently available so callers never pay for probes they
//! don't need, and a failure in one probe never poisons the others —
//! the aggregate `hw_system_json` reports per-section errors inline.

pub mod ffi;
pub mod platform;
pub mod smbios;

pub const VERSION: &str = "0.4.0";
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 4;
pub const VERSION_PATCH: u32 = 0;

// Error codes (mirror include/hardwareinfo.h).
pub const HW_OK: i32 = 0;
pub const ERR_INVALID_ARG: i32 = 1;
pub const ERR_NOT_SUPPORTED: i32 = 2;
pub const ERR_NOT_FOUND: i32 = 3;
pub const ERR_ACCESS_DENIED: i32 = 4;
pub const ERR_PLATFORM: i32 = 5;
pub const ERR_INTERNAL: i32 = 6;

/// The crate-wide result: failures carry a stable code + message.
pub type CResult<T> = Result<T, (i32, String)>;

#[derive(Debug, Default, Clone)]
pub struct CpuInfo {
    pub brand: String,
    pub vendor: String,
    pub architecture: String,
    pub physical_cores: u32,
    pub logical_processors: u32,
    pub max_mhz: u32,
    pub features: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct OsInfo {
    pub product_name: String,
    pub display_version: String,
    pub edition: String,
    pub build: u32,
    pub ubr: u32,
    pub computer_name: String,
    pub architecture: String,
}

#[derive(Debug, Default, Clone)]
pub struct MemoryInfo {
    pub total_phys_bytes: u64,
    pub avail_phys_bytes: u64,
    pub total_pagefile_bytes: u64,
    pub avail_pagefile_bytes: u64,
    pub load_percent: u32,
}

#[derive(Debug, Default, Clone)]
pub struct DiskInfo {
    pub letter: String,
    pub kind: String, // fixed / removable / network / cdrom / ramdisk / unknown
    pub label: String,
    pub filesystem: String,
    pub total_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Debug, Default, Clone)]
pub struct GpuInfo {
    pub name: String,
    pub device: String,
    /// DXGI vendor id formatted "0x10DE"; empty if no DXGI match.
    pub vendor_id: String,
    /// DXGI device id formatted "0x2684"; empty if no DXGI match.
    pub device_id: String,
    pub dedicated_video_memory_bytes: u64,
    pub dedicated_system_memory_bytes: u64,
    pub shared_system_memory_bytes: u64,
    /// Driver version string from the display device registry key; may be empty.
    pub driver_version: String,
    /// DXGI adapter LUID formatted "0x0000000000001234"; empty if no DXGI match.
    pub luid: String,
}

#[derive(Debug, Default, Clone)]
pub struct MonitorInfo {
    pub name: String,
    pub width: i32,
    pub height: i32,
    pub primary: bool,
}

#[derive(Debug, Default, Clone)]
pub struct AdapterInfo {
    pub name: String,
    pub description: String,
    pub mac: String,
    pub kind: String, // ethernet / wireless / loopback / tunnel / other
    pub up: bool,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct BatteryInfo {
    pub present: bool,
    pub ac_online: bool,
    pub charging: bool,
    pub percent: i32, // -1 unknown
}

#[derive(Debug, Default, Clone)]
pub struct BoardInfo {
    pub system_manufacturer: String,
    pub system_product: String,
    pub board_manufacturer: String,
    pub board_product: String,
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_date: String,
    /// SMBIOS type 1 version string; empty if firmware table unavailable.
    pub system_version: String,
    /// SMBIOS type 1 serial; empty if firmware table unavailable.
    pub system_serial: String,
    /// SMBIOS type 2 version string; empty if firmware table unavailable.
    pub board_version: String,
    /// SMBIOS type 2 serial; empty if firmware table unavailable.
    pub board_serial: String,
    /// SMBIOS type 1 UUID in canonical text form; empty if unset/unavailable.
    pub system_uuid: String,
}

#[derive(Debug, Default, Clone)]
pub struct PhysicalDiskInfo {
    /// `\\.\PhysicalDriveN` index.
    pub index: u32,
    pub model: String,
    pub vendor: String,
    pub revision: String,
    pub serial: String,
    /// Bus token from STORAGE_BUS_TYPE, e.g. "nvme", "sata", "usb".
    pub interface: String,
    /// "ssd" / "hdd" from the seek-penalty descriptor, else "unknown".
    pub media: String,
    pub removable: bool,
    pub size_bytes: u64,
    /// SMART failure-prediction verdict: "ok" / "failure_predicted" / "unknown".
    pub health: String,
}

#[derive(Debug, Default, Clone)]
pub struct RamModule {
    pub slot: String,
    pub bank: String,
    pub manufacturer: String,
    pub part_number: String,
    pub serial: String,
    pub capacity_bytes: u64,
    /// Rated speed in MT/s; 0 if firmware does not report it.
    pub speed_mts: u32,
    /// Configured speed in MT/s; 0 if firmware does not report it.
    pub configured_speed_mts: u32,
    /// e.g. "DDR4", "DDR5", "LPDDR5".
    pub memory_type: String,
    /// e.g. "DIMM", "SODIMM".
    pub form_factor: String,
    pub data_width_bits: u32,
    pub total_width_bits: u32,
}

#[derive(Debug, Default, Clone)]
pub struct PlatformInfo {
    /// "uefi" / "bios" (legacy) / "unknown" from GetFirmwareType.
    pub firmware_type: String,
    /// UEFISecureBootEnabled from the SecureBoot\State registry key;
    /// false when the key is absent (legacy firmware).
    pub secure_boot_enabled: bool,
    /// Whether the firmware exposes the SecureBoot UEFI variable
    /// in the current boot (Some(false) on legacy BIOS, where the
    /// firmware-variable call fails with ERROR_INVALID_FUNCTION).
    /// None when it could not be determined — typically because
    /// SE_SYSTEM_ENVIRONMENT was not grantable unelevated. In JSON
    /// this is true / false / null.
    pub secure_boot_capable: Option<bool>,
    /// A Trusted Platform Module device is present (Security
    /// devices setup class).
    pub tpm_present: bool,
    /// "2.0" / "1.2" when the device description states it, else "".
    pub tpm_version: String,
    /// The TPM device description Windows reports; empty if none.
    pub tpm_device: String,
}

#[derive(Debug, Default, Clone)]
pub struct BatteryHealth {
    pub name: String,
    pub manufacturer: String,
    /// Four-character chemistry code as reported, e.g. "LION".
    pub chemistry: String,
    pub rechargeable: bool,
    /// 0 when the battery reports BATTERY_UNKNOWN_CAPACITY.
    pub designed_capacity_mwh: u32,
    /// 0 when the battery reports BATTERY_UNKNOWN_CAPACITY.
    pub full_charge_capacity_mwh: u32,
    /// full / designed * 100 from the reported capacities;
    /// -1 when either capacity is unknown.
    pub health_percent: i32,
    pub cycle_count: u32,
}

/// One ATA SMART attribute entry, values exactly as reported.
/// Meanings (including how `raw` is packed) are vendor-specific
/// beyond the small documented generic set behind `name`;
/// `name` is empty for ids outside that set.
#[derive(Debug, Default, Clone)]
pub struct SmartAttribute {
    pub id: u32,
    pub name: String,
    pub flags: u32,
    pub value: u32,
    pub worst: u32,
    /// 0 when the thresholds table could not be read.
    pub threshold: u32,
    /// The 48-bit raw value, as one integer.
    pub raw: u64,
}

/// The NVMe SMART / Health Information log (log identifier 02h),
/// fields as reported. Count fields are the low 64 bits of the
/// log's 128-bit integers.
#[derive(Debug, Default, Clone)]
pub struct NvmeHealth {
    pub critical_warning: u32,
    pub temperature_kelvin: u32,
    /// temperature_kelvin - 273; 0 when no sensor value was reported.
    pub temperature_celsius: i32,
    pub available_spare_percent: u32,
    pub available_spare_threshold_percent: u32,
    pub percentage_used: u32,
    /// In units of 500,960 bytes, per the NVMe specification.
    pub data_units_read: u64,
    pub data_units_written: u64,
    pub power_cycles: u64,
    pub power_on_hours: u64,
    pub unsafe_shutdowns: u64,
    pub media_errors: u64,
    pub error_log_entries: u64,
}

#[derive(Debug, Default, Clone)]
pub struct DiskSmart {
    /// `\\.\PhysicalDriveN` index, matching PhysicalDiskInfo.
    pub index: u32,
    /// Bus token as in PhysicalDiskInfo (nvme / sata / ...).
    pub interface: String,
    /// "ata_smart" / "nvme_health_log" / "none" (no SMART-style
    /// data answered for this drive).
    pub source: String,
    pub ata_attributes: Vec<SmartAttribute>,
    pub nvme: Option<NvmeHealth>,
}

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn q(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

impl CpuInfo {
    pub fn to_json(&self) -> String {
        let feats: Vec<String> = self.features.iter().map(|f| q(f)).collect();
        format!(
            "{{\"brand\":{},\"vendor\":{},\"architecture\":{},\"physical_cores\":{},\"logical_processors\":{},\"max_mhz\":{},\"features\":[{}]}}",
            q(&self.brand),
            q(&self.vendor),
            q(&self.architecture),
            self.physical_cores,
            self.logical_processors,
            self.max_mhz,
            feats.join(",")
        )
    }
}

impl OsInfo {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"product_name\":{},\"display_version\":{},\"edition\":{},\"build\":{},\"ubr\":{},\"computer_name\":{},\"architecture\":{}}}",
            q(&self.product_name),
            q(&self.display_version),
            q(&self.edition),
            self.build,
            self.ubr,
            q(&self.computer_name),
            q(&self.architecture)
        )
    }
}

impl MemoryInfo {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"total_phys_bytes\":{},\"avail_phys_bytes\":{},\"total_pagefile_bytes\":{},\"avail_pagefile_bytes\":{},\"load_percent\":{}}}",
            self.total_phys_bytes,
            self.avail_phys_bytes,
            self.total_pagefile_bytes,
            self.avail_pagefile_bytes,
            self.load_percent
        )
    }
}

impl DiskInfo {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"letter\":{},\"type\":{},\"label\":{},\"filesystem\":{},\"total_bytes\":{},\"free_bytes\":{}}}",
            q(&self.letter),
            q(&self.kind),
            q(&self.label),
            q(&self.filesystem),
            self.total_bytes,
            self.free_bytes
        )
    }
}

pub fn disks_json(disks: &[DiskInfo]) -> String {
    let items: Vec<String> = disks.iter().map(|d| d.to_json()).collect();
    format!("[{}]", items.join(","))
}

pub fn gpus_json(gpus: &[GpuInfo]) -> String {
    let items: Vec<String> = gpus
        .iter()
        .map(|g| {
            format!(
                "{{\"name\":{},\"device\":{},\"vendor_id\":{},\"device_id\":{},\"dedicated_video_memory_bytes\":{},\"dedicated_system_memory_bytes\":{},\"shared_system_memory_bytes\":{},\"driver_version\":{},\"luid\":{}}}",
                q(&g.name),
                q(&g.device),
                q(&g.vendor_id),
                q(&g.device_id),
                g.dedicated_video_memory_bytes,
                g.dedicated_system_memory_bytes,
                g.shared_system_memory_bytes,
                q(&g.driver_version),
                q(&g.luid)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

pub fn physical_disks_json(disks: &[PhysicalDiskInfo]) -> String {
    let items: Vec<String> = disks
        .iter()
        .map(|d| {
            format!(
                "{{\"index\":{},\"model\":{},\"vendor\":{},\"revision\":{},\"serial\":{},\"interface\":{},\"media\":{},\"removable\":{},\"size_bytes\":{},\"health\":{}}}",
                d.index,
                q(&d.model),
                q(&d.vendor),
                q(&d.revision),
                q(&d.serial),
                q(&d.interface),
                q(&d.media),
                d.removable,
                d.size_bytes,
                q(&d.health)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

pub fn ram_json(modules: &[RamModule]) -> String {
    let items: Vec<String> = modules
        .iter()
        .map(|m| {
            format!(
                "{{\"slot\":{},\"bank\":{},\"manufacturer\":{},\"part_number\":{},\"serial\":{},\"capacity_bytes\":{},\"speed_mts\":{},\"configured_speed_mts\":{},\"type\":{},\"form_factor\":{},\"data_width_bits\":{},\"total_width_bits\":{}}}",
                q(&m.slot),
                q(&m.bank),
                q(&m.manufacturer),
                q(&m.part_number),
                q(&m.serial),
                m.capacity_bytes,
                m.speed_mts,
                m.configured_speed_mts,
                q(&m.memory_type),
                q(&m.form_factor),
                m.data_width_bits,
                m.total_width_bits
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

pub fn monitors_json(monitors: &[MonitorInfo]) -> String {
    let items: Vec<String> = monitors
        .iter()
        .map(|m| {
            format!(
                "{{\"name\":{},\"width\":{},\"height\":{},\"primary\":{}}}",
                q(&m.name),
                m.width,
                m.height,
                m.primary
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

pub fn adapters_json(adapters: &[AdapterInfo]) -> String {
    let items: Vec<String> = adapters
        .iter()
        .map(|a| {
            let v4: Vec<String> = a.ipv4.iter().map(|s| q(s)).collect();
            let v6: Vec<String> = a.ipv6.iter().map(|s| q(s)).collect();
            format!(
                "{{\"name\":{},\"description\":{},\"mac\":{},\"type\":{},\"up\":{},\"ipv4\":[{}],\"ipv6\":[{}]}}",
                q(&a.name),
                q(&a.description),
                q(&a.mac),
                q(&a.kind),
                a.up,
                v4.join(","),
                v6.join(",")
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

impl BatteryInfo {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"present\":{},\"ac_online\":{},\"charging\":{},\"percent\":{}}}",
            self.present, self.ac_online, self.charging, self.percent
        )
    }
}

impl PlatformInfo {
    pub fn to_json(&self) -> String {
        let capable = match self.secure_boot_capable {
            Some(value) => value.to_string(),
            None => "null".to_string(),
        };
        format!(
            "{{\"firmware_type\":{},\"secure_boot_enabled\":{},\"secure_boot_capable\":{},\"tpm_present\":{},\"tpm_version\":{},\"tpm_device\":{}}}",
            q(&self.firmware_type),
            self.secure_boot_enabled,
            capable,
            self.tpm_present,
            q(&self.tpm_version),
            q(&self.tpm_device)
        )
    }
}

pub fn batteries_json(batteries: &[BatteryHealth]) -> String {
    let items: Vec<String> = batteries
        .iter()
        .map(|b| {
            format!(
                "{{\"name\":{},\"manufacturer\":{},\"chemistry\":{},\"rechargeable\":{},\"designed_capacity_mwh\":{},\"full_charge_capacity_mwh\":{},\"health_percent\":{},\"cycle_count\":{}}}",
                q(&b.name),
                q(&b.manufacturer),
                q(&b.chemistry),
                b.rechargeable,
                b.designed_capacity_mwh,
                b.full_charge_capacity_mwh,
                b.health_percent,
                b.cycle_count
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

fn nvme_health_json(health: &NvmeHealth) -> String {
    format!(
        "{{\"critical_warning\":{},\"temperature_kelvin\":{},\"temperature_celsius\":{},\"available_spare_percent\":{},\"available_spare_threshold_percent\":{},\"percentage_used\":{},\"data_units_read\":{},\"data_units_written\":{},\"power_cycles\":{},\"power_on_hours\":{},\"unsafe_shutdowns\":{},\"media_errors\":{},\"error_log_entries\":{}}}",
        health.critical_warning,
        health.temperature_kelvin,
        health.temperature_celsius,
        health.available_spare_percent,
        health.available_spare_threshold_percent,
        health.percentage_used,
        health.data_units_read,
        health.data_units_written,
        health.power_cycles,
        health.power_on_hours,
        health.unsafe_shutdowns,
        health.media_errors,
        health.error_log_entries
    )
}

pub fn disk_smart_json(disks: &[DiskSmart]) -> String {
    let items: Vec<String> = disks
        .iter()
        .map(|d| {
            let attrs: Vec<String> = d
                .ata_attributes
                .iter()
                .map(|a| {
                    format!(
                        "{{\"id\":{},\"name\":{},\"flags\":{},\"value\":{},\"worst\":{},\"threshold\":{},\"raw\":{}}}",
                        a.id,
                        q(&a.name),
                        a.flags,
                        a.value,
                        a.worst,
                        a.threshold,
                        a.raw
                    )
                })
                .collect();
            let nvme = match &d.nvme {
                Some(health) => nvme_health_json(health),
                None => "null".to_string(),
            };
            format!(
                "{{\"index\":{},\"interface\":{},\"source\":{},\"ata_attributes\":[{}],\"nvme\":{}}}",
                d.index,
                q(&d.interface),
                q(&d.source),
                attrs.join(","),
                nvme
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

impl BoardInfo {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"system_manufacturer\":{},\"system_product\":{},\"board_manufacturer\":{},\"board_product\":{},\"bios_vendor\":{},\"bios_version\":{},\"bios_date\":{},\"system_version\":{},\"system_serial\":{},\"board_version\":{},\"board_serial\":{},\"system_uuid\":{}}}",
            q(&self.system_manufacturer),
            q(&self.system_product),
            q(&self.board_manufacturer),
            q(&self.board_product),
            q(&self.bios_vendor),
            q(&self.bios_version),
            q(&self.bios_date),
            q(&self.system_version),
            q(&self.system_serial),
            q(&self.board_version),
            q(&self.board_serial),
            q(&self.system_uuid)
        )
    }
}

// ---- pure platform / battery helpers ----

/// FIRMWARE_TYPE (winbase.h): 1 = legacy BIOS, 2 = UEFI.
pub fn firmware_type_name(firmware_type: u32) -> &'static str {
    match firmware_type {
        1 => "bios",
        2 => "uefi",
        _ => "unknown",
    }
}

/// TPM spec version stated by the device description Windows
/// reports ("Trusted Platform Module 2.0"); "" when the
/// description doesn't state one. Nothing is inferred beyond
/// the text itself.
pub fn tpm_version_from_name(device: &str) -> &'static str {
    if device.contains("2.0") {
        "2.0"
    } else if device.contains("1.2") {
        "1.2"
    } else {
        ""
    }
}

/// The decoded BATTERY_INFORMATION fields this library reports.
/// Capacities are 0 when the battery reports
/// BATTERY_UNKNOWN_CAPACITY (0xFFFFFFFF).
#[derive(Debug, Default, Clone)]
pub struct BatteryInformationRaw {
    pub chemistry: String,
    pub rechargeable: bool,
    pub designed_capacity_mwh: u32,
    pub full_charge_capacity_mwh: u32,
    pub cycle_count: u32,
}

/// BATTERY_INFORMATION layout (poclass.h): Capabilities u32@0,
/// Technology u8@4, Chemistry[4]@8 (not necessarily
/// NUL-terminated), DesignedCapacity u32@12,
/// FullChargedCapacity u32@16, CycleCount u32@32; 36 bytes total.
pub fn parse_battery_information(buf: &[u8]) -> Option<BatteryInformationRaw> {
    if buf.len() < 36 {
        return None;
    }
    const UNKNOWN_CAPACITY: u32 = 0xFFFF_FFFF;
    let capacity = |off: usize| -> u32 {
        match le_u32(buf, off) {
            Some(UNKNOWN_CAPACITY) | None => 0,
            Some(v) => v,
        }
    };
    let chemistry_bytes = &buf[8..12];
    let end = chemistry_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(chemistry_bytes.len());
    Some(BatteryInformationRaw {
        chemistry: String::from_utf8_lossy(&chemistry_bytes[..end])
            .trim()
            .to_string(),
        rechargeable: buf[4] != 0,
        designed_capacity_mwh: capacity(12),
        full_charge_capacity_mwh: capacity(16),
        cycle_count: le_u32(buf, 32).unwrap_or(0),
    })
}

/// Wear level from the two reported capacities. A fresh battery
/// can report slightly over 100; the value is reported as
/// computed, not clamped. -1 when either capacity is unknown.
pub fn battery_health_percent(designed_mwh: u32, full_mwh: u32) -> i32 {
    if designed_mwh == 0 || full_mwh == 0 {
        return -1;
    }
    ((full_mwh as u64 * 100) / designed_mwh as u64) as i32
}

/// Map a GetFirmwareEnvironmentVariableW("SecureBoot", ...)
/// outcome to capability. ERROR_INVALID_FUNCTION (1) is the
/// documented answer on systems without UEFI firmware-variable
/// support, and the SecureBoot variable is mandatory on
/// Secure-Boot-capable UEFI firmware, so ERROR_ENVVAR_NOT_FOUND
/// (203) also reads as "not capable in this boot". Anything else
/// (privilege not held, access denied, ...) is honestly unknown.
pub fn secure_boot_capability(succeeded: bool, last_error: u32) -> Option<bool> {
    if succeeded {
        return Some(true);
    }
    match last_error {
        1 | 203 => Some(false),
        _ => None,
    }
}

// ---- pure SMART parsing ----

/// Names for the small set of SMART attribute ids whose meaning
/// is documented generically (ATA spec / vendor-common). Anything
/// else stays unnamed rather than guessed.
pub fn smart_attribute_name(id: u8) -> &'static str {
    match id {
        1 => "raw_read_error_rate",
        2 => "throughput_performance",
        3 => "spin_up_time",
        4 => "start_stop_count",
        5 => "reallocated_sectors",
        7 => "seek_error_rate",
        8 => "seek_time_performance",
        9 => "power_on_hours",
        10 => "spin_retry_count",
        11 => "calibration_retry_count",
        12 => "power_cycle_count",
        183 => "sata_downshift_count",
        184 => "end_to_end_error",
        187 => "reported_uncorrectable_errors",
        188 => "command_timeout",
        190 => "airflow_temperature",
        191 => "g_sense_error_rate",
        192 => "power_off_retract_count",
        193 => "load_cycle_count",
        194 => "temperature",
        195 => "hardware_ecc_recovered",
        196 => "reallocation_event_count",
        197 => "current_pending_sectors",
        198 => "offline_uncorrectable_sectors",
        199 => "udma_crc_error_count",
        240 => "head_flying_hours",
        241 => "total_lbas_written",
        242 => "total_lbas_read",
        _ => "",
    }
}

/// Threshold byte per attribute id from the SMART thresholds
/// block, whose entries mirror the attribute layout: starting at
/// offset 2, up to 30 records of 12 bytes (id, threshold, then
/// reserved). Id 0 marks an unused slot.
fn smart_threshold(thresholds: &[u8], id: u8) -> u32 {
    for slot in 0..30usize {
        let off = 2 + slot * 12;
        if off + 2 > thresholds.len() {
            break;
        }
        if thresholds[off] == id {
            return thresholds[off + 1] as u32;
        }
    }
    0
}

/// Parse the 512-byte SMART READ DATA attribute block: a 2-byte
/// revision followed by up to 30 attribute records of 12 bytes
/// (id u8, status flags u16le, current value u8, worst u8, raw
/// 48-bit little-endian, reserved u8). Slots with id 0 are
/// unused and skipped. `thresholds`, when present, is the
/// matching SMART READ THRESHOLDS block.
pub fn parse_ata_smart_attributes(data: &[u8], thresholds: Option<&[u8]>) -> Vec<SmartAttribute> {
    let mut out = Vec::new();
    for slot in 0..30usize {
        let off = 2 + slot * 12;
        if off + 12 > data.len() {
            break;
        }
        let entry = &data[off..off + 12];
        if entry[0] == 0 {
            continue;
        }
        let mut raw = [0u8; 8];
        raw[..6].copy_from_slice(&entry[5..11]);
        out.push(SmartAttribute {
            id: entry[0] as u32,
            name: smart_attribute_name(entry[0]).to_string(),
            flags: u16::from_le_bytes([entry[1], entry[2]]) as u32,
            value: entry[3] as u32,
            worst: entry[4] as u32,
            threshold: thresholds.map_or(0, |t| smart_threshold(t, entry[0])),
            raw: u64::from_le_bytes(raw),
        });
    }
    out
}

fn le_u128_low64(buf: &[u8], off: usize) -> u64 {
    match buf.get(off..off + 8) {
        Some(b) => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
        None => 0,
    }
}

/// Parse the NVMe SMART / Health Information log page (512
/// bytes): critical warning @0, composite temperature u16le
/// Kelvin @1, available spare % @3, spare threshold % @4,
/// percentage used @5, then 128-bit counters (low 64 bits kept)
/// for data units read @32 / written @48, power cycles @112,
/// power-on hours @128, unsafe shutdowns @144, media errors
/// @160, and error-log entries @176.
pub fn parse_nvme_health_log(buf: &[u8]) -> Option<NvmeHealth> {
    if buf.len() < 192 {
        return None;
    }
    let kelvin = u16::from_le_bytes([buf[1], buf[2]]) as u32;
    Some(NvmeHealth {
        critical_warning: buf[0] as u32,
        temperature_kelvin: kelvin,
        temperature_celsius: if kelvin == 0 { 0 } else { kelvin as i32 - 273 },
        available_spare_percent: buf[3] as u32,
        available_spare_threshold_percent: buf[4] as u32,
        percentage_used: buf[5] as u32,
        data_units_read: le_u128_low64(buf, 32),
        data_units_written: le_u128_low64(buf, 48),
        power_cycles: le_u128_low64(buf, 112),
        power_on_hours: le_u128_low64(buf, 128),
        unsafe_shutdowns: le_u128_low64(buf, 144),
        media_errors: le_u128_low64(buf, 160),
        error_log_entries: le_u128_low64(buf, 176),
    })
}

// ---- pure storage-descriptor parsing (STORAGE_DEVICE_DESCRIPTOR) ----
// Kept here, off the Windows path, so the byte layouts are unit
// testable anywhere. Layout (winioctl.h): Version u32@0, Size u32@4,
// DeviceType u8@8, DeviceTypeModifier u8@9, RemovableMedia u8@10,
// CommandQueueing u8@11, then u32 offsets (from the start of the
// struct, NUL-terminated ASCII) for Vendor@12, Product@16,
// Revision@20, Serial@24, then BusType u32@28.

#[derive(Debug, Default, Clone)]
pub struct StorageDescriptor {
    pub vendor: String,
    pub product: String,
    pub revision: String,
    pub serial: String,
    pub bus_type: u32,
    pub removable: bool,
}

fn le_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn descriptor_string(buf: &[u8], offset_field: usize) -> String {
    let off = match le_u32(buf, offset_field) {
        Some(0) | None => return String::new(),
        Some(v) => v as usize,
    };
    let bytes = match buf.get(off..) {
        Some(b) => b,
        None => return String::new(),
    };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    // Vendors pad these with spaces; a padded value is still the
    // reported value, just unpadded.
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

pub fn parse_storage_device_descriptor(buf: &[u8]) -> Option<StorageDescriptor> {
    if buf.len() < 36 {
        return None;
    }
    Some(StorageDescriptor {
        vendor: descriptor_string(buf, 12),
        product: descriptor_string(buf, 16),
        revision: descriptor_string(buf, 20),
        serial: descriptor_string(buf, 24),
        bus_type: le_u32(buf, 28)?,
        removable: buf[10] != 0,
    })
}

/// STORAGE_BUS_TYPE (winioctl.h) as a stable lowercase token.
pub fn bus_type_name(bus_type: u32) -> &'static str {
    match bus_type {
        1 => "scsi",
        2 => "atapi",
        3 => "ata",
        4 => "ieee1394",
        5 => "ssa",
        6 => "fibre",
        7 => "usb",
        8 => "raid",
        9 => "iscsi",
        10 => "sas",
        11 => "sata",
        12 => "sd",
        13 => "mmc",
        14 => "virtual",
        15 => "file_backed_virtual",
        16 => "spaces",
        17 => "nvme",
        18 => "scm",
        19 => "ufs",
        _ => "unknown",
    }
}

/// DEVICE_SEEK_PENALTY_DESCRIPTOR: Version u32@0, Size u32@4,
/// IncursSeekPenalty u8@8. `Some(false)` is how Windows reports an
/// SSD-class device; `None` means the descriptor was too small.
pub fn parse_seek_penalty(buf: &[u8]) -> Option<bool> {
    buf.get(8).map(|b| *b != 0)
}

/// DISK_GEOMETRY_EX starts with DISK_GEOMETRY (Cylinders u64@0,
/// MediaType u32@8, TracksPerCylinder u32@12, SectorsPerTrack
/// u32@16, BytesPerSector u32@20) followed by DiskSize u64@24.
pub fn parse_disk_geometry_ex_size(buf: &[u8]) -> Option<u64> {
    let b = buf.get(24..32)?;
    Some(u64::from_le_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ]))
}

// ---- pure DXGI adapter merging ----

/// The platform-neutral shape of one DXGI_ADAPTER_DESC1, as read by
/// the Windows DXGI probe. Merging onto the EnumDisplayDevices list
/// is pure so the matching rules are testable anywhere.
#[derive(Debug, Default, Clone)]
pub struct DxgiAdapter {
    pub name: String, // DXGI Description
    pub vendor_id: u32,
    pub device_id: u32,
    pub dedicated_video_memory_bytes: u64,
    pub dedicated_system_memory_bytes: u64,
    pub shared_system_memory_bytes: u64,
    pub luid: u64,
}

/// Match DXGI adapters onto GPUs by exact name, consuming adapters
/// in enumeration order so two identical cards each get their own
/// DXGI record. Unmatched GPUs keep empty/zero DXGI fields.
pub fn merge_dxgi_adapters(gpus: &mut [GpuInfo], adapters: &[DxgiAdapter]) {
    let mut used = vec![false; adapters.len()];
    for gpu in gpus.iter_mut() {
        for (i, adapter) in adapters.iter().enumerate() {
            if used[i] || adapter.name != gpu.name {
                continue;
            }
            used[i] = true;
            gpu.vendor_id = format!("0x{:04X}", adapter.vendor_id);
            gpu.device_id = format!("0x{:04X}", adapter.device_id);
            gpu.dedicated_video_memory_bytes = adapter.dedicated_video_memory_bytes;
            gpu.dedicated_system_memory_bytes = adapter.dedicated_system_memory_bytes;
            gpu.shared_system_memory_bytes = adapter.shared_system_memory_bytes;
            gpu.luid = format!("0x{:016X}", adapter.luid);
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shapes() {
        let cpu = CpuInfo {
            brand: "Test CPU \"X\"".into(),
            logical_processors: 8,
            features: vec!["avx2".into()],
            ..Default::default()
        };
        let j = cpu.to_json();
        assert!(j.contains("\"brand\":\"Test CPU \\\"X\\\"\""), "{j}");
        assert!(j.contains("\"features\":[\"avx2\"]"), "{j}");
        let disks = vec![DiskInfo {
            letter: "C:".into(),
            kind: "fixed".into(),
            total_bytes: 100,
            ..Default::default()
        }];
        assert!(disks_json(&disks).contains("\"total_bytes\":100"));
    }

    #[test]
    fn new_json_shapes() {
        let disks = vec![PhysicalDiskInfo {
            index: 0,
            model: "TestNVMe 1TB".into(),
            interface: "nvme".into(),
            media: "ssd".into(),
            size_bytes: 1_000_204_886_016,
            health: "ok".into(),
            ..Default::default()
        }];
        let j = physical_disks_json(&disks);
        assert!(j.contains("\"interface\":\"nvme\""), "{j}");
        assert!(j.contains("\"size_bytes\":1000204886016"), "{j}");
        assert!(j.contains("\"health\":\"ok\""), "{j}");
        let ram = vec![RamModule {
            slot: "DIMM 0".into(),
            capacity_bytes: 17_179_869_184,
            speed_mts: 5600,
            memory_type: "DDR5".into(),
            form_factor: "SODIMM".into(),
            ..Default::default()
        }];
        let j = ram_json(&ram);
        assert!(j.contains("\"capacity_bytes\":17179869184"), "{j}");
        assert!(j.contains("\"type\":\"DDR5\""), "{j}");
        let gpus = vec![GpuInfo {
            name: "GPU".into(),
            dedicated_video_memory_bytes: 8_589_934_592,
            driver_version: "32.0.1".into(),
            ..Default::default()
        }];
        let j = gpus_json(&gpus);
        assert!(
            j.contains("\"dedicated_video_memory_bytes\":8589934592"),
            "{j}"
        );
        assert!(j.contains("\"driver_version\":\"32.0.1\""), "{j}");
    }

    #[test]
    fn storage_descriptor_parsing() {
        // Build a synthetic STORAGE_DEVICE_DESCRIPTOR with strings
        // packed after the 36-byte header.
        let mut buf = vec![0u8; 256];
        buf[10] = 1; // removable
        let put = |field: usize, off: usize, s: &str, buf: &mut Vec<u8>| {
            buf[field..field + 4].copy_from_slice(&(off as u32).to_le_bytes());
            buf[off..off + s.len()].copy_from_slice(s.as_bytes());
        };
        put(12, 40, "ACME    ", &mut buf);
        put(16, 64, "RoadRunner NVMe", &mut buf);
        put(20, 96, "1.2.3", &mut buf);
        put(24, 112, " SN42 ", &mut buf);
        buf[28..32].copy_from_slice(&17u32.to_le_bytes()); // BusTypeNvme
        let d = parse_storage_device_descriptor(&buf).expect("descriptor");
        assert_eq!(d.vendor, "ACME");
        assert_eq!(d.product, "RoadRunner NVMe");
        assert_eq!(d.revision, "1.2.3");
        assert_eq!(d.serial, "SN42");
        assert!(d.removable);
        assert_eq!(bus_type_name(d.bus_type), "nvme");
        assert_eq!(bus_type_name(11), "sata");
        assert_eq!(bus_type_name(7), "usb");
        assert_eq!(bus_type_name(0), "unknown");
        // Truncated / zero-offset descriptors never panic.
        assert!(parse_storage_device_descriptor(&buf[..20]).is_none());
        assert!(parse_storage_device_descriptor(&[0u8; 36]).is_some());
        // Seek penalty + geometry sizes.
        let mut seek = [0u8; 12];
        seek[8] = 0;
        assert_eq!(parse_seek_penalty(&seek), Some(false));
        seek[8] = 1;
        assert_eq!(parse_seek_penalty(&seek), Some(true));
        assert_eq!(parse_seek_penalty(&seek[..4]), None);
        let mut geo = [0u8; 40];
        geo[24..32].copy_from_slice(&500_107_862_016u64.to_le_bytes());
        assert_eq!(parse_disk_geometry_ex_size(&geo), Some(500_107_862_016));
        assert_eq!(parse_disk_geometry_ex_size(&geo[..31]), None);
    }

    #[test]
    fn dxgi_merge_consumes_each_adapter_once() {
        let mut gpus = vec![
            GpuInfo {
                name: "Card X".into(),
                ..Default::default()
            },
            GpuInfo {
                name: "Card X".into(),
                ..Default::default()
            },
            GpuInfo {
                name: "Basic Render".into(),
                ..Default::default()
            },
        ];
        let adapters = vec![
            DxgiAdapter {
                name: "Card X".into(),
                vendor_id: 0x10DE,
                device_id: 0x2684,
                dedicated_video_memory_bytes: 100,
                luid: 0x1111,
                ..Default::default()
            },
            DxgiAdapter {
                name: "Card X".into(),
                vendor_id: 0x10DE,
                device_id: 0x2684,
                dedicated_video_memory_bytes: 200,
                luid: 0x2222,
                ..Default::default()
            },
        ];
        merge_dxgi_adapters(&mut gpus, &adapters);
        assert_eq!(gpus[0].dedicated_video_memory_bytes, 100);
        assert_eq!(gpus[0].vendor_id, "0x10DE");
        assert_eq!(gpus[0].device_id, "0x2684");
        assert_eq!(gpus[0].luid, "0x0000000000001111");
        assert_eq!(gpus[1].dedicated_video_memory_bytes, 200);
        assert_eq!(gpus[2].dedicated_video_memory_bytes, 0);
        assert_eq!(gpus[2].luid, "");
        // No adapters at all leaves the v0.1 shape untouched.
        merge_dxgi_adapters(&mut gpus, &[]);
        assert_eq!(gpus[0].name, "Card X");
    }

    #[test]
    fn platform_and_battery_helpers() {
        assert_eq!(firmware_type_name(1), "bios");
        assert_eq!(firmware_type_name(2), "uefi");
        assert_eq!(firmware_type_name(0), "unknown");
        assert_eq!(tpm_version_from_name("Trusted Platform Module 2.0"), "2.0");
        assert_eq!(tpm_version_from_name("Trusted Platform Module 1.2"), "1.2");
        assert_eq!(tpm_version_from_name("TPM"), "");
        // Synthetic BATTERY_INFORMATION: LION, rechargeable,
        // 56_000 mWh designed, 47_600 mWh full (85%), 312 cycles.
        let mut buf = [0u8; 36];
        buf[4] = 1;
        buf[8..12].copy_from_slice(b"LION");
        buf[12..16].copy_from_slice(&56_000u32.to_le_bytes());
        buf[16..20].copy_from_slice(&47_600u32.to_le_bytes());
        buf[32..36].copy_from_slice(&312u32.to_le_bytes());
        let raw = parse_battery_information(&buf).expect("battery info");
        assert_eq!(raw.chemistry, "LION");
        assert!(raw.rechargeable);
        assert_eq!(raw.designed_capacity_mwh, 56_000);
        assert_eq!(raw.cycle_count, 312);
        assert_eq!(battery_health_percent(56_000, 47_600), 85);
        assert_eq!(battery_health_percent(50_000, 52_500), 105);
        assert_eq!(battery_health_percent(0, 47_600), -1);
        // Unknown capacities read as 0, never 0xFFFFFFFF.
        buf[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let raw = parse_battery_information(&buf).expect("battery info");
        assert_eq!(raw.designed_capacity_mwh, 0);
        assert!(parse_battery_information(&buf[..35]).is_none());
        // JSON shapes.
        let platform = PlatformInfo {
            firmware_type: "uefi".into(),
            secure_boot_enabled: true,
            tpm_present: true,
            tpm_version: "2.0".into(),
            ..Default::default()
        };
        let j = platform.to_json();
        assert!(j.contains("\"firmware_type\":\"uefi\""), "{j}");
        assert!(j.contains("\"secure_boot_enabled\":true"), "{j}");
        assert!(j.contains("\"tpm_version\":\"2.0\""), "{j}");
        let batteries = vec![BatteryHealth {
            name: "BAT0".into(),
            chemistry: "LION".into(),
            designed_capacity_mwh: 56_000,
            full_charge_capacity_mwh: 47_600,
            health_percent: 85,
            ..Default::default()
        }];
        let j = batteries_json(&batteries);
        assert!(j.contains("\"health_percent\":85"), "{j}");
        assert!(j.contains("\"designed_capacity_mwh\":56000"), "{j}");
    }

    #[test]
    fn secure_boot_capability_mapping() {
        assert_eq!(secure_boot_capability(true, 0), Some(true));
        assert_eq!(secure_boot_capability(false, 1), Some(false));
        assert_eq!(secure_boot_capability(false, 203), Some(false));
        assert_eq!(secure_boot_capability(false, 1314), None);
        assert_eq!(secure_boot_capability(false, 5), None);
    }

    #[test]
    fn smart_parsing() {
        // Synthetic SMART block: id 9 power-on-hours raw 12345,
        // id 194 temperature, one empty slot, one unnamed vendor id 230.
        let mut data = [0u8; 512];
        let mut put_attr = |slot: usize, id: u8, value: u8, worst: u8, raw: u64| {
            let off = 2 + slot * 12;
            data[off] = id;
            data[off + 1..off + 3].copy_from_slice(&0x0023u16.to_le_bytes());
            data[off + 3] = value;
            data[off + 4] = worst;
            data[off + 5..off + 11].copy_from_slice(&raw.to_le_bytes()[..6]);
        };
        put_attr(0, 9, 98, 98, 12345);
        put_attr(2, 194, 70, 60, 30);
        put_attr(3, 0xE6, 100, 100, 7);
        let mut thresholds = [0u8; 512];
        thresholds[2] = 9;
        thresholds[3] = 1;
        thresholds[14] = 194;
        thresholds[15] = 45;
        let attrs = parse_ata_smart_attributes(&data, Some(&thresholds));
        assert_eq!(attrs.len(), 3, "{attrs:?}");
        assert_eq!(attrs[0].id, 9);
        assert_eq!(attrs[0].name, "power_on_hours");
        assert_eq!(attrs[0].flags, 0x23);
        assert_eq!(attrs[0].value, 98);
        assert_eq!(attrs[0].raw, 12345);
        assert_eq!(attrs[0].threshold, 1);
        assert_eq!(attrs[1].name, "temperature");
        assert_eq!(attrs[1].threshold, 45);
        assert_eq!(attrs[2].name, "");
        assert_eq!(attrs[2].threshold, 0);
        // No thresholds block: thresholds read 0, entries intact.
        assert_eq!(parse_ata_smart_attributes(&data, None).len(), 3);
        // Truncated input yields what fits, never panics.
        assert_eq!(parse_ata_smart_attributes(&data[..14], None).len(), 1);
        assert!(parse_ata_smart_attributes(&[], None).is_empty());
        // NVMe health log.
        let mut log = [0u8; 512];
        log[0] = 0;
        log[1..3].copy_from_slice(&310u16.to_le_bytes()); // 37 C
        log[3] = 100;
        log[4] = 10;
        log[5] = 3;
        log[128..136].copy_from_slice(&8766u64.to_le_bytes());
        log[160..168].copy_from_slice(&2u64.to_le_bytes());
        let health = parse_nvme_health_log(&log).expect("nvme log");
        assert_eq!(health.temperature_kelvin, 310);
        assert_eq!(health.temperature_celsius, 37);
        assert_eq!(health.percentage_used, 3);
        assert_eq!(health.power_on_hours, 8766);
        assert_eq!(health.media_errors, 2);
        assert!(parse_nvme_health_log(&log[..64]).is_none());
        // JSON shape: nulls where data did not answer.
        let disks = vec![
            DiskSmart {
                index: 0,
                interface: "nvme".into(),
                source: "nvme_health_log".into(),
                nvme: Some(health),
                ..Default::default()
            },
            DiskSmart {
                index: 1,
                interface: "spaces".into(),
                source: "none".into(),
                ..Default::default()
            },
        ];
        let j = disk_smart_json(&disks);
        assert!(j.contains("\"percentage_used\":3"), "{j}");
        assert!(j.contains("\"nvme\":null"), "{j}");
        assert!(j.contains("\"source\":\"none\""), "{j}");
    }
}
