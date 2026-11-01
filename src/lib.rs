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

pub const VERSION: &str = "0.2.0";
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 2;
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
}
