//! HardwareInfo — a hardware inventory of the machine (CPU, OS,
//! memory, disks, GPUs, monitors, network adapters, battery,
//! motherboard/BIOS) as structured JSON behind one clean C ABI, in
//! pure Rust with zero dependencies and hand-declared Win32 bindings.
//!
//! Read-only by design: the library only ever queries. Every section
//! is independently available so callers never pay for probes they
//! don't need, and a failure in one probe never poisons the others —
//! the aggregate `hw_system_json` reports per-section errors inline.

pub mod ffi;
pub mod platform;

pub const VERSION: &str = "0.1.0";
pub const VERSION_MAJOR: u32 = 0;
pub const VERSION_MINOR: u32 = 1;
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
        .map(|g| format!("{{\"name\":{},\"device\":{}}}", q(&g.name), q(&g.device)))
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
            "{{\"system_manufacturer\":{},\"system_product\":{},\"board_manufacturer\":{},\"board_product\":{},\"bios_vendor\":{},\"bios_version\":{},\"bios_date\":{}}}",
            q(&self.system_manufacturer),
            q(&self.system_product),
            q(&self.board_manufacturer),
            q(&self.board_product),
            q(&self.bios_vendor),
            q(&self.bios_version),
            q(&self.bios_date)
        )
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
}
