//! Platform layer: hand-declared Win32 probes. Every extern block
//! carries its #[link(name = "...")] — without it the build fails at
//! LINK time; check/clippy cannot catch it, CI can.
//!
//! On non-Windows everything returns ERR_NOT_SUPPORTED so the FFI
//! contract stays testable anywhere.

use crate::{CResult, ERR_NOT_SUPPORTED};

pub fn not_supported<T>(what: &str) -> CResult<T> {
    Err((
        ERR_NOT_SUPPORTED,
        format!("{what} is only available on Windows"),
    ))
}

/// The aggregate probe (hw_system_json) uses this to fail wholesale
/// off-Windows instead of returning a document of inline errors.
pub fn platform_available() -> bool {
    cfg!(windows)
}

#[cfg(windows)]
pub use win::*;

#[cfg(windows)]
mod win {
    use std::ffi::c_void;

    use crate::{
        AdapterInfo, BatteryInfo, BoardInfo, CResult, CpuInfo, DiskInfo, GpuInfo, MemoryInfo,
        MonitorInfo, OsInfo, ERR_PLATFORM,
    };

    // ---- registry (advapi32) ----
    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            key: isize,
            subkey: *const u16,
            options: u32,
            sam: u32,
            result: *mut isize,
        ) -> i32;
        fn RegQueryValueExW(
            key: isize,
            name: *const u16,
            reserved: *mut u32,
            ty: *mut u32,
            data: *mut u8,
            size: *mut u32,
        ) -> i32;
        fn RegCloseKey(key: isize) -> i32;
    }
    const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
    const KEY_READ: u32 = 0x0002_0019;

    fn reg_string(root: isize, subkey: &str, name: &str) -> Option<String> {
        let sub: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let nm: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut key: isize = 0;
        if unsafe { RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
            return None;
        }
        let mut size: u32 = 0;
        let mut ty: u32 = 0;
        let rc = unsafe {
            RegQueryValueExW(
                key,
                nm.as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        let mut result = None;
        if rc == 0 && size > 0 && (ty == 1 || ty == 2) {
            // REG_SZ / REG_EXPAND_SZ
            let mut buf = vec![0u8; size as usize];
            let rc2 = unsafe {
                RegQueryValueExW(
                    key,
                    nm.as_ptr(),
                    std::ptr::null_mut(),
                    &mut ty,
                    buf.as_mut_ptr(),
                    &mut size,
                )
            };
            if rc2 == 0 {
                let units: Vec<u16> = buf
                    .chunks_exact(2)
                    .map(|p| u16::from_le_bytes([p[0], p[1]]))
                    .collect();
                let s = String::from_utf16_lossy(&units);
                result = Some(s.trim_end_matches('\0').to_string());
            }
        }
        unsafe { RegCloseKey(key) };
        result
    }

    fn reg_dword(root: isize, subkey: &str, name: &str) -> Option<u32> {
        let sub: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let nm: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut key: isize = 0;
        if unsafe { RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
            return None;
        }
        let mut data = [0u8; 4];
        let mut size = 4u32;
        let mut ty = 0u32;
        let rc = unsafe {
            RegQueryValueExW(
                key,
                nm.as_ptr(),
                std::ptr::null_mut(),
                &mut ty,
                data.as_mut_ptr(),
                &mut size,
            )
        };
        unsafe { RegCloseKey(key) };
        if rc == 0 && ty == 4 {
            Some(u32::from_le_bytes(data))
        } else {
            None
        }
    }

    // ---- system info / memory / power (kernel32) ----
    #[link(name = "kernel32")]
    extern "system" {
        fn GetNativeSystemInfo(info: *mut u8);
        fn GlobalMemoryStatusEx(info: *mut MemoryStatusEx) -> i32;
        fn GetLogicalProcessorInformationEx(relation: i32, buffer: *mut u8, len: *mut u32) -> i32;
        fn GetLastError() -> u32;
        fn GetComputerNameW(name: *mut u16, size: *mut u32) -> i32;
        fn GetLogicalDriveStringsW(len: u32, buffer: *mut u16) -> u32;
        fn GetDriveTypeW(root: *const u16) -> u32;
        fn GetVolumeInformationW(
            root: *const u16,
            label: *mut u16,
            label_len: u32,
            serial: *mut u32,
            max_comp: *mut u32,
            flags: *mut u32,
            fs: *mut u16,
            fs_len: u32,
        ) -> i32;
        fn GetDiskFreeSpaceExW(
            path: *const u16,
            free_caller: *mut u64,
            total: *mut u64,
            total_free: *mut u64,
        ) -> i32;
        fn GetSystemPowerStatus(status: *mut PowerStatus) -> i32;
    }

    #[repr(C)]
    struct MemoryStatusEx {
        length: u32,
        load: u32,
        total_phys: u64,
        avail_phys: u64,
        total_page: u64,
        avail_page: u64,
        total_virt: u64,
        avail_virt: u64,
        avail_ext: u64,
    }

    #[repr(C)]
    struct PowerStatus {
        ac_line: u8,
        battery_flag: u8,
        battery_percent: u8,
        system_status: u8,
        battery_life_time: u32,
        battery_full_life_time: u32,
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn RtlGetVersion(info: *mut OsVersionInfoW) -> i32;
    }
    #[repr(C)]
    struct OsVersionInfoW {
        size: u32,
        major: u32,
        minor: u32,
        build: u32,
        platform_id: u32,
        csd_version: [u16; 128],
    }

    fn arch_name(code: u16) -> String {
        match code {
            9 => "x86_64",
            5 => "ARM",
            12 => "ARM64",
            0 => "x86",
            6 => "IA64",
            _ => "unknown",
        }
        .to_string()
    }

    fn system_info_raw() -> [u8; 48] {
        let mut buf = [0u8; 48];
        unsafe { GetNativeSystemInfo(buf.as_mut_ptr()) };
        buf
    }

    pub fn cpu_info() -> CResult<CpuInfo> {
        let raw = system_info_raw();
        let arch = arch_name(u16::from_le_bytes([raw[0], raw[1]]));
        let logical = u32::from_le_bytes([raw[32], raw[33], raw[34], raw[35]]);
        let brand = reg_string(
            HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            "ProcessorNameString",
        )
        .unwrap_or_default()
        .trim()
        .to_string();
        let vendor_reg = reg_string(
            HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            "VendorIdentifier",
        )
        .unwrap_or_default();
        let mhz = reg_dword(
            HKEY_LOCAL_MACHINE,
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
            "~MHz",
        )
        .unwrap_or(0);
        // Physical cores: count RelationProcessorCore entries.
        let mut physical = 0u32;
        let mut len: u32 = 0;
        unsafe { GetLogicalProcessorInformationEx(0, std::ptr::null_mut(), &mut len) };
        if len > 0 {
            let mut buf = vec![0u8; len as usize];
            if unsafe { GetLogicalProcessorInformationEx(0, buf.as_mut_ptr(), &mut len) } != 0 {
                let mut off = 0usize;
                while off + 8 <= buf.len() {
                    let relation =
                        i32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]);
                    let size = u32::from_le_bytes([
                        buf[off + 4],
                        buf[off + 5],
                        buf[off + 6],
                        buf[off + 7],
                    ]) as usize;
                    if size == 0 {
                        break;
                    }
                    if relation == 0 {
                        physical += 1;
                    }
                    off += size;
                }
            }
        }
        if physical == 0 {
            physical = logical;
        }
        let mut features: Vec<String> = Vec::new();
        let mut vendor = vendor_reg;
        #[cfg(target_arch = "x86_64")]
        {
            // CPUID brand/vendor via the std intrinsics wrappers.
            if vendor.is_empty() {
                vendor = cpuid_vendor();
            }
            for (name, present) in [
                ("sse3", is_x86_feature_detected!("sse3")),
                ("ssse3", is_x86_feature_detected!("ssse3")),
                ("sse4.1", is_x86_feature_detected!("sse4.1")),
                ("sse4.2", is_x86_feature_detected!("sse4.2")),
                ("avx", is_x86_feature_detected!("avx")),
                ("avx2", is_x86_feature_detected!("avx2")),
                ("avx512f", is_x86_feature_detected!("avx512f")),
                ("aes", is_x86_feature_detected!("aes")),
                ("fma", is_x86_feature_detected!("fma")),
                ("bmi1", is_x86_feature_detected!("bmi1")),
                ("bmi2", is_x86_feature_detected!("bmi2")),
                ("popcnt", is_x86_feature_detected!("popcnt")),
            ] {
                if present {
                    features.push(name.to_string());
                }
            }
        }
        Ok(CpuInfo {
            brand,
            vendor,
            architecture: arch,
            physical_cores: physical,
            logical_processors: logical,
            max_mhz: mhz,
            features,
        })
    }

    #[cfg(target_arch = "x86_64")]
    fn cpuid_vendor() -> String {
        // Leaf 0: vendor in EBX, EDX, ECX.
        let res = std::arch::x86_64::__cpuid(0);
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&res.ebx.to_le_bytes());
        bytes.extend_from_slice(&res.edx.to_le_bytes());
        bytes.extend_from_slice(&res.ecx.to_le_bytes());
        String::from_utf8_lossy(&bytes).into_owned()
    }

    pub fn os_info() -> CResult<OsInfo> {
        let mut ver = OsVersionInfoW {
            size: std::mem::size_of::<OsVersionInfoW>() as u32,
            major: 0,
            minor: 0,
            build: 0,
            platform_id: 0,
            csd_version: [0; 128],
        };
        unsafe { RtlGetVersion(&mut ver) };
        let key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        let raw = system_info_raw();
        let mut name_len: u32 = 0;
        unsafe { GetComputerNameW(std::ptr::null_mut(), &mut name_len) };
        let mut name_buf = vec![0u16; (name_len.max(1)) as usize];
        let mut n2 = name_len;
        let computer = if unsafe { GetComputerNameW(name_buf.as_mut_ptr(), &mut n2) } != 0 {
            String::from_utf16_lossy(&name_buf[..n2 as usize])
        } else {
            String::new()
        };
        Ok(OsInfo {
            product_name: reg_string(HKEY_LOCAL_MACHINE, key, "ProductName").unwrap_or_default(),
            display_version: reg_string(HKEY_LOCAL_MACHINE, key, "DisplayVersion")
                .unwrap_or_default(),
            edition: reg_string(HKEY_LOCAL_MACHINE, key, "EditionID").unwrap_or_default(),
            build: ver.build,
            ubr: reg_dword(HKEY_LOCAL_MACHINE, key, "UBR").unwrap_or(0),
            computer_name: computer,
            architecture: arch_name(u16::from_le_bytes([raw[0], raw[1]])),
        })
    }

    pub fn memory_info() -> CResult<MemoryInfo> {
        let mut ms = MemoryStatusEx {
            length: std::mem::size_of::<MemoryStatusEx>() as u32,
            load: 0,
            total_phys: 0,
            avail_phys: 0,
            total_page: 0,
            avail_page: 0,
            total_virt: 0,
            avail_virt: 0,
            avail_ext: 0,
        };
        if unsafe { GlobalMemoryStatusEx(&mut ms) } == 0 {
            return Err((
                ERR_PLATFORM,
                format!("GlobalMemoryStatusEx failed ({})", unsafe {
                    GetLastError()
                }),
            ));
        }
        Ok(MemoryInfo {
            total_phys_bytes: ms.total_phys,
            avail_phys_bytes: ms.avail_phys,
            total_pagefile_bytes: ms.total_page,
            avail_pagefile_bytes: ms.avail_page,
            load_percent: ms.load,
        })
    }

    pub fn disks() -> CResult<Vec<DiskInfo>> {
        let needed = unsafe { GetLogicalDriveStringsW(0, std::ptr::null_mut()) };
        if needed == 0 {
            return Err((ERR_PLATFORM, "GetLogicalDriveStringsW failed".into()));
        }
        let mut buf = vec![0u16; needed as usize];
        let got = unsafe { GetLogicalDriveStringsW(needed, buf.as_mut_ptr()) };
        if got == 0 {
            return Err((ERR_PLATFORM, "GetLogicalDriveStringsW failed".into()));
        }
        let all = String::from_utf16_lossy(&buf);
        let mut out = Vec::new();
        for root in all.split('\0') {
            if root.is_empty() {
                continue;
            }
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            let ty = unsafe { GetDriveTypeW(wide.as_ptr()) };
            let kind = match ty {
                2 => "removable",
                3 => "fixed",
                4 => "network",
                5 => "cdrom",
                6 => "ramdisk",
                _ => "unknown",
            }
            .to_string();
            let mut label = vec![0u16; 261];
            let mut fs = vec![0u16; 261];
            let ok = unsafe {
                GetVolumeInformationW(
                    wide.as_ptr(),
                    label.as_mut_ptr(),
                    261,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    fs.as_mut_ptr(),
                    261,
                )
            };
            let (mut total, mut free) = (0u64, 0u64);
            unsafe {
                GetDiskFreeSpaceExW(wide.as_ptr(), std::ptr::null_mut(), &mut total, &mut free)
            };
            out.push(DiskInfo {
                letter: root.trim_end_matches('\\').to_string(),
                kind,
                label: if ok != 0 {
                    String::from_utf16_lossy(&label)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    String::new()
                },
                filesystem: if ok != 0 {
                    String::from_utf16_lossy(&fs)
                        .trim_end_matches('\0')
                        .to_string()
                } else {
                    String::new()
                },
                total_bytes: total,
                free_bytes: free,
            });
        }
        Ok(out)
    }

    // ---- display devices & monitors (user32) ----
    #[link(name = "user32")]
    extern "system" {
        fn EnumDisplayDevicesW(
            device: *const u16,
            dev_num: u32,
            info: *mut DisplayDeviceW,
            flags: u32,
        ) -> i32;
        fn EnumDisplayMonitors(
            dc: *mut c_void,
            clip: *mut c_void,
            proc_: extern "system" fn(*mut c_void, *mut c_void, *mut c_void, isize) -> i32,
            data: isize,
        ) -> i32;
        fn GetMonitorInfoW(monitor: *mut c_void, info: *mut MonitorInfoRaw) -> i32;
    }

    #[repr(C)]
    struct DisplayDeviceW {
        cb: u32,
        device_name: [u16; 32],
        device_string: [u16; 128],
        state_flags: u32,
        device_id: [u16; 128],
        device_key: [u16; 128],
    }

    #[repr(C)]
    struct MonitorInfoRaw {
        cb_size: u32,
        rc_monitor: [i32; 4],
        rc_work: [i32; 4],
        flags: u32,
        device: [u16; 32],
    }

    fn u16z(units: &[u16]) -> String {
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        String::from_utf16_lossy(&units[..end])
    }

    pub fn gpus() -> CResult<Vec<GpuInfo>> {
        let mut out = Vec::new();
        let mut i = 0u32;
        loop {
            let mut dd = DisplayDeviceW {
                cb: std::mem::size_of::<DisplayDeviceW>() as u32,
                device_name: [0; 32],
                device_string: [0; 128],
                state_flags: 0,
                device_id: [0; 128],
                device_key: [0; 128],
            };
            if unsafe { EnumDisplayDevicesW(std::ptr::null(), i, &mut dd, 0) } == 0 {
                break;
            }
            i += 1;
            const MIRRORING: u32 = 0x8;
            if dd.state_flags & MIRRORING != 0 {
                continue;
            }
            out.push(GpuInfo {
                name: u16z(&dd.device_string),
                device: u16z(&dd.device_name),
            });
        }
        Ok(out)
    }

    pub fn monitors() -> CResult<Vec<MonitorInfo>> {
        struct Ctx {
            items: Vec<MonitorInfo>,
        }
        extern "system" fn callback(
            monitor: *mut c_void,
            _dc: *mut c_void,
            _rect: *mut c_void,
            data: isize,
        ) -> i32 {
            let ctx = unsafe { &mut *(data as *mut Ctx) };
            let mut info = MonitorInfoRaw {
                cb_size: std::mem::size_of::<MonitorInfoRaw>() as u32,
                rc_monitor: [0; 4],
                rc_work: [0; 4],
                flags: 0,
                device: [0; 32],
            };
            if unsafe { GetMonitorInfoW(monitor, &mut info) } != 0 {
                ctx.items.push(MonitorInfo {
                    name: u16z(&info.device),
                    width: info.rc_monitor[2] - info.rc_monitor[0],
                    height: info.rc_monitor[3] - info.rc_monitor[1],
                    primary: info.flags & 1 != 0,
                });
            }
            1
        }
        let mut ctx = Ctx { items: Vec::new() };
        let ok = unsafe {
            EnumDisplayMonitors(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                callback,
                &mut ctx as *mut Ctx as isize,
            )
        };
        if ok == 0 {
            return Err((ERR_PLATFORM, "EnumDisplayMonitors failed".into()));
        }
        Ok(ctx.items)
    }

    // ---- network adapters (iphlpapi + ws2_32 for formatting) ----
    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetAdaptersAddresses(
            family: u32,
            flags: u32,
            reserved: *mut c_void,
            addresses: *mut u8,
            size: *mut u32,
        ) -> u32;
    }

    pub fn adapters() -> CResult<Vec<AdapterInfo>> {
        const AF_UNSPEC: u32 = 0;
        const GAA_FLAG_INCLUDE_PREFIX: u32 = 0x10;
        let mut size: u32 = 0;
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_INCLUDE_PREFIX,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if rc != 111 && rc != 0 {
            // ERROR_BUFFER_OVERFLOW = 111 expected on the sizing call.
            if size == 0 {
                return Err((
                    ERR_PLATFORM,
                    format!("GetAdaptersAddresses sizing failed ({rc})"),
                ));
            }
        }
        if size == 0 {
            size = 16 * 1024;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                GAA_FLAG_INCLUDE_PREFIX,
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                &mut size,
            )
        };
        if rc != 0 {
            return Err((ERR_PLATFORM, format!("GetAdaptersAddresses failed ({rc})")));
        }
        // Parse the linked list using documented x64/ARM64 offsets.
        let base = buf.as_ptr() as usize;
        let mut out = Vec::new();
        let mut current = base;
        loop {
            let read_ptr = |off: usize| -> usize {
                unsafe { *(current as *const u8).add(off).cast::<usize>() }
            };
            let read_u32 =
                |off: usize| -> u32 { unsafe { *(current as *const u8).add(off).cast::<u32>() } };
            let read_wstr = |off: usize| -> String {
                let p = read_ptr(off);
                if p == 0 {
                    return String::new();
                }
                let mut units = Vec::new();
                let mut i = 0usize;
                loop {
                    let u = unsafe { *(p as *const u16).add(i) };
                    if u == 0 || i > 512 {
                        break;
                    }
                    units.push(u);
                    i += 1;
                }
                String::from_utf16_lossy(&units)
            };
            let friendly = read_wstr(72);
            let description = read_wstr(64);
            let mac_len = read_u32(88) as usize;
            let mac_bytes: Vec<u8> = (0..mac_len.min(8))
                .map(|i| unsafe { *(current as *const u8).add(80 + i) })
                .collect();
            let mac = mac_bytes
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":");
            let if_type = read_u32(100);
            let oper = read_u32(104);
            let kind = match if_type {
                6 => "ethernet",
                71 => "wireless",
                24 => "loopback",
                131 => "tunnel",
                _ => "other",
            }
            .to_string();
            // Unicast addresses.
            let mut ipv4 = Vec::new();
            let mut ipv6 = Vec::new();
            let mut ua = read_ptr(24);
            while ua != 0 {
                let sockaddr = unsafe { *(ua as *const u8).add(16).cast::<usize>() };
                if sockaddr != 0 {
                    let family = unsafe { *(sockaddr as *const u16) };
                    match family {
                        2 => {
                            let b: Vec<u8> = (0..4)
                                .map(|i| unsafe { *(sockaddr as *const u8).add(4 + i) })
                                .collect();
                            ipv4.push(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]));
                        }
                        23 => {
                            let groups: Vec<String> = (0..8)
                                .map(|g| {
                                    let hi = unsafe { *(sockaddr as *const u8).add(8 + g * 2) };
                                    let lo = unsafe { *(sockaddr as *const u8).add(9 + g * 2) };
                                    format!("{:x}", ((hi as u16) << 8) | lo as u16)
                                })
                                .collect();
                            ipv6.push(groups.join(":"));
                        }
                        _ => {}
                    }
                }
                ua = unsafe { *(ua as *const u8).add(8).cast::<usize>() };
            }
            out.push(AdapterInfo {
                name: friendly,
                description,
                mac,
                kind,
                up: oper == 1,
                ipv4,
                ipv6,
            });
            let next = read_ptr(8);
            if next == 0 {
                break;
            }
            current = next;
        }
        Ok(out)
    }

    pub fn battery() -> CResult<BatteryInfo> {
        let mut ps = PowerStatus {
            ac_line: 0,
            battery_flag: 0,
            battery_percent: 255,
            system_status: 0,
            battery_life_time: 0,
            battery_full_life_time: 0,
        };
        if unsafe { GetSystemPowerStatus(&mut ps) } == 0 {
            return Err((ERR_PLATFORM, "GetSystemPowerStatus failed".into()));
        }
        const NO_BATTERY: u8 = 128;
        Ok(BatteryInfo {
            present: ps.battery_flag & NO_BATTERY == 0,
            ac_online: ps.ac_line == 1,
            charging: ps.battery_flag & 8 != 0,
            percent: if ps.battery_percent == 255 {
                -1
            } else {
                ps.battery_percent as i32
            },
        })
    }

    pub fn board() -> CResult<BoardInfo> {
        let key = "HARDWARE\\DESCRIPTION\\System\\BIOS";
        let get = |name: &str| reg_string(HKEY_LOCAL_MACHINE, key, name).unwrap_or_default();
        Ok(BoardInfo {
            system_manufacturer: get("SystemManufacturer"),
            system_product: get("SystemProductName"),
            board_manufacturer: get("BaseBoardManufacturer"),
            board_product: get("BaseBoardProduct"),
            bios_vendor: get("BIOSVendor"),
            bios_version: get("BIOSVersion"),
            bios_date: get("BIOSReleaseDate"),
        })
    }
}

#[cfg(not(windows))]
use crate::{
    AdapterInfo, BatteryInfo, BoardInfo, CpuInfo, DiskInfo, GpuInfo, MemoryInfo, MonitorInfo,
    OsInfo,
};

#[cfg(not(windows))]
pub fn cpu_info() -> CResult<CpuInfo> {
    not_supported("cpu_info")
}
#[cfg(not(windows))]
pub fn os_info() -> CResult<OsInfo> {
    not_supported("os_info")
}
#[cfg(not(windows))]
pub fn memory_info() -> CResult<MemoryInfo> {
    not_supported("memory_info")
}
#[cfg(not(windows))]
pub fn disks() -> CResult<Vec<DiskInfo>> {
    not_supported("disks")
}
#[cfg(not(windows))]
pub fn gpus() -> CResult<Vec<GpuInfo>> {
    not_supported("gpus")
}
#[cfg(not(windows))]
pub fn monitors() -> CResult<Vec<MonitorInfo>> {
    not_supported("monitors")
}
#[cfg(not(windows))]
pub fn adapters() -> CResult<Vec<AdapterInfo>> {
    not_supported("adapters")
}
#[cfg(not(windows))]
pub fn battery() -> CResult<BatteryInfo> {
    not_supported("battery")
}
#[cfg(not(windows))]
pub fn board() -> CResult<BoardInfo> {
    not_supported("board")
}
