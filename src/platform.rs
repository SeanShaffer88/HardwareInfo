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

    use crate::smbios;
    use crate::{
        battery_health_percent, bus_type_name, device_ids_from_hardware_id, firmware_type_name,
        merge_dxgi_adapters, parse_ata_smart_attributes, parse_battery_information,
        parse_disk_geometry_ex_size, parse_nvme_health_log, parse_seek_penalty,
        parse_storage_device_descriptor, parse_wave_caps, secure_boot_capability,
        tpm_version_from_name, AdapterInfo, AudioDevice, BatteryHealth, BatteryInfo, BoardInfo,
        CResult, CpuInfo, DiskInfo, DiskSmart, DxgiAdapter, GpuInfo, MemoryInfo, MonitorInfo,
        NvmeHealth, OsInfo, PhysicalDiskInfo, PlatformInfo, PnpDevice, PrinterInfo, RamModule,
        ERR_PLATFORM,
    };

    // ---- registry + token privileges (advapi32) ----
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
        fn OpenProcessToken(process: isize, access: u32, token: *mut isize) -> i32;
        fn LookupPrivilegeValueW(system: *const u16, name: *const u16, luid: *mut u8) -> i32;
        fn AdjustTokenPrivileges(
            token: isize,
            disable_all: i32,
            new_state: *const u8,
            buffer_length: u32,
            previous_state: *mut u8,
            return_length: *mut u32,
        ) -> i32;
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

    fn reg_qword(root: isize, subkey: &str, name: &str) -> Option<u64> {
        let sub: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let nm: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut key: isize = 0;
        if unsafe { RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
            return None;
        }
        let mut data = [0u8; 8];
        let mut size = 8u32;
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
        if rc == 0 && ty == 11 {
            // REG_QWORD
            Some(u64::from_le_bytes(data))
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
        fn GetFirmwareType(firmware_type: *mut u32) -> i32;
        fn GetCurrentProcess() -> isize;
        fn GetFirmwareEnvironmentVariableW(
            name: *const u16,
            guid: *const u16,
            value: *mut c_void,
            size: u32,
        ) -> u32;
        fn GetSystemFirmwareTable(sig: u32, id: u32, buf: *mut c_void, size: u32) -> u32;
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut c_void,
            disposition: u32,
            flags: u32,
            template: *mut c_void,
        ) -> isize;
        fn DeviceIoControl(
            handle: isize,
            code: u32,
            in_buf: *const c_void,
            in_size: u32,
            out_buf: *mut c_void,
            out_size: u32,
            returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn CloseHandle(handle: isize) -> i32;
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

    // ---- physical disks (kernel32 storage IOCTLs) ----
    // Read-only query IOCTLs only: device descriptor, drive
    // geometry, seek penalty, and the SMART failure-prediction
    // verdict. Nothing here can write to the drive.
    const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
    const IOCTL_STORAGE_PREDICT_FAILURE: u32 = 0x002D_1100;
    const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x0007_00A0;
    const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
    const STORAGE_DEVICE_PROPERTY: u32 = 0;
    const STORAGE_DEVICE_SEEK_PENALTY_PROPERTY: u32 = 7;

    fn storage_query(handle: isize, property: u32, out_size: usize) -> Option<Vec<u8>> {
        // STORAGE_PROPERTY_QUERY: PropertyId u32, QueryType u32
        // (0 = PropertyStandardQuery), AdditionalParameters[1].
        let mut query = [0u8; 12];
        query[0..4].copy_from_slice(&property.to_le_bytes());
        let mut out = vec![0u8; out_size];
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                query.as_ptr() as *const c_void,
                query.len() as u32,
                out.as_mut_ptr() as *mut c_void,
                out.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || returned == 0 {
            return None;
        }
        out.truncate((returned as usize).min(out.len()));
        Some(out)
    }

    fn disk_size_bytes(handle: isize) -> u64 {
        let mut geo = vec![0u8; 512];
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                std::ptr::null(),
                0,
                geo.as_mut_ptr() as *mut c_void,
                geo.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            if let Some(size) = parse_disk_geometry_ex_size(&geo) {
                if size > 0 {
                    return size;
                }
            }
        }
        // GET_LENGTH_INFO needs a read-access handle; best-effort.
        let mut len_buf = [0u8; 8];
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_LENGTH_INFO,
                std::ptr::null(),
                0,
                len_buf.as_mut_ptr() as *mut c_void,
                len_buf.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            u64::from_le_bytes(len_buf)
        } else {
            0
        }
    }

    fn disk_health(handle: isize) -> String {
        // STORAGE_PREDICT_FAILURE: PredictFailure u32, then 512
        // vendor-specific bytes we deliberately don't decode --
        // the verdict is what Windows reports, nothing more.
        let mut buf = vec![0u8; 516];
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_PREDICT_FAILURE,
                std::ptr::null(),
                0,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || returned < 4 {
            return "unknown".to_string();
        }
        let predict = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if predict != 0 {
            "failure_predicted".to_string()
        } else {
            "ok".to_string()
        }
    }

    fn probe_physical_disk(handle: isize, index: u32) -> Option<PhysicalDiskInfo> {
        let raw = storage_query(handle, STORAGE_DEVICE_PROPERTY, 1024)?;
        let desc = parse_storage_device_descriptor(&raw)?;
        let media = storage_query(handle, STORAGE_DEVICE_SEEK_PENALTY_PROPERTY, 32)
            .and_then(|b| parse_seek_penalty(&b))
            .map(|penalty| if penalty { "hdd" } else { "ssd" })
            .unwrap_or("unknown");
        Some(PhysicalDiskInfo {
            index,
            model: desc.product,
            vendor: desc.vendor,
            revision: desc.revision,
            serial: desc.serial,
            interface: bus_type_name(desc.bus_type).to_string(),
            media: media.to_string(),
            removable: desc.removable,
            size_bytes: disk_size_bytes(handle),
            health: disk_health(handle),
        })
    }

    pub fn physical_disks() -> CResult<Vec<PhysicalDiskInfo>> {
        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_SHARE_READ_WRITE: u32 = 0x3;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE: isize = -1;
        let mut out = Vec::new();
        for index in 0..32u32 {
            let path: Vec<u16> = format!("\\\\.\\PhysicalDrive{index}")
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            // Opening a physical drive for reading needs
            // elevation; the storage queries are FILE_ANY_ACCESS,
            // so fall back to a zero-access handle (size then
            // comes from geometry, which is also FILE_ANY_ACCESS).
            let mut handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ_WRITE,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE {
                handle = unsafe {
                    CreateFileW(
                        path.as_ptr(),
                        0,
                        FILE_SHARE_READ_WRITE,
                        std::ptr::null_mut(),
                        OPEN_EXISTING,
                        0,
                        std::ptr::null_mut(),
                    )
                };
            }
            if handle == INVALID_HANDLE {
                continue;
            }
            let disk = probe_physical_disk(handle, index);
            unsafe { CloseHandle(handle) };
            if let Some(disk) = disk {
                out.push(disk);
            }
        }
        Ok(out)
    }

    // ---- SMART detail (same storage handles, read-only commands) ----
    // ATA: SMART READ DATA / READ THRESHOLDS via the legacy
    // SMART_RCV_DRIVE_DATA command path — receive-only by name and
    // by design. NVMe: the protocol-specific storage query asking
    // for log page 02h. Neither can write to the drive.
    const SMART_RCV_DRIVE_DATA: u32 = 0x0007_C088;
    const STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY: u32 = 50;

    fn ata_smart_read(handle: isize, index: u32, feature: u8) -> Option<Vec<u8>> {
        // SENDCMDINPARAMS (32 bytes before the buffer byte):
        // cBufferSize u32 @0, then the task-file registers as
        // single bytes @4: Features, SectorCount, SectorNumber,
        // CylLow, CylHigh, DriveHead, Command, Reserved, then
        // bDriveNumber @12. SMART commands require the signature
        // CylLow/CylHigh 0x4F/0xC2 and command 0xB0.
        let mut input = [0u8; 32];
        input[0..4].copy_from_slice(&512u32.to_le_bytes());
        input[4] = feature;
        input[5] = 1;
        input[6] = 1;
        input[7] = 0x4F;
        input[8] = 0xC2;
        input[9] = 0xA0;
        input[10] = 0xB0;
        input[12] = index as u8;
        // SENDCMDOUTPARAMS: cBufferSize u32, DRIVERSTATUS (error
        // byte first) @4, reserved to @16, then the 512 data bytes.
        let mut out = vec![0u8; 528];
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                SMART_RCV_DRIVE_DATA,
                input.as_ptr() as *const c_void,
                input.len() as u32,
                out.as_mut_ptr() as *mut c_void,
                out.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || returned < 528 || out[4] != 0 {
            return None;
        }
        Some(out[16..528].to_vec())
    }

    fn nvme_health(handle: isize) -> Option<NvmeHealth> {
        // STORAGE_PROPERTY_QUERY (PropertyId @0, QueryType @4)
        // with a STORAGE_PROTOCOL_SPECIFIC_DATA record in the
        // additional-parameters overlay @8: ProtocolType 3 (NVMe)
        // @8, DataType 2 (log page) @12, log identifier 02h @16,
        // data offset 40 (from the record start) @24, length 512
        // @28. The descriptor comes back in the same layout.
        let mut query = [0u8; 48];
        let put = |buf: &mut [u8; 48], off: usize, value: u32| {
            buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
        };
        put(&mut query, 0, STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY);
        put(&mut query, 8, 3);
        put(&mut query, 12, 2);
        put(&mut query, 16, 2);
        put(&mut query, 24, 40);
        put(&mut query, 28, 512);
        let mut out = vec![0u8; 560];
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                query.as_ptr() as *const c_void,
                query.len() as u32,
                out.as_mut_ptr() as *mut c_void,
                out.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || returned < 48 {
            return None;
        }
        // Returned ProtocolDataOffset/Length sit at the same @24/@28;
        // the log follows at 8 + offset. Trust them only in bounds.
        let offset = u32::from_le_bytes([out[24], out[25], out[26], out[27]]) as usize;
        let length = u32::from_le_bytes([out[28], out[29], out[30], out[31]]) as usize;
        let start = 8usize.checked_add(offset)?;
        let end = start.checked_add(length)?.min(out.len());
        let slice = out.get(start..end)?;
        parse_nvme_health_log(slice)
    }

    fn probe_disk_smart(handle: isize, index: u32) -> Option<DiskSmart> {
        let raw = storage_query(handle, STORAGE_DEVICE_PROPERTY, 1024)?;
        let desc = parse_storage_device_descriptor(&raw)?;
        let interface = bus_type_name(desc.bus_type).to_string();
        if desc.bus_type == 17 {
            // BusTypeNvme.
            if let Some(health) = nvme_health(handle) {
                return Some(DiskSmart {
                    index,
                    interface,
                    source: "nvme_health_log".to_string(),
                    nvme: Some(health),
                    ..Default::default()
                });
            }
        } else if matches!(desc.bus_type, 2 | 3 | 11) {
            // BusTypeAtapi / BusTypeAta / BusTypeSata: features
            // 0xD0 = SMART READ DATA, 0xD1 = READ THRESHOLDS.
            if let Some(data) = ata_smart_read(handle, index, 0xD0) {
                let thresholds = ata_smart_read(handle, index, 0xD1);
                let attrs = parse_ata_smart_attributes(&data, thresholds.as_deref());
                if !attrs.is_empty() {
                    return Some(DiskSmart {
                        index,
                        interface,
                        source: "ata_smart".to_string(),
                        ata_attributes: attrs,
                        ..Default::default()
                    });
                }
            }
        }
        Some(DiskSmart {
            index,
            interface,
            source: "none".to_string(),
            ..Default::default()
        })
    }

    pub fn smart_disks() -> CResult<Vec<DiskSmart>> {
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const FILE_SHARE_READ_WRITE: u32 = 0x3;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE: isize = -1;
        let mut out = Vec::new();
        for index in 0..32u32 {
            let path: Vec<u16> = format!("\\\\.\\PhysicalDrive{index}")
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            // SMART command paths historically want a read/write
            // handle even though every command sent here only
            // reads; degrade read-only, then zero-access (the
            // storage descriptor still answers there, so the drive
            // is at least listed with source "none").
            let mut handle = INVALID_HANDLE;
            for access in [GENERIC_READ | GENERIC_WRITE, GENERIC_READ, 0] {
                handle = unsafe {
                    CreateFileW(
                        path.as_ptr(),
                        access,
                        FILE_SHARE_READ_WRITE,
                        std::ptr::null_mut(),
                        OPEN_EXISTING,
                        0,
                        std::ptr::null_mut(),
                    )
                };
                if handle != INVALID_HANDLE {
                    break;
                }
            }
            if handle == INVALID_HANDLE {
                continue;
            }
            let disk = probe_disk_smart(handle, index);
            unsafe { CloseHandle(handle) };
            if let Some(disk) = disk {
                out.push(disk);
            }
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
        let mut keys: Vec<String> = Vec::new();
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
                ..Default::default()
            });
            keys.push(u16z(&dd.device_key));
        }
        // Enrichment is best-effort: DXGI memory/IDs matched by
        // card name, driver version from the display device's
        // registry key. A GPU Windows enumerates is reported
        // either way (that's the v0.1 contract).
        merge_dxgi_adapters(&mut out, &dxgi_adapters());
        for (gpu, key) in out.iter_mut().zip(keys.iter()) {
            let (version, vram) = driver_details(key);
            gpu.driver_version = version;
            if gpu.dedicated_video_memory_bytes == 0 {
                gpu.dedicated_video_memory_bytes = vram;
            }
        }
        Ok(out)
    }

    fn driver_details(device_key: &str) -> (String, u64) {
        // EnumDisplayDevices reports the driver key in NT form
        // (\Registry\Machine\...); the rest is HKLM-relative.
        let subkey = device_key
            .strip_prefix("\\Registry\\Machine\\")
            .unwrap_or("");
        if subkey.is_empty() {
            return (String::new(), 0);
        }
        let version = reg_string(HKEY_LOCAL_MACHINE, subkey, "DriverVersion").unwrap_or_default();
        let vram = reg_qword(
            HKEY_LOCAL_MACHINE,
            subkey,
            "HardwareInformation.qwMemorySize",
        )
        .unwrap_or(0);
        (version, vram)
    }

    // ---- DXGI adapters (dxgi) ----
    #[link(name = "dxgi")]
    extern "system" {
        fn CreateDXGIFactory1(riid: *const Guid, factory: *mut *mut c_void) -> i32;
    }

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    // IID_IDXGIFactory1 = {770AAE78-F26F-4DBA-A829-253C83D1B387}
    const IID_IDXGIFACTORY1: Guid = Guid {
        data1: 0x770A_AE78,
        data2: 0xF26F,
        data3: 0x4DBA,
        data4: [0xA8, 0x29, 0x25, 0x3C, 0x83, 0xD1, 0xB3, 0x87],
    };

    // DXGI_ADAPTER_DESC1 (dxgi.h); AdapterLuid is read as one u64.
    #[repr(C)]
    struct DxgiAdapterDesc1Raw {
        description: [u16; 128],
        vendor_id: u32,
        device_id: u32,
        subsys_id: u32,
        revision: u32,
        dedicated_video_memory: usize,
        dedicated_system_memory: usize,
        shared_system_memory: usize,
        adapter_luid: u64,
        flags: u32,
    }

    /// Read one vtable slot as a typed fn pointer. Slot indices
    /// follow C++ COM inheritance: IUnknown is 0 (QueryInterface),
    /// 1 (AddRef), 2 (Release); IDXGIObject is 3-6; IDXGIFactory
    /// is 7-11, so IDXGIFactory1::EnumAdapters1 is 12.
    /// IDXGIAdapter is 7 (EnumOutputs), 8 (GetDesc),
    /// 9 (CheckInterfaceSupport), so IDXGIAdapter1::GetDesc1 is
    /// 10. Re-verify against dxgi.h before trusting a new slot.
    ///
    /// # Safety: `obj` is a live COM interface pointer whose
    /// vtable slot `slot` holds a function of type `T`.
    unsafe fn com_method<T>(obj: *mut c_void, slot: usize) -> T {
        let vtbl = *(obj as *const *const usize);
        let addr = *vtbl.add(slot);
        std::mem::transmute_copy(&addr)
    }

    unsafe fn com_release(obj: *mut c_void) {
        if !obj.is_null() {
            let release: extern "system" fn(*mut c_void) -> u32 = com_method(obj, 2);
            release(obj);
        }
    }

    fn dxgi_adapters() -> Vec<DxgiAdapter> {
        let mut factory: *mut c_void = std::ptr::null_mut();
        if unsafe { CreateDXGIFactory1(&IID_IDXGIFACTORY1, &mut factory) } < 0 || factory.is_null()
        {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut i = 0u32;
        loop {
            let enum_adapters1: extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32 =
                unsafe { com_method(factory, 12) };
            let mut adapter: *mut c_void = std::ptr::null_mut();
            // DXGI_ERROR_NOT_FOUND (a negative HRESULT) ends the
            // enumeration.
            if enum_adapters1(factory, i, &mut adapter) < 0 || adapter.is_null() {
                break;
            }
            i += 1;
            let get_desc1: extern "system" fn(*mut c_void, *mut DxgiAdapterDesc1Raw) -> i32 =
                unsafe { com_method(adapter, 10) };
            let mut desc: DxgiAdapterDesc1Raw = unsafe { std::mem::zeroed() };
            let hr = get_desc1(adapter, &mut desc);
            unsafe { com_release(adapter) };
            if hr < 0 {
                continue;
            }
            // Software adapters (Microsoft Basic Render) have no
            // VRAM to report; the display-device list still
            // carries the card itself.
            const DXGI_ADAPTER_FLAG_SOFTWARE: u32 = 2;
            if desc.flags & DXGI_ADAPTER_FLAG_SOFTWARE != 0 {
                continue;
            }
            out.push(DxgiAdapter {
                name: u16z(&desc.description),
                vendor_id: desc.vendor_id,
                device_id: desc.device_id,
                dedicated_video_memory_bytes: desc.dedicated_video_memory as u64,
                dedicated_system_memory_bytes: desc.dedicated_system_memory as u64,
                shared_system_memory_bytes: desc.shared_system_memory as u64,
                luid: desc.adapter_luid,
            });
        }
        unsafe { com_release(factory) };
        out
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

    // ---- device enumeration (setupapi) ----
    #[link(name = "setupapi")]
    extern "system" {
        fn SetupDiGetClassDevsW(
            class_guid: *const Guid,
            enumerator: *const u16,
            parent: *mut c_void,
            flags: u32,
        ) -> isize;
        fn SetupDiEnumDeviceInterfaces(
            devs: isize,
            dev_info: *mut c_void,
            guid: *const Guid,
            index: u32,
            data: *mut u8,
        ) -> i32;
        fn SetupDiGetDeviceInterfaceDetailW(
            devs: isize,
            data: *mut u8,
            detail: *mut u8,
            detail_size: u32,
            required: *mut u32,
            dev_info: *mut c_void,
        ) -> i32;
        fn SetupDiEnumDeviceInfo(devs: isize, index: u32, data: *mut u8) -> i32;
        fn SetupDiGetDeviceInstanceIdW(
            devs: isize,
            data: *mut u8,
            buffer: *mut u16,
            buffer_size: u32,
            required: *mut u32,
        ) -> i32;
        fn SetupDiGetDeviceRegistryPropertyW(
            devs: isize,
            data: *mut u8,
            property: u32,
            data_type: *mut u32,
            buffer: *mut u8,
            buffer_size: u32,
            required: *mut u32,
        ) -> i32;
        fn SetupDiDestroyDeviceInfoList(devs: isize) -> i32;
    }

    const DIGCF_PRESENT: u32 = 0x2;
    const DIGCF_ALLCLASSES: u32 = 0x4;
    const DIGCF_DEVICEINTERFACE: u32 = 0x10;
    // GUID_DEVINTERFACE_BATTERY {72631E54-78A4-11D0-BCF7-00AA00B7B32A}
    const GUID_DEVINTERFACE_BATTERY: Guid = Guid {
        data1: 0x7263_1E54,
        data2: 0x78A4,
        data3: 0x11D0,
        data4: [0xBC, 0xF7, 0x00, 0xAA, 0x00, 0xB7, 0xB3, 0x2A],
    };
    // Security devices setup class {D94EE5D8-D189-4994-83D2-F68D7D41B0E6}
    const GUID_DEVCLASS_SECURITY: Guid = Guid {
        data1: 0xD94E_E5D8,
        data2: 0xD189,
        data3: 0x4994,
        data4: [0x83, 0xD2, 0xF6, 0x8D, 0x7D, 0x41, 0xB0, 0xE6],
    };

    fn wide_string_from_bytes(buf: &[u8]) -> String {
        let units: Vec<u16> = buf
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16_lossy(&units)
    }

    /// Device-interface paths for one interface class, via SetupDi.
    /// SP_DEVICE_INTERFACE_DATA is handled as a byte buffer with
    /// cbSize 32 (its 64-bit size); the detail record carries the
    /// path as WCHARs at offset 4, and its cbSize must be 8 for
    /// the W variant on 64-bit. Failures keep the paths gathered
    /// so far -- enumeration is best-effort.
    fn device_interface_paths(guid: &Guid) -> Vec<String> {
        let mut paths = Vec::new();
        let devs = unsafe {
            SetupDiGetClassDevsW(
                guid,
                std::ptr::null(),
                std::ptr::null_mut(),
                DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
            )
        };
        if devs == -1 {
            return paths;
        }
        let mut index = 0u32;
        loop {
            let mut data = [0u8; 32];
            data[0..4].copy_from_slice(&32u32.to_le_bytes());
            let ok = unsafe {
                SetupDiEnumDeviceInterfaces(
                    devs,
                    std::ptr::null_mut(),
                    guid,
                    index,
                    data.as_mut_ptr(),
                )
            };
            index += 1;
            if ok == 0 {
                break;
            }
            let mut required: u32 = 0;
            unsafe {
                SetupDiGetDeviceInterfaceDetailW(
                    devs,
                    data.as_mut_ptr(),
                    std::ptr::null_mut(),
                    0,
                    &mut required,
                    std::ptr::null_mut(),
                )
            };
            if required >= 6 {
                let mut detail = vec![0u8; required as usize];
                detail[0..4].copy_from_slice(&8u32.to_le_bytes());
                let ok = unsafe {
                    SetupDiGetDeviceInterfaceDetailW(
                        devs,
                        data.as_mut_ptr(),
                        detail.as_mut_ptr(),
                        required,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                };
                if ok != 0 {
                    paths.push(wide_string_from_bytes(&detail[4..]));
                }
            }
            if index > 64 {
                break;
            }
        }
        unsafe { SetupDiDestroyDeviceInfoList(devs) };
        paths
    }

    /// Friendly-name (fallback: device-description) strings for
    /// every present device in one setup class. SP_DEVINFO_DATA
    /// cbSize is 32 on 64-bit Windows.
    fn class_device_names(guid: &Guid) -> Vec<String> {
        const SPDRP_DEVICEDESC: u32 = 0x0;
        const SPDRP_FRIENDLYNAME: u32 = 0x0C;
        let mut names = Vec::new();
        let devs = unsafe {
            SetupDiGetClassDevsW(guid, std::ptr::null(), std::ptr::null_mut(), DIGCF_PRESENT)
        };
        if devs == -1 {
            return names;
        }
        let mut index = 0u32;
        loop {
            let mut data = [0u8; 32];
            data[0..4].copy_from_slice(&32u32.to_le_bytes());
            if unsafe { SetupDiEnumDeviceInfo(devs, index, data.as_mut_ptr()) } == 0 {
                break;
            }
            index += 1;
            for property in [SPDRP_FRIENDLYNAME, SPDRP_DEVICEDESC] {
                let mut buf = vec![0u8; 512];
                let mut required: u32 = 0;
                let ok = unsafe {
                    SetupDiGetDeviceRegistryPropertyW(
                        devs,
                        data.as_mut_ptr(),
                        property,
                        std::ptr::null_mut(),
                        buf.as_mut_ptr(),
                        buf.len() as u32,
                        &mut required,
                    )
                };
                if ok != 0 {
                    let name = wide_string_from_bytes(&buf);
                    if !name.is_empty() {
                        names.push(name);
                        break;
                    }
                }
            }
            if index > 64 {
                break;
            }
        }
        unsafe { SetupDiDestroyDeviceInfoList(devs) };
        names
    }

    // ---- battery health (battery device IOCTLs) ----
    // Query IOCTLs only, like everything else in this library.
    const IOCTL_BATTERY_QUERY_TAG: u32 = 0x0029_4040;
    const IOCTL_BATTERY_QUERY_INFORMATION: u32 = 0x0029_4044;

    fn battery_query_string(handle: isize, tag: u32, level: u32) -> String {
        // BATTERY_QUERY_INFORMATION: BatteryTag u32, level u32,
        // AtRate u32. String levels: DeviceName 4, ManufactureName 6.
        let mut query = [0u8; 12];
        query[0..4].copy_from_slice(&tag.to_le_bytes());
        query[4..8].copy_from_slice(&level.to_le_bytes());
        let mut out = vec![0u8; 512];
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_BATTERY_QUERY_INFORMATION,
                query.as_ptr() as *const c_void,
                query.len() as u32,
                out.as_mut_ptr() as *mut c_void,
                out.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return String::new();
        }
        wide_string_from_bytes(&out).trim().to_string()
    }

    fn probe_battery(handle: isize) -> Option<BatteryHealth> {
        // The tag changes whenever the battery is swapped, so query
        // it fresh instead of trusting a cached value. The input
        // is a timeout in ms; 0 polls.
        let timeout: u32 = 0;
        let mut tag_buf = [0u8; 4];
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_BATTERY_QUERY_TAG,
                &timeout as *const u32 as *const c_void,
                4,
                tag_buf.as_mut_ptr() as *mut c_void,
                tag_buf.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || returned < 4 {
            return None;
        }
        let tag = u32::from_le_bytes(tag_buf);
        if tag == 0 {
            return None;
        }
        let mut query = [0u8; 12];
        query[0..4].copy_from_slice(&tag.to_le_bytes());
        // Level 0 (BatteryInformation), AtRate 0.
        let mut out = [0u8; 64];
        let ok = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_BATTERY_QUERY_INFORMATION,
                query.as_ptr() as *const c_void,
                query.len() as u32,
                out.as_mut_ptr() as *mut c_void,
                out.len() as u32,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || returned < 36 {
            return None;
        }
        let raw = parse_battery_information(&out)?;
        Some(BatteryHealth {
            name: battery_query_string(handle, tag, 4),
            manufacturer: battery_query_string(handle, tag, 6),
            health_percent: battery_health_percent(
                raw.designed_capacity_mwh,
                raw.full_charge_capacity_mwh,
            ),
            chemistry: raw.chemistry,
            rechargeable: raw.rechargeable,
            designed_capacity_mwh: raw.designed_capacity_mwh,
            full_charge_capacity_mwh: raw.full_charge_capacity_mwh,
            cycle_count: raw.cycle_count,
        })
    }

    pub fn batteries() -> CResult<Vec<BatteryHealth>> {
        const GENERIC_READ: u32 = 0x8000_0000;
        const FILE_SHARE_READ_WRITE: u32 = 0x3;
        const OPEN_EXISTING: u32 = 3;
        let mut out = Vec::new();
        for path in device_interface_paths(&GUID_DEVINTERFACE_BATTERY) {
            let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ_WRITE,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if handle == -1 {
                continue;
            }
            let battery = probe_battery(handle);
            unsafe { CloseHandle(handle) };
            if let Some(battery) = battery {
                out.push(battery);
            }
        }
        Ok(out)
    }

    fn secure_boot_capable_probe() -> Option<bool> {
        // Reading a UEFI firmware variable needs
        // SE_SYSTEM_ENVIRONMENT, which administrators hold
        // disabled: enable it just for the call, restore it after.
        // Without the privilege (the usual unelevated case) the
        // capability is honestly unknown (None).
        const TOKEN_ADJUST_PRIVILEGES_QUERY: u32 = 0x0028;
        const SE_PRIVILEGE_ENABLED: u32 = 0x0002;
        const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
        let mut token: isize = 0;
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES_QUERY,
                &mut token,
            )
        };
        if opened == 0 {
            return None;
        }
        let name: Vec<u16> = "SeSystemEnvironmentPrivilege"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut luid = [0u8; 8];
        let looked_up =
            unsafe { LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), luid.as_mut_ptr()) };
        if looked_up == 0 {
            unsafe { CloseHandle(token) };
            return None;
        }
        // TOKEN_PRIVILEGES: PrivilegeCount u32 @0, then one
        // LUID_AND_ATTRIBUTES (Luid 8 bytes, Attributes u32).
        let mut privileges = [0u8; 16];
        privileges[0..4].copy_from_slice(&1u32.to_le_bytes());
        privileges[4..12].copy_from_slice(&luid);
        privileges[12..16].copy_from_slice(&SE_PRIVILEGE_ENABLED.to_le_bytes());
        let adjusted = unsafe {
            AdjustTokenPrivileges(
                token,
                0,
                privileges.as_ptr(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        // AdjustTokenPrivileges reports success even when the
        // privilege was not held; the last-error says so.
        if adjusted == 0 || unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
            unsafe { CloseHandle(token) };
            return None;
        }
        let var_name: Vec<u16> = "SecureBoot"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let guid: Vec<u16> = "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut value = [0u8; 8];
        let got = unsafe {
            GetFirmwareEnvironmentVariableW(
                var_name.as_ptr(),
                guid.as_ptr(),
                value.as_mut_ptr() as *mut c_void,
                value.len() as u32,
            )
        };
        let last_error = if got == 0 {
            unsafe { GetLastError() }
        } else {
            0
        };
        // Restore: same LUID with the attributes cleared.
        privileges[12..16].copy_from_slice(&0u32.to_le_bytes());
        unsafe {
            AdjustTokenPrivileges(
                token,
                0,
                privileges.as_ptr(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        unsafe { CloseHandle(token) };
        secure_boot_capability(got != 0, last_error)
    }

    // ---- platform readiness (kernel32 + registry + setupapi) ----
    pub fn platform_info() -> CResult<PlatformInfo> {
        let mut firmware: u32 = 0;
        let firmware_type = if unsafe { GetFirmwareType(&mut firmware) } != 0 {
            firmware_type_name(firmware)
        } else {
            "unknown"
        };
        let secure_boot_enabled = reg_dword(
            HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
            "UEFISecureBootEnabled",
        )
        .unwrap_or(0)
            == 1;
        // Enabled implies capable; only the disabled case needs
        // the firmware-variable probe (and its privilege).
        let secure_boot_capable = if secure_boot_enabled {
            Some(true)
        } else {
            secure_boot_capable_probe()
        };
        let devices = class_device_names(&GUID_DEVCLASS_SECURITY);
        let tpm_device = devices
            .iter()
            .find(|name| name.contains("Trusted Platform Module") || name.contains("TPM"))
            .cloned()
            .unwrap_or_default();
        Ok(PlatformInfo {
            firmware_type: firmware_type.to_string(),
            secure_boot_enabled,
            secure_boot_capable,
            tpm_present: !tpm_device.is_empty(),
            tpm_version: tpm_version_from_name(&tpm_device).to_string(),
            tpm_device,
        })
    }

    // ---- SMBIOS firmware table (kernel32) ----
    fn smbios_table() -> Option<Vec<u8>> {
        const RSMB: u32 = 0x5253_4D42; // 'RSMB'
        let size = unsafe { GetSystemFirmwareTable(RSMB, 0, std::ptr::null_mut(), 0) };
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let got = unsafe { GetSystemFirmwareTable(RSMB, 0, buf.as_mut_ptr() as *mut c_void, size) };
        if got == 0 {
            return None;
        }
        buf.truncate((got as usize).min(buf.len()));
        smbios::raw_smbios_table(&buf).map(|table| table.to_vec())
    }

    pub fn ram_modules() -> CResult<Vec<RamModule>> {
        match smbios_table() {
            Some(table) => Ok(smbios::parse_ram_modules(&table)),
            None => Err((ERR_PLATFORM, "SMBIOS firmware table unavailable".into())),
        }
    }

    fn prefer_smbios(dst: &mut String, src: String) {
        if !src.is_empty() {
            *dst = src;
        }
    }

    pub fn board() -> CResult<BoardInfo> {
        let key = "HARDWARE\\DESCRIPTION\\System\\BIOS";
        let get = |name: &str| reg_string(HKEY_LOCAL_MACHINE, key, name).unwrap_or_default();
        let mut info = BoardInfo {
            system_manufacturer: get("SystemManufacturer"),
            system_product: get("SystemProductName"),
            board_manufacturer: get("BaseBoardManufacturer"),
            board_product: get("BaseBoardProduct"),
            bios_vendor: get("BIOSVendor"),
            bios_version: get("BIOSVersion"),
            bios_date: get("BIOSReleaseDate"),
            ..Default::default()
        };
        // SMBIOS is the firmware record the registry key mirrors,
        // so its non-empty values win and the registry fills any
        // gaps (and carries the section alone when the firmware
        // table can't be read).
        if let Some(table) = smbios_table() {
            let s = smbios::parse_board(&table);
            prefer_smbios(&mut info.system_manufacturer, s.system_manufacturer);
            prefer_smbios(&mut info.system_product, s.system_product);
            prefer_smbios(&mut info.board_manufacturer, s.board_manufacturer);
            prefer_smbios(&mut info.board_product, s.board_product);
            prefer_smbios(&mut info.bios_vendor, s.bios_vendor);
            prefer_smbios(&mut info.bios_version, s.bios_version);
            prefer_smbios(&mut info.bios_date, s.bios_date);
            prefer_smbios(&mut info.system_version, s.system_version);
            prefer_smbios(&mut info.system_serial, s.system_serial);
            prefer_smbios(&mut info.board_version, s.board_version);
            prefer_smbios(&mut info.board_serial, s.board_serial);
            prefer_smbios(&mut info.system_uuid, s.system_uuid);
        }
        Ok(info)
    }

    // ---- PnP device inventory (setupapi + cfgmgr32) ----
    #[link(name = "cfgmgr32")]
    extern "system" {
        fn CM_Get_DevNode_Status(
            status: *mut u32,
            problem: *mut u32,
            dev_inst: u32,
            flags: u32,
        ) -> i32;
    }
    const DN_STARTED: u32 = 0x0000_0008;

    /// One SetupDi device-registry property as raw bytes
    /// (two-call sizing, capped); empty when absent.
    fn device_registry_bytes(devs: isize, data: *mut u8, property: u32) -> Vec<u8> {
        let mut required: u32 = 0;
        unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                devs,
                data,
                property,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                &mut required,
            )
        };
        if required == 0 || required > 65_536 {
            return Vec::new();
        }
        let mut buf = vec![0u8; required as usize];
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                devs,
                data,
                property,
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                required,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            Vec::new()
        } else {
            buf
        }
    }

    /// REG_MULTI_SZ bytes (UTF-16LE, NUL-separated) as strings.
    fn multi_sz_from_bytes(buf: &[u8]) -> Vec<String> {
        let units: Vec<u16> = buf
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        units
            .split(|&u| u == 0)
            .filter(|s| !s.is_empty())
            .map(String::from_utf16_lossy)
            .collect()
    }

    fn device_instance_id(devs: isize, data: *mut u8) -> String {
        let mut buf = vec![0u16; 512];
        let mut required: u32 = 0;
        let ok = unsafe {
            SetupDiGetDeviceInstanceIdW(
                devs,
                data,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut required,
            )
        };
        if ok == 0 {
            return String::new();
        }
        let units: Vec<u16> = buf.iter().copied().take_while(|&u| u != 0).collect();
        String::from_utf16_lossy(&units)
    }

    pub fn devices() -> CResult<Vec<PnpDevice>> {
        const SPDRP_DEVICEDESC: u32 = 0x00;
        const SPDRP_HARDWAREID: u32 = 0x01;
        const SPDRP_CLASS: u32 = 0x07;
        const SPDRP_MFG: u32 = 0x0B;
        const SPDRP_FRIENDLYNAME: u32 = 0x0C;
        const SPDRP_LOCATION_INFORMATION: u32 = 0x0D;
        const SPDRP_ENUMERATOR_NAME: u32 = 0x16;
        let mut out = Vec::new();
        let devs = unsafe {
            SetupDiGetClassDevsW(
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
                DIGCF_PRESENT | DIGCF_ALLCLASSES,
            )
        };
        if devs == -1 {
            return Ok(out);
        }
        let string_prop = |data: *mut u8, property: u32| -> String {
            wide_string_from_bytes(&device_registry_bytes(devs, data, property))
        };
        let mut index = 0u32;
        loop {
            let mut data = [0u8; 32];
            data[0..4].copy_from_slice(&32u32.to_le_bytes());
            if unsafe { SetupDiEnumDeviceInfo(devs, index, data.as_mut_ptr()) } == 0 {
                break;
            }
            index += 1;
            let description = string_prop(data.as_mut_ptr(), SPDRP_DEVICEDESC);
            let friendly = string_prop(data.as_mut_ptr(), SPDRP_FRIENDLYNAME);
            let name = if friendly.is_empty() {
                description.clone()
            } else {
                friendly
            };
            let id_bytes = device_registry_bytes(devs, data.as_mut_ptr(), SPDRP_HARDWAREID);
            let hardware_ids = multi_sz_from_bytes(&id_bytes);
            let (vendor_id, device_id) = match hardware_ids.first() {
                Some(id) => device_ids_from_hardware_id(id),
                None => (String::new(), String::new()),
            };
            // DevInst is the u32 at offset 20 (cbSize + ClassGuid).
            let dev_inst = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
            let mut status: u32 = 0;
            let mut problem: u32 = 0;
            let cm_rc = unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, dev_inst, 0) };
            let (problem_code, started) = if cm_rc == 0 {
                (Some(problem), Some(status & DN_STARTED != 0))
            } else {
                (None, None)
            };
            out.push(PnpDevice {
                name,
                description,
                manufacturer: string_prop(data.as_mut_ptr(), SPDRP_MFG),
                class: string_prop(data.as_mut_ptr(), SPDRP_CLASS),
                enumerator: string_prop(data.as_mut_ptr(), SPDRP_ENUMERATOR_NAME),
                location: string_prop(data.as_mut_ptr(), SPDRP_LOCATION_INFORMATION),
                instance_id: device_instance_id(devs, data.as_mut_ptr()),
                hardware_ids,
                vendor_id,
                device_id,
                problem_code,
                started,
            });
            if index > 4096 {
                break;
            }
        }
        unsafe { SetupDiDestroyDeviceInfoList(devs) };
        Ok(out)
    }

    // ---- audio endpoints (winmm, legacy wave API) ----
    #[link(name = "winmm")]
    extern "system" {
        fn waveOutGetNumDevs() -> u32;
        fn waveInGetNumDevs() -> u32;
        fn waveOutGetDevCapsW(device: usize, caps: *mut u8, size: u32) -> u32;
        fn waveInGetDevCapsW(device: usize, caps: *mut u8, size: u32) -> u32;
    }

    fn wave_devices(output: bool) -> Vec<AudioDevice> {
        const WAVEOUTCAPS_SIZE: usize = 84;
        const WAVEINCAPS_SIZE: usize = 80;
        let mut out = Vec::new();
        let count = if output {
            unsafe { waveOutGetNumDevs() }
        } else {
            unsafe { waveInGetNumDevs() }
        };
        let size = if output {
            WAVEOUTCAPS_SIZE
        } else {
            WAVEINCAPS_SIZE
        };
        let direction = if output { "output" } else { "input" };
        for index in 0..count.min(64) {
            let mut buf = vec![0u8; size];
            let rc = if output {
                unsafe { waveOutGetDevCapsW(index as usize, buf.as_mut_ptr(), size as u32) }
            } else {
                unsafe { waveInGetDevCapsW(index as usize, buf.as_mut_ptr(), size as u32) }
            };
            if rc != 0 {
                continue;
            }
            if let Some(caps) = parse_wave_caps(&buf) {
                out.push(AudioDevice {
                    name: caps.name,
                    direction: direction.to_string(),
                    channels: caps.channels,
                    manufacturer_id: caps.manufacturer_id,
                    product_id: caps.product_id,
                    driver_version: caps.driver_version,
                });
            }
        }
        out
    }

    pub fn audio_devices() -> CResult<Vec<AudioDevice>> {
        let mut out = wave_devices(true);
        out.extend(wave_devices(false));
        Ok(out)
    }

    // ---- printers (winspool) ----
    #[link(name = "winspool")]
    extern "system" {
        fn EnumPrintersW(
            flags: u32,
            name: *mut u16,
            level: u32,
            printers: *mut u8,
            buf_size: u32,
            needed: *mut u32,
            returned: *mut u32,
        ) -> i32;
        fn GetDefaultPrinterW(name: *mut u16, size: *mut u32) -> i32;
    }

    fn default_printer_name() -> String {
        let mut size: u32 = 0;
        unsafe { GetDefaultPrinterW(std::ptr::null_mut(), &mut size) };
        if size == 0 || size > 8192 {
            return String::new();
        }
        let mut buf = vec![0u16; size as usize];
        if unsafe { GetDefaultPrinterW(buf.as_mut_ptr(), &mut size) } == 0 {
            return String::new();
        }
        let units: Vec<u16> = buf.iter().copied().take_while(|&u| u != 0).collect();
        String::from_utf16_lossy(&units)
    }

    /// A NUL-terminated wide string packed inside `buf` at the
    /// absolute address `ptr` (how EnumPrinters level-2 records
    /// reference their strings); empty for null / out-of-buffer.
    fn packed_wide_string(buf: &[u8], ptr: usize) -> String {
        let base = buf.as_ptr() as usize;
        if ptr < base || ptr >= base + buf.len() {
            return String::new();
        }
        wide_string_from_bytes(&buf[ptr - base..])
    }

    pub fn printers() -> CResult<Vec<PrinterInfo>> {
        const PRINTER_ENUM_LOCAL: u32 = 0x2;
        const PRINTER_ENUM_CONNECTIONS: u32 = 0x4;
        const PRINTER_ATTRIBUTE_SHARED: u32 = 0x8;
        let mut out = Vec::new();
        let mut needed: u32 = 0;
        let mut returned: u32 = 0;
        unsafe {
            EnumPrintersW(
                PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS,
                std::ptr::null_mut(),
                2,
                std::ptr::null_mut(),
                0,
                &mut needed,
                &mut returned,
            )
        };
        if needed == 0 || needed > 16 * 1024 * 1024 {
            return Ok(out);
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = unsafe {
            EnumPrintersW(
                PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS,
                std::ptr::null_mut(),
                2,
                buf.as_mut_ptr(),
                needed,
                &mut needed,
                &mut returned,
            )
        };
        if ok == 0 {
            return Ok(out);
        }
        let default_name = default_printer_name();
        // PRINTER_INFO_2W: 13 pointer fields (name @1, port @3,
        // driver @4), then Attributes / Priority / DefaultPriority
        // / StartTime / UntilTime / Status / cJobs / AveragePPM as
        // u32s. Offsets are pointer-sized, so the layout holds on
        // 32- and 64-bit alike.
        let p = std::mem::size_of::<usize>();
        let record_size = 13 * p + 8 * 4;
        let ptr_at = |record: &[u8], field: usize| -> usize {
            unsafe { std::ptr::read_unaligned(record.as_ptr().add(field * p) as *const usize) }
        };
        let u32_at = |record: &[u8], off: usize| -> u32 {
            u32::from_le_bytes([
                record[off],
                record[off + 1],
                record[off + 2],
                record[off + 3],
            ])
        };
        for i in 0..returned as usize {
            let start = i * record_size;
            let record = match buf.get(start..start + record_size) {
                Some(r) => r,
                None => break,
            };
            let name = packed_wide_string(&buf, ptr_at(record, 1));
            let is_default = !default_name.is_empty() && name == default_name;
            out.push(PrinterInfo {
                name,
                driver: packed_wide_string(&buf, ptr_at(record, 4)),
                port: packed_wide_string(&buf, ptr_at(record, 3)),
                is_default,
                shared: u32_at(record, 13 * p) & PRINTER_ATTRIBUTE_SHARED != 0,
                status: u32_at(record, 13 * p + 20),
                jobs: u32_at(record, 13 * p + 24),
            });
        }
        Ok(out)
    }
}

#[cfg(not(windows))]
use crate::{
    AdapterInfo, AudioDevice, BatteryHealth, BatteryInfo, BoardInfo, CpuInfo, DiskInfo, DiskSmart,
    GpuInfo, MemoryInfo, MonitorInfo, OsInfo, PhysicalDiskInfo, PlatformInfo, PnpDevice,
    PrinterInfo, RamModule,
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
#[cfg(not(windows))]
pub fn physical_disks() -> CResult<Vec<PhysicalDiskInfo>> {
    not_supported("physical_disks")
}
#[cfg(not(windows))]
pub fn smart_disks() -> CResult<Vec<DiskSmart>> {
    not_supported("smart_disks")
}
#[cfg(not(windows))]
pub fn ram_modules() -> CResult<Vec<RamModule>> {
    not_supported("ram_modules")
}
#[cfg(not(windows))]
pub fn batteries() -> CResult<Vec<BatteryHealth>> {
    not_supported("batteries")
}
#[cfg(not(windows))]
pub fn platform_info() -> CResult<PlatformInfo> {
    not_supported("platform_info")
}
#[cfg(not(windows))]
pub fn devices() -> CResult<Vec<PnpDevice>> {
    not_supported("devices")
}
#[cfg(not(windows))]
pub fn audio_devices() -> CResult<Vec<AudioDevice>> {
    not_supported("audio_devices")
}
#[cfg(not(windows))]
pub fn printers() -> CResult<Vec<PrinterInfo>> {
    not_supported("printers")
}
