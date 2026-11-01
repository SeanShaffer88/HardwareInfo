//! Windows-only CI proof: run every probe against the CI machine
//! and validate the invariants that must hold on ANY real Windows
//! box (CPU present with cores, memory > 0, at least one fixed disk,
//! OS build > 0, SMBIOS readable). On non-Windows this file is empty.
#![cfg(windows)]

use hardwareinfo::ffi::*;

fn take(p: *mut std::os::raw::c_char) -> String {
    assert!(!p.is_null(), "probe returned null: {}", unsafe {
        std::ffi::CStr::from_ptr(hw_last_error()).to_string_lossy()
    });
    let s = unsafe { std::ffi::CStr::from_ptr(p) }
        .to_string_lossy()
        .into_owned();
    hw_free_string(p);
    s
}

#[test]
fn probes_return_plausible_data() {
    let cpu = take(hw_cpu_json());
    assert!(cpu.contains("\"logical_processors\":"), "{cpu}");
    assert!(!cpu.contains("\"logical_processors\":0"), "{cpu}");
    assert!(
        cpu.contains("\"brand\":\"") && !cpu.contains("\"brand\":\"\""),
        "brand: {cpu}"
    );

    let os = take(hw_os_json());
    assert!(os.contains("\"build\":"), "{os}");
    assert!(!os.contains("\"build\":0"), "build: {os}");
    assert!(os.contains("Windows"), "product: {os}");

    let mem = take(hw_memory_json());
    assert!(mem.contains("\"total_phys_bytes\":"), "{mem}");
    assert!(!mem.contains("\"total_phys_bytes\":0"), "{mem}");

    let disks = take(hw_disks_json());
    assert!(disks.contains("\"letter\":\"C:\""), "disks: {disks}");
    assert!(disks.contains("\"total_bytes\":"), "{disks}");

    // Every real box (CI agents included, which run elevated) has
    // a PhysicalDrive0 whose descriptor + geometry answer.
    let physical = take(hw_physical_disks_json());
    assert!(physical.contains("\"index\":0"), "physical: {physical}");
    assert!(physical.contains("\"size_bytes\":"), "{physical}");
    assert!(!physical.contains("\"size_bytes\":0"), "size: {physical}");
    assert!(physical.contains("\"health\":\""), "{physical}");

    // SMBIOS is present on CI VMs; a module list may be short but
    // populated modules report a real capacity.
    let ram = take(hw_ram_json());
    assert!(ram.starts_with('['), "{ram}");
    if ram != "[]" {
        assert!(ram.contains("\"capacity_bytes\":"), "{ram}");
        assert!(!ram.contains("\"capacity_bytes\":0"), "ram: {ram}");
    }

    // GPU/monitor/network/battery/board/platform: shape only (a
    // headless CI agent may have a basic display driver, no
    // battery, and firmware settings we don't control).
    let gpus = take(hw_gpus_json());
    assert!(gpus.starts_with('['), "{gpus}");
    if gpus != "[]" {
        assert!(gpus.contains("\"driver_version\":"), "{gpus}");
        assert!(gpus.contains("\"dedicated_video_memory_bytes\":"), "{gpus}");
    }
    let monitors = take(hw_monitors_json());
    assert!(monitors.starts_with('['), "{monitors}");
    let net = take(hw_network_json());
    assert!(net.starts_with('['), "{net}");
    assert!(net.contains("\"mac\""), "{net}");
    let battery = take(hw_battery_json());
    assert!(battery.contains("\"present\":"), "{battery}");
    let batteries = take(hw_batteries_json());
    assert!(batteries.starts_with('['), "{batteries}");
    if batteries != "[]" {
        assert!(batteries.contains("\"health_percent\":"), "{batteries}");
        assert!(
            batteries.contains("\"designed_capacity_mwh\":"),
            "{batteries}"
        );
    }
    let board = take(hw_board_json());
    assert!(board.contains("\"bios_version\""), "{board}");
    assert!(board.contains("\"system_uuid\""), "{board}");
    let platform = take(hw_platform_json());
    assert!(platform.contains("\"firmware_type\":\""), "{platform}");
    assert!(
        platform.contains("\"secure_boot_enabled\":"),
        "{platform}"
    );
    assert!(platform.contains("\"tpm_present\":"), "{platform}");

    let system = take(hw_system_json());
    for key in [
        "\"cpu\"",
        "\"os\"",
        "\"memory\"",
        "\"ram\"",
        "\"disks\"",
        "\"physical_disks\"",
        "\"gpus\"",
        "\"network\"",
        "\"batteries\"",
        "\"board\"",
        "\"platform\"",
    ] {
        assert!(system.contains(key), "system json missing {key}: {system}");
    }
}
