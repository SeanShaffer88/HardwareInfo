//! Windows-only CI proof: run every probe against the CI machine
//! and validate the invariants that must hold on ANY real Windows
//! box (CPU present with cores, memory > 0, at least one fixed disk,
//! OS build > 0). On non-Windows this file is empty.
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

    // GPU/monitor/network/battery/board: shape only (a headless CI
    // agent may have a basic display driver and no battery).
    let gpus = take(hw_gpus_json());
    assert!(gpus.starts_with('['), "{gpus}");
    let monitors = take(hw_monitors_json());
    assert!(monitors.starts_with('['), "{monitors}");
    let net = take(hw_network_json());
    assert!(net.starts_with('['), "{net}");
    assert!(net.contains("\"mac\""), "{net}");
    let battery = take(hw_battery_json());
    assert!(battery.contains("\"present\":"), "{battery}");
    let board = take(hw_board_json());
    assert!(board.contains("\"bios_version\""), "{board}");

    let system = take(hw_system_json());
    for key in [
        "\"cpu\"",
        "\"os\"",
        "\"memory\"",
        "\"disks\"",
        "\"network\"",
        "\"board\"",
    ] {
        assert!(system.contains(key), "system json missing {key}: {system}");
    }
}
