//! C ABI surface — everything declared in include/hardwareinfo.h.
//! Conventions (house standard):
//! - Every probe returns a caller-owned JSON string; free with
//!   `hw_free_string`. Failures return null + the thread-local error.
//! - `hw_system_json` never fails wholesale: each section is its own
//!   probe, and a failed section reports {"error": "..."} inline.
//! - Nothing unwinds across the FFI boundary.

use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::platform;
use crate::{
    adapters_json, disks_json, gpus_json, json_escape, monitors_json, physical_disks_json,
    ram_json, ERR_INTERNAL, HW_OK, VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH,
};

thread_local! {
    static LAST_ERROR: RefCell<(i32, CString)> =
        RefCell::new((0, CString::new("").unwrap()));
}

pub fn set_error(code: i32, msg: &str) {
    let cleaned: String = msg
        .chars()
        .map(|c| if c == '\0' { ' ' } else { c })
        .collect();
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = (
            code,
            CString::new(cleaned).unwrap_or_else(|_| CString::new("error").unwrap()),
        );
    });
}

fn clear_error() {
    set_error(HW_OK, "");
}

fn guard<T, F: FnOnce() -> T>(f: F) -> Result<T, (i32, String)> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => Ok(v),
        Err(_) => Err((ERR_INTERNAL, "internal panic caught at FFI boundary".into())),
    }
}

fn finish_str(run: Result<Result<String, (i32, String)>, (i32, String)>) -> *mut c_char {
    match run {
        Ok(Ok(s)) => {
            clear_error();
            match CString::new(s) {
                Ok(c) => c.into_raw(),
                Err(_) => {
                    set_error(ERR_INTERNAL, "result contained a NUL byte");
                    std::ptr::null_mut()
                }
            }
        }
        Ok(Err((code, msg))) | Err((code, msg)) => {
            set_error(code, &msg);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn hw_version() -> *const c_char {
    static VERSION_C: &[u8] = b"0.2.0\0";
    VERSION_C.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn hw_version_major() -> c_int {
    VERSION_MAJOR as c_int
}

#[no_mangle]
pub extern "C" fn hw_version_minor() -> c_int {
    VERSION_MINOR as c_int
}

#[no_mangle]
pub extern "C" fn hw_version_patch() -> c_int {
    VERSION_PATCH as c_int
}

#[no_mangle]
pub extern "C" fn hw_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().1.as_ptr())
}

#[no_mangle]
pub extern "C" fn hw_last_error_code() -> c_int {
    LAST_ERROR.with(|e| e.borrow().0) as c_int
}

/// # Safety (caller contract): `p` is null or a string this library
/// returned and has not been freed yet.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
#[no_mangle]
pub extern "C" fn hw_free_string(p: *mut c_char) {
    if !p.is_null() {
        unsafe {
            drop(CString::from_raw(p));
        }
    }
}

#[no_mangle]
pub extern "C" fn hw_cpu_json() -> *mut c_char {
    finish_str(guard(|| platform::cpu_info().map(|c| c.to_json())))
}

#[no_mangle]
pub extern "C" fn hw_os_json() -> *mut c_char {
    finish_str(guard(|| platform::os_info().map(|o| o.to_json())))
}

#[no_mangle]
pub extern "C" fn hw_memory_json() -> *mut c_char {
    finish_str(guard(|| platform::memory_info().map(|m| m.to_json())))
}

#[no_mangle]
pub extern "C" fn hw_disks_json() -> *mut c_char {
    finish_str(guard(|| platform::disks().map(|d| disks_json(&d))))
}

#[no_mangle]
pub extern "C" fn hw_physical_disks_json() -> *mut c_char {
    finish_str(guard(|| platform::physical_disks().map(|d| physical_disks_json(&d))))
}

#[no_mangle]
pub extern "C" fn hw_ram_json() -> *mut c_char {
    finish_str(guard(|| platform::ram_modules().map(|m| ram_json(&m))))
}

#[no_mangle]
pub extern "C" fn hw_gpus_json() -> *mut c_char {
    finish_str(guard(|| platform::gpus().map(|g| gpus_json(&g))))
}

#[no_mangle]
pub extern "C" fn hw_monitors_json() -> *mut c_char {
    finish_str(guard(|| platform::monitors().map(|m| monitors_json(&m))))
}

#[no_mangle]
pub extern "C" fn hw_network_json() -> *mut c_char {
    finish_str(guard(|| platform::adapters().map(|a| adapters_json(&a))))
}

#[no_mangle]
pub extern "C" fn hw_battery_json() -> *mut c_char {
    finish_str(guard(|| platform::battery().map(|b| b.to_json())))
}

#[no_mangle]
pub extern "C" fn hw_board_json() -> *mut c_char {
    finish_str(guard(|| platform::board().map(|b| b.to_json())))
}

/// All sections in one document; a failed section is
/// {"error":"..."} in place of its data so the aggregate call only
/// fails on non-Windows.
#[no_mangle]
pub extern "C" fn hw_system_json() -> *mut c_char {
    fn section<T, F: FnOnce() -> Result<T, (i32, String)>, J: FnOnce(T) -> String>(
        probe: F,
        to_json: J,
    ) -> String {
        match probe() {
            Ok(v) => to_json(v),
            Err((_, msg)) => format!("{{\"error\":\"{}\"}}", json_escape(&msg)),
        }
    }
    finish_str(guard(|| {
        if !platform::platform_available() {
            return platform::not_supported("hardware probes");
        }
        Ok(format!(
            "{{\"cpu\":{},\"os\":{},\"memory\":{},\"ram\":{},\"disks\":{},\"physical_disks\":{},\"gpus\":{},\"monitors\":{},\"network\":{},\"battery\":{},\"board\":{}}}",
            section(platform::cpu_info, |c| c.to_json()),
            section(platform::os_info, |o| o.to_json()),
            section(platform::memory_info, |m| m.to_json()),
            section(platform::ram_modules, |m| ram_json(&m)),
            section(platform::disks, |d| disks_json(&d)),
            section(platform::physical_disks, |d| physical_disks_json(&d)),
            section(platform::gpus, |g| gpus_json(&g)),
            section(platform::monitors, |m| monitors_json(&m)),
            section(platform::adapters, |a| adapters_json(&a)),
            section(platform::battery, |b| b.to_json()),
            section(platform::board, |b| b.to_json()),
        ))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_off_windows() {
        if cfg!(windows) {
            // Native behavior is proven by tests/roundtrip.rs in CI.
            assert!(!hw_cpu_json().is_null());
        } else {
            assert!(hw_cpu_json().is_null());
            assert_eq!(hw_last_error_code(), crate::ERR_NOT_SUPPORTED);
            assert!(hw_physical_disks_json().is_null());
            assert_eq!(hw_last_error_code(), crate::ERR_NOT_SUPPORTED);
            assert!(hw_ram_json().is_null());
            assert_eq!(hw_last_error_code(), crate::ERR_NOT_SUPPORTED);
            assert!(hw_system_json().is_null());
        }
    }
}
