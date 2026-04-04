use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{GetLastError, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;

use crate::{SandboxError, cap_fs};

pub(super) fn to_wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

pub(super) fn format_last_error(code: i32) -> String {
    std::io::Error::from_raw_os_error(code).to_string()
}

pub(super) fn normalize_null_device_env(env_map: &mut HashMap<String, String>) {
    let keys: Vec<String> = env_map.keys().cloned().collect();
    for key in keys {
        if let Some(value) = env_map.get(&key).cloned() {
            let lowered = value.trim().to_ascii_lowercase();
            if lowered == "/dev/null" || lowered == "\\\\dev\\null" {
                env_map.insert(key, "NUL".to_string());
            }
        }
    }
}

pub(super) fn ensure_non_interactive_pager(env_map: &mut HashMap<String, String>) {
    env_map
        .entry("GIT_PAGER".to_string())
        .or_insert_with(|| "more.com".to_string());
    env_map
        .entry("PAGER".to_string())
        .or_insert_with(|| "more.com".to_string());
    env_map.entry("LESS".to_string()).or_default();
}

pub(super) fn ensure_safe_allow_path(path: &Path) -> Result<PathBuf, SandboxError> {
    if !cap_fs::path_exists(path) {
        return Err(SandboxError::InvalidRequest(format!(
            "allow path does not exist: {}",
            path.display()
        )));
    }

    cap_fs::canonicalize_path(path).map_err(SandboxError::Io)
}

pub(super) fn sid_to_string(sid: *mut c_void) -> Result<String, SandboxError> {
    if sid.is_null() {
        return Err(SandboxError::Windows(
            "unable to convert null sid to string".to_string(),
        ));
    }

    unsafe {
        let mut sid_string_ptr: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut sid_string_ptr) == 0 {
            let code = GetLastError() as i32;
            return Err(SandboxError::Windows(format!(
                "ConvertSidToStringSidW failed: {code} ({})",
                format_last_error(code)
            )));
        }

        let mut len = 0;
        while *sid_string_ptr.add(len) != 0 {
            len += 1;
        }
        let sid_string = String::from_utf16_lossy(std::slice::from_raw_parts(sid_string_ptr, len));
        LocalFree(sid_string_ptr as HLOCAL);
        Ok(sid_string)
    }
}
