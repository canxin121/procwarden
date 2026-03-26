use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
