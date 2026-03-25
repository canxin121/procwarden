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

    reject_dangerous_namespace(path)?;

    let (final_path, file_attributes) = resolve_final_path_and_attributes(path)?;

    if (file_attributes & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT)
        != 0
    {
        return Err(SandboxError::Denied(format!(
            "allow path cannot be a reparse point: {}",
            final_path.display()
        )));
    }

    if cap_fs::is_symlink(&final_path)? {
        return Err(SandboxError::Denied(format!(
            "allow path cannot be a symlink: {}",
            final_path.display()
        )));
    }

    cap_fs::canonicalize_path(&final_path).map_err(SandboxError::Io)
}

fn reject_dangerous_namespace(path: &Path) -> Result<(), SandboxError> {
    let raw = path.to_string_lossy();
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with(r"\\.\")
        || lower.starts_with(r"\??\")
        || lower.starts_with(r"\\?\globalroot")
    {
        return Err(SandboxError::Denied(format!(
            "allow path uses disallowed namespace: {}",
            path.display()
        )));
    }
    Ok(())
}

fn resolve_final_path_and_attributes(path: &Path) -> Result<(PathBuf, u32), SandboxError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;
    use windows_sys::Win32::Storage::FileSystem::CreateFileW;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
    use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;

    let wide_path = to_wide(path.as_os_str());
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() } as i32;
        return Err(SandboxError::Windows(format!(
            "CreateFileW failed for {}: {}",
            path.display(),
            format_last_error(code)
        )));
    }

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        let code = unsafe { GetLastError() } as i32;
        unsafe {
            CloseHandle(handle);
        }
        return Err(SandboxError::Windows(format!(
            "GetFileInformationByHandle failed for {}: {}",
            path.display(),
            format_last_error(code)
        )));
    }

    let required_len = unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, 0) };
    if required_len == 0 {
        let code = unsafe { GetLastError() } as i32;
        unsafe {
            CloseHandle(handle);
        }
        return Err(SandboxError::Windows(format!(
            "GetFinalPathNameByHandleW(size) failed for {}: {}",
            path.display(),
            format_last_error(code)
        )));
    }

    let mut buffer = vec![0_u16; required_len as usize + 1];
    let written =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) };
    unsafe {
        CloseHandle(handle);
    }
    if written == 0 {
        return Err(SandboxError::Windows(format!(
            "GetFinalPathNameByHandleW(path) failed for {}",
            path.display()
        )));
    }

    let text = String::from_utf16_lossy(&buffer[..written as usize]);
    let normalized = normalize_final_path_string(&text);
    Ok((PathBuf::from(normalized), info.dwFileAttributes))
}

fn normalize_final_path_string(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if lower.starts_with(r"\\?\unc\") {
        return format!(r"\\{}", &path[8..]);
    }
    if lower.starts_with(r"\\?\") {
        return path[4..].to_string();
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{normalize_final_path_string, reject_dangerous_namespace};

    #[test]
    fn rejects_dangerous_windows_namespaces() {
        let paths = [
            Path::new(r"\\.\NUL"),
            Path::new(r"\??\C:\\temp"),
            Path::new(r"\\?\GLOBALROOT\Device\HarddiskVolume1"),
        ];

        for path in paths {
            let result = reject_dangerous_namespace(path);
            assert!(result.is_err(), "path should be rejected: {path:?}");
        }
    }

    #[test]
    fn normalizes_final_path_prefixes() {
        let dos = normalize_final_path_string(r"\\?\C:\repo");
        let unc = normalize_final_path_string(r"\\?\UNC\server\share\dir");
        assert_eq!(dos, r"C:\repo");
        assert_eq!(unc, r"\\server\share\dir");
    }
}
