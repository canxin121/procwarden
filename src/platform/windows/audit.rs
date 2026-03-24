#![allow(unsafe_op_in_unsafe_fn)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

use crate::{SandboxError, cap_fs};

use super::acl::dacl_effective_allows_write;
use super::token::OwnedSid;
use super::util::to_wide;

pub(super) fn audit_paths_for_world_writable(
    allow_paths: &[PathBuf],
    env_map: &HashMap<String, String>,
    cwd: &Path,
) -> Result<(), SandboxError> {
    let candidates = gather_candidates(allow_paths, env_map, cwd);

    let world_sid = OwnedSid::from_string_sid("S-1-1-0")?;
    let start = Instant::now();
    let mut flagged = Vec::new();
    let mut checked = 0usize;

    for root in candidates {
        if start.elapsed() > Duration::from_secs(4) || checked > 2000 {
            break;
        }
        checked += 1;
        if unsafe { path_has_world_write_allow(&root, world_sid.raw())? } {
            flagged.push(root.clone());
        }

        if let Ok(children) = cap_fs::child_directories(&root, 40) {
            for child in children {
                if start.elapsed() > Duration::from_secs(4) || checked > 2000 {
                    break;
                }

                checked += 1;
                if unsafe { path_has_world_write_allow(&child, world_sid.raw())? } {
                    flagged.push(child);
                }
            }
        }
    }

    if flagged.is_empty() {
        return Ok(());
    }

    let formatted = flagged
        .iter()
        .take(8)
        .map(|path| format!(" - {}", path.display()))
        .collect::<Vec<_>>()
        .join("\n");
    Err(SandboxError::AuditFailed(format!(
        "world-writable directories detected before sandbox launch:\n{}",
        formatted
    )))
}

fn gather_candidates(
    allow_paths: &[PathBuf],
    env_map: &HashMap<String, String>,
    cwd: &Path,
) -> Vec<PathBuf> {
    let mut candidates = allow_paths.to_vec();
    candidates.push(cwd.to_path_buf());

    let path_var = env_map
        .get("PATH")
        .cloned()
        .or_else(|| std::env::var("PATH").ok())
        .unwrap_or_default();
    for part in path_var.split(';').filter(|part| !part.trim().is_empty()) {
        candidates.push(PathBuf::from(part.trim()));
    }

    cap_fs::PathPolicy::ascii_case_insensitive().normalize_paths(candidates)
}

unsafe fn path_has_world_write_allow(
    path: &Path,
    world_sid: *mut c_void,
) -> Result<bool, SandboxError> {
    let mut p_sd: *mut c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let code = GetNamedSecurityInfoW(
        to_wide(path).as_ptr(),
        1,
        DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut p_dacl,
        std::ptr::null_mut(),
        &mut p_sd,
    );
    if code != ERROR_SUCCESS {
        if !p_sd.is_null() {
            LocalFree(p_sd as HLOCAL);
        }
        return Err(SandboxError::AuditFailed(format!(
            "failed to inspect DACL for {}",
            path.display()
        )));
    }

    let has = dacl_effective_allows_write(p_dacl, world_sid);
    if !p_sd.is_null() {
        LocalFree(p_sd as HLOCAL);
    }
    Ok(has)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    use super::gather_candidates;

    #[test]
    fn gather_candidates_includes_cwd_and_dedupes_case_insensitive_entries() {
        let allow_paths = vec![PathBuf::from(r"C:\allow"), PathBuf::from(r"c:\ALLOW")];
        let cwd = PathBuf::from(r"C:\workspace");

        let mut env = HashMap::new();
        env.insert("PATH".to_string(), r"C:\tools;c:\TOOLS;C:\bin".to_string());

        let candidates = gather_candidates(&allow_paths, &env, &cwd);
        let matches_case_insensitive = |needle: &str| {
            candidates
                .iter()
                .filter(|path| path.to_string_lossy().eq_ignore_ascii_case(needle))
                .count()
        };

        assert!(
            candidates.iter().any(|path| path == &cwd),
            "cwd should always be audited"
        );
        assert_eq!(matches_case_insensitive(r"C:\allow"), 1);
        assert_eq!(matches_case_insensitive(r"C:\tools"), 1);
        assert_eq!(matches_case_insensitive(r"C:\bin"), 1);
    }

    #[test]
    fn gather_candidates_handles_missing_path_variable() {
        let allow_paths = vec![PathBuf::from(r"C:\allow")];
        let cwd = PathBuf::from(r"C:\workspace");
        let env = HashMap::new();

        let candidates = gather_candidates(&allow_paths, &env, &cwd);

        assert!(
            candidates
                .iter()
                .any(|path| path.to_string_lossy().eq_ignore_ascii_case(r"C:\allow"))
        );
        assert!(
            candidates
                .iter()
                .any(|path| { path.to_string_lossy().eq_ignore_ascii_case(r"C:\workspace") })
        );
    }
}
