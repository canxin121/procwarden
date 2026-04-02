#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::ACL;
use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
use windows_sys::Win32::Security::Authorization::SetEntriesInAclW;
use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_SID;
use windows_sys::Win32::Security::Authorization::TRUSTEE_IS_UNKNOWN;
use windows_sys::Win32::Security::Authorization::TRUSTEE_W;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;

use crate::SandboxError;

use super::util::to_wide;

const SE_KERNEL_OBJECT: u32 = 6;
const READ_ONLY_ALLOW_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
const READ_WRITE_ALLOW_MASK: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;

pub(super) struct AclRollback {
    sid: *mut c_void,
    paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub(super) struct AclAccessPlan {
    pub(super) allow_readonly_paths: Vec<PathBuf>,
    pub(super) allow_readwrite_paths: Vec<PathBuf>,
    pub(super) deny_write_paths: Vec<PathBuf>,
}

pub(super) unsafe fn apply_access_plan(
    plan: &AclAccessPlan,
    sid: *mut c_void,
) -> Result<AclRollback, SandboxError> {
    let mut rollback = AclRollback::new(sid);

    for path in &plan.deny_write_paths {
        let added = add_deny_write_ace(path, sid)?;
        if added {
            rollback.track(path.clone());
        }
    }

    for path in &plan.allow_readonly_paths {
        let added = add_allow_read_only_ace(path, sid)?;
        if added {
            rollback.track(path.clone());
        }
    }

    for path in &plan.allow_readwrite_paths {
        let added = add_allow_read_write_ace(path, sid)?;
        if added {
            rollback.track(path.clone());
        }
    }

    allow_null_device(sid);
    Ok(rollback)
}

pub(super) unsafe fn apply_optional_readonly_paths(
    paths: &[PathBuf],
    sid: *mut c_void,
) -> AclRollback {
    let mut rollback = AclRollback::new(sid);

    for path in paths {
        if let Ok(true) = add_allow_read_only_ace(path, sid) {
            rollback.track(path.clone());
        }
    }

    rollback
}

impl AclRollback {
    pub(super) fn new(sid: *mut c_void) -> Self {
        Self {
            sid,
            paths: Vec::new(),
        }
    }

    pub(super) fn track(&mut self, path: PathBuf) {
        self.paths.push(path);
    }
}

impl Drop for AclRollback {
    fn drop(&mut self) {
        unsafe {
            for path in &self.paths {
                revoke_ace(path, self.sid);
            }
        }
    }
}

pub(super) unsafe fn add_allow_read_write_ace(
    path: &Path,
    sid: *mut c_void,
) -> Result<bool, SandboxError> {
    add_allow_access_ace(path, sid, READ_WRITE_ALLOW_MASK)
}

pub(super) unsafe fn add_allow_read_only_ace(
    path: &Path,
    sid: *mut c_void,
) -> Result<bool, SandboxError> {
    add_allow_access_ace(path, sid, READ_ONLY_ALLOW_MASK)
}

unsafe fn add_allow_access_ace(
    path: &Path,
    sid: *mut c_void,
    access_mask: u32,
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
        return Err(SandboxError::Windows(format!(
            "GetNamedSecurityInfoW failed with code {code} for {}",
            path.display()
        )));
    }

    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: sid as *mut u16,
    };

    let mut explicit: EXPLICIT_ACCESS_W = std::mem::zeroed();
    explicit.grfAccessPermissions = access_mask;
    explicit.grfAccessMode = 2;
    explicit.grfInheritance = windows_sys::Win32::Security::CONTAINER_INHERIT_ACE
        | windows_sys::Win32::Security::OBJECT_INHERIT_ACE;
    explicit.Trustee = trustee;

    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let code2 = SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl);
    if code2 != ERROR_SUCCESS {
        if !p_sd.is_null() {
            LocalFree(p_sd as HLOCAL);
        }
        return Err(SandboxError::Windows(format!(
            "SetEntriesInAclW failed with code {code2} for {}",
            path.display()
        )));
    }

    let code3 = SetNamedSecurityInfoW(
        to_wide(path).as_ptr() as *mut u16,
        1,
        DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        p_new_dacl,
        std::ptr::null_mut(),
    );
    if !p_new_dacl.is_null() {
        LocalFree(p_new_dacl as HLOCAL);
    }
    if code3 != ERROR_SUCCESS {
        if !p_sd.is_null() {
            LocalFree(p_sd as HLOCAL);
        }
        return Err(SandboxError::Windows(format!(
            "SetNamedSecurityInfoW failed with code {code3} for {}",
            path.display()
        )));
    }

    if !p_sd.is_null() {
        LocalFree(p_sd as HLOCAL);
    }
    Ok(true)
}

pub(super) unsafe fn add_deny_write_ace(
    path: &Path,
    sid: *mut c_void,
) -> Result<bool, SandboxError> {
    add_deny_access_ace(path, sid, FILE_GENERIC_WRITE)
}

unsafe fn add_deny_access_ace(
    path: &Path,
    sid: *mut c_void,
    access_mask: u32,
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
        return Err(SandboxError::Windows(format!(
            "GetNamedSecurityInfoW failed with code {code} for {}",
            path.display()
        )));
    }

    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: sid as *mut u16,
    };
    let mut explicit: EXPLICIT_ACCESS_W = std::mem::zeroed();
    explicit.grfAccessPermissions = access_mask;
    explicit.grfAccessMode = 3;
    explicit.grfInheritance = windows_sys::Win32::Security::CONTAINER_INHERIT_ACE
        | windows_sys::Win32::Security::OBJECT_INHERIT_ACE;
    explicit.Trustee = trustee;

    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let code2 = SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl);
    if code2 != ERROR_SUCCESS {
        if !p_sd.is_null() {
            LocalFree(p_sd as HLOCAL);
        }
        return Err(SandboxError::Windows(format!(
            "SetEntriesInAclW failed with code {code2} for {}",
            path.display()
        )));
    }

    let code3 = SetNamedSecurityInfoW(
        to_wide(path).as_ptr() as *mut u16,
        1,
        DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        p_new_dacl,
        std::ptr::null_mut(),
    );
    if !p_new_dacl.is_null() {
        LocalFree(p_new_dacl as HLOCAL);
    }
    if code3 != ERROR_SUCCESS {
        if !p_sd.is_null() {
            LocalFree(p_sd as HLOCAL);
        }
        return Err(SandboxError::Windows(format!(
            "SetNamedSecurityInfoW failed with code {code3} for {}",
            path.display()
        )));
    }

    if !p_sd.is_null() {
        LocalFree(p_sd as HLOCAL);
    }
    Ok(true)
}

pub(super) unsafe fn revoke_ace(path: &Path, sid: *mut c_void) {
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
        return;
    }

    let trustee = TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: 0,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: sid as *mut u16,
    };
    let mut explicit: EXPLICIT_ACCESS_W = std::mem::zeroed();
    explicit.grfAccessPermissions = 0;
    explicit.grfAccessMode = 4;
    explicit.grfInheritance = windows_sys::Win32::Security::CONTAINER_INHERIT_ACE
        | windows_sys::Win32::Security::OBJECT_INHERIT_ACE;
    explicit.Trustee = trustee;

    let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
    let code2 = SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl);
    if code2 == ERROR_SUCCESS {
        let _ = SetNamedSecurityInfoW(
            to_wide(path).as_ptr() as *mut u16,
            1,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            p_new_dacl,
            std::ptr::null_mut(),
        );
        if !p_new_dacl.is_null() {
            LocalFree(p_new_dacl as HLOCAL);
        }
    }

    if !p_sd.is_null() {
        LocalFree(p_sd as HLOCAL);
    }
}

pub(super) unsafe fn allow_null_device(sid: *mut c_void) {
    let desired = 0x0002_0000 | 0x0004_0000;
    let handle = CreateFileW(
        to_wide(r"\\.\NUL").as_ptr(),
        desired,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        std::ptr::null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        std::ptr::null_mut(),
    );
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return;
    }

    let mut p_sd: *mut c_void = std::ptr::null_mut();
    let mut p_dacl: *mut ACL = std::ptr::null_mut();
    let code = GetSecurityInfo(
        handle,
        SE_KERNEL_OBJECT as i32,
        DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut p_dacl,
        std::ptr::null_mut(),
        &mut p_sd,
    );
    if code == ERROR_SUCCESS {
        let trustee = TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid as *mut u16,
        };
        let mut explicit: EXPLICIT_ACCESS_W = std::mem::zeroed();
        explicit.grfAccessPermissions =
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;
        explicit.grfAccessMode = 2;
        explicit.grfInheritance = 0;
        explicit.Trustee = trustee;

        let mut p_new_dacl: *mut ACL = std::ptr::null_mut();
        if SetEntriesInAclW(1, &explicit, p_dacl, &mut p_new_dacl) == ERROR_SUCCESS {
            let _ = SetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT as i32,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                p_new_dacl,
                std::ptr::null_mut(),
            );
            if !p_new_dacl.is_null() {
                LocalFree(p_new_dacl as HLOCAL);
            }
        }
    }

    if !p_sd.is_null() {
        LocalFree(p_sd as HLOCAL);
    }
    CloseHandle(handle);
}
