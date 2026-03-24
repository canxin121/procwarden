#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LUID;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::AdjustTokenPrivileges;
use windows_sys::Win32::Security::CopySid;
use windows_sys::Win32::Security::CreateRestrictedToken;
use windows_sys::Win32::Security::CreateWellKnownSid;
use windows_sys::Win32::Security::GetLengthSid;
use windows_sys::Win32::Security::GetTokenInformation;
use windows_sys::Win32::Security::Isolation::CreateAppContainerProfile;
use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::Isolation::DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName;
use windows_sys::Win32::Security::LookupPrivilegeValueW;
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
use windows_sys::Win32::Security::TOKEN_ADJUST_DEFAULT;
use windows_sys::Win32::Security::TOKEN_ADJUST_PRIVILEGES;
use windows_sys::Win32::Security::TOKEN_ADJUST_SESSIONID;
use windows_sys::Win32::Security::TOKEN_ASSIGN_PRIMARY;
use windows_sys::Win32::Security::TOKEN_DUPLICATE;
use windows_sys::Win32::Security::TOKEN_PRIVILEGES;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Security::TokenGroups;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::SandboxError;

use super::util::{format_last_error, to_wide};

const DISABLE_MAX_PRIVILEGE: u32 = 0x01;
const LUA_TOKEN: u32 = 0x04;
const WRITE_RESTRICTED: u32 = 0x08;
const WIN_WORLD_SID: i32 = 1;
const SE_GROUP_LOGON_ID: u32 = 0xC0000000;

#[derive(Debug)]
pub(super) struct OwnedHandle(HANDLE);

impl OwnedHandle {
    pub(super) fn new(value: HANDLE) -> Result<Self, SandboxError> {
        if value.is_null() {
            return Err(SandboxError::Windows(
                "received null windows handle".to_string(),
            ));
        }
        Ok(Self(value))
    }

    pub(super) fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[derive(Debug)]
pub(super) struct OwnedSid {
    ptr: PSID,
}

impl OwnedSid {
    pub(super) fn from_string_sid(sid: &str) -> Result<Self, SandboxError> {
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut PSID) -> i32;
        }

        let mut out: PSID = std::ptr::null_mut();
        let wide = to_wide(sid);
        let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut out as *mut PSID) };
        if ok == 0 || out.is_null() {
            return Err(SandboxError::Windows(format!(
                "ConvertStringSidToSidW failed: {}",
                format_last_error(unsafe { GetLastError() } as i32)
            )));
        }
        Ok(Self { ptr: out })
    }

    pub(super) fn raw(&self) -> PSID {
        self.ptr
    }

    pub(super) fn from_raw(ptr: PSID) -> Result<Self, SandboxError> {
        if ptr.is_null() {
            return Err(SandboxError::Windows(
                "received null sid pointer".to_string(),
            ));
        }
        Ok(Self { ptr })
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                LocalFree(self.ptr as HLOCAL);
            }
        }
    }
}

pub(super) fn random_capability_sid() -> String {
    let a = rand::random::<u32>();
    let b = rand::random::<u32>();
    let c = rand::random::<u32>();
    let d = rand::random::<u32>();
    format!("S-1-5-21-{a}-{b}-{c}-{d}")
}

pub(super) struct AppContainerContext {
    sid: OwnedSid,
    profile_name: String,
    profile_created: bool,
}

impl AppContainerContext {
    pub(super) fn sid(&self) -> PSID {
        self.sid.raw()
    }
}

impl Drop for AppContainerContext {
    fn drop(&mut self) {
        if !self.profile_created {
            return;
        }

        let wide = to_wide(&self.profile_name);
        unsafe {
            let _ = DeleteAppContainerProfile(wide.as_ptr());
        }
    }
}

pub(super) fn create_appcontainer_context(
    use_lpac: bool,
) -> Result<AppContainerContext, SandboxError> {
    let profile_name = format!(
        "procwarden_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    );
    let wide_name = to_wide(&profile_name);

    let mut sid_ptr: PSID = std::ptr::null_mut();
    let create_hr = unsafe {
        CreateAppContainerProfile(
            wide_name.as_ptr(),
            wide_name.as_ptr(),
            wide_name.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid_ptr,
        )
    };

    let (base_sid, profile_created) = if create_hr >= 0 {
        (OwnedSid::from_raw(sid_ptr)?, true)
    } else {
        let mut derived_sid: PSID = std::ptr::null_mut();
        let derive_hr = unsafe {
            DeriveAppContainerSidFromAppContainerName(wide_name.as_ptr(), &mut derived_sid)
        };
        if derive_hr < 0 {
            return Err(SandboxError::Windows(format!(
                "CreateAppContainerProfile/DeriveAppContainerSidFromAppContainerName failed: 0x{create_hr:08x}/0x{derive_hr:08x}"
            )));
        }
        (OwnedSid::from_raw(derived_sid)?, false)
    };

    let sid = if use_lpac {
        let restricted_name = to_wide("lpac");
        let mut restricted_sid_ptr: PSID = std::ptr::null_mut();
        let restricted_hr = unsafe {
            DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName(
                base_sid.raw(),
                restricted_name.as_ptr(),
                &mut restricted_sid_ptr,
            )
        };
        if restricted_hr < 0 {
            return Err(SandboxError::Windows(format!(
                "DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedName failed: 0x{restricted_hr:08x}"
            )));
        }
        OwnedSid::from_raw(restricted_sid_ptr)?
    } else {
        base_sid
    };

    Ok(AppContainerContext {
        sid,
        profile_name,
        profile_created,
    })
}

pub(super) fn create_restricted_token_with_capability(
    capability_sid: PSID,
) -> Result<OwnedHandle, SandboxError> {
    let base_token = get_current_token_for_restriction()?;
    let mut logon_sid_bytes = get_logon_sid_bytes(base_token.raw())?;
    let mut everyone_sid = world_sid()?;

    let mut entries: [SID_AND_ATTRIBUTES; 3] = unsafe { std::mem::zeroed() };
    entries[0].Sid = capability_sid;
    entries[0].Attributes = 0;
    entries[1].Sid = logon_sid_bytes.as_mut_ptr() as *mut c_void;
    entries[1].Attributes = 0;
    entries[2].Sid = everyone_sid.as_mut_ptr() as *mut c_void;
    entries[2].Attributes = 0;

    let mut restricted: HANDLE = std::ptr::null_mut();
    let flags = DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED;
    let ok = unsafe {
        CreateRestrictedToken(
            base_token.raw(),
            flags,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            3,
            entries.as_mut_ptr(),
            &mut restricted,
        )
    };
    if ok == 0 {
        return Err(SandboxError::Windows(format!(
            "CreateRestrictedToken failed: {}",
            format_last_error(unsafe { GetLastError() } as i32)
        )));
    }

    enable_single_privilege(restricted, "SeChangeNotifyPrivilege")?;
    OwnedHandle::new(restricted)
}

fn world_sid() -> Result<Vec<u8>, SandboxError> {
    let mut size: u32 = 0;
    unsafe {
        CreateWellKnownSid(
            WIN_WORLD_SID,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        );
    }

    let mut out = vec![0_u8; size as usize];
    let ok = unsafe {
        CreateWellKnownSid(
            WIN_WORLD_SID,
            std::ptr::null_mut(),
            out.as_mut_ptr() as *mut c_void,
            &mut size,
        )
    };
    if ok == 0 {
        return Err(SandboxError::Windows(format!(
            "CreateWellKnownSid failed: {}",
            format_last_error(unsafe { GetLastError() } as i32)
        )));
    }
    Ok(out)
}

fn get_current_token_for_restriction() -> Result<OwnedHandle, SandboxError> {
    let desired = TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID
        | TOKEN_ADJUST_PRIVILEGES;
    let mut handle: HANDLE = std::ptr::null_mut();

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process_handle: HANDLE, desired_access: u32, token: *mut HANDLE)
        -> i32;
    }

    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), desired, &mut handle) };
    if ok == 0 {
        return Err(SandboxError::Windows(format!(
            "OpenProcessToken failed: {}",
            format_last_error(unsafe { GetLastError() } as i32)
        )));
    }
    OwnedHandle::new(handle)
}

fn get_logon_sid_bytes(token: HANDLE) -> Result<Vec<u8>, SandboxError> {
    unsafe fn scan_token_groups_for_logon(token: HANDLE) -> Option<Vec<u8>> {
        let mut needed: u32 = 0;
        GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return None;
        }

        let mut buffer = vec![0_u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenGroups,
            buffer.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        );
        if ok == 0 || needed < std::mem::size_of::<u32>() as u32 {
            return None;
        }

        let group_count = std::ptr::read_unaligned(buffer.as_ptr() as *const u32) as usize;
        let after_count = buffer.as_ptr().add(std::mem::size_of::<u32>()) as usize;
        let align = std::mem::align_of::<SID_AND_ATTRIBUTES>();
        let aligned = (after_count + (align - 1)) & !(align - 1);
        let groups_ptr = aligned as *const SID_AND_ATTRIBUTES;

        for index in 0..group_count {
            let entry: SID_AND_ATTRIBUTES = std::ptr::read_unaligned(groups_ptr.add(index));
            if (entry.Attributes & SE_GROUP_LOGON_ID) != SE_GROUP_LOGON_ID {
                continue;
            }

            let sid = entry.Sid;
            let sid_len = GetLengthSid(sid);
            if sid_len == 0 {
                return None;
            }
            let mut out = vec![0_u8; sid_len as usize];
            if CopySid(sid_len, out.as_mut_ptr() as *mut c_void, sid) == 0 {
                return None;
            }
            return Some(out);
        }

        None
    }

    if let Some(value) = unsafe { scan_token_groups_for_logon(token) } {
        return Ok(value);
    }

    Err(SandboxError::Windows(
        "logon SID not present on token".to_string(),
    ))
}

fn enable_single_privilege(token: HANDLE, name: &str) -> Result<(), SandboxError> {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let ok = unsafe { LookupPrivilegeValueW(std::ptr::null(), to_wide(name).as_ptr(), &mut luid) };
    if ok == 0 {
        return Err(SandboxError::Windows(format!(
            "LookupPrivilegeValueW failed: {}",
            format_last_error(unsafe { GetLastError() } as i32)
        )));
    }

    let mut privileges: TOKEN_PRIVILEGES = unsafe { std::mem::zeroed() };
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = 0x0000_0002;

    let ok = unsafe {
        AdjustTokenPrivileges(
            token,
            0,
            &privileges,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(SandboxError::Windows(format!(
            "AdjustTokenPrivileges failed: {}",
            format_last_error(unsafe { GetLastError() } as i32)
        )));
    }

    let last_error = unsafe { GetLastError() };
    if last_error != 0 {
        return Err(SandboxError::Windows(format!(
            "AdjustTokenPrivileges returned warning: {}",
            format_last_error(last_error as i32)
        )));
    }
    Ok(())
}
