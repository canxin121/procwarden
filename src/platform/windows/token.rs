#![allow(unsafe_op_in_unsafe_fn)]

use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Isolation::CreateAppContainerProfile;
use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::PSID;

use crate::SandboxError;

use super::util::to_wide;

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
            return Err(SandboxError::Windows(
                "ConvertStringSidToSidW failed".to_string(),
            ));
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

pub(super) fn create_appcontainer_context() -> Result<AppContainerContext, SandboxError> {
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

    let (sid, profile_created) = if create_hr >= 0 {
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

    Ok(AppContainerContext {
        sid,
        profile_name,
        profile_created,
    })
}
