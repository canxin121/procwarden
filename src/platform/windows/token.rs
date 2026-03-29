#![allow(unsafe_op_in_unsafe_fn)]

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Isolation::CreateAppContainerProfile;
use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;

use crate::SandboxError;

use super::util::{format_last_error, to_wide};

#[derive(Debug)]
pub(super) struct OwnedSid {
    ptr: PSID,
}

impl OwnedSid {
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

pub(super) fn create_appcontainer_context_with_network(
    network_access: bool,
) -> Result<AppContainerContext, SandboxError> {
    let profile_name = format!(
        "procwarden_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    );
    let wide_name = to_wide(&profile_name);

    let (_capability_sids, capability_entries) = network_capabilities(network_access)?;

    let mut sid_ptr: PSID = std::ptr::null_mut();
    let create_hr = unsafe {
        CreateAppContainerProfile(
            wide_name.as_ptr(),
            wide_name.as_ptr(),
            wide_name.as_ptr(),
            if capability_entries.is_empty() {
                std::ptr::null()
            } else {
                capability_entries.as_ptr()
            },
            capability_entries.len() as u32,
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

struct OwnedCapabilitySid {
    ptr: PSID,
}

impl Drop for OwnedCapabilitySid {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                LocalFree(self.ptr as HLOCAL);
            }
        }
    }
}

fn network_capabilities(
    network_access: bool,
) -> Result<(Vec<OwnedCapabilitySid>, Vec<SID_AND_ATTRIBUTES>), SandboxError> {
    if !network_access {
        return Ok((Vec::new(), Vec::new()));
    }

    const NETWORK_CAPABILITY_SIDS: [&str; 3] = ["S-1-15-3-1", "S-1-15-3-2", "S-1-15-3-3"];
    const GROUP_ATTRIBUTE_ENABLED: u32 = 0x0000_0004;

    let mut capability_sids = Vec::with_capacity(NETWORK_CAPABILITY_SIDS.len());
    for sid in NETWORK_CAPABILITY_SIDS {
        let sid_wide = to_wide(sid);
        let mut sid_ptr: PSID = std::ptr::null_mut();
        let ok = unsafe { ConvertStringSidToSidW(sid_wide.as_ptr(), &mut sid_ptr) };
        if ok == 0 || sid_ptr.is_null() {
            let code = unsafe { GetLastError() as i32 };
            return Err(SandboxError::Windows(format!(
                "ConvertStringSidToSidW failed for network capability SID {sid}: {} ({})",
                code,
                format_last_error(code)
            )));
        }
        capability_sids.push(OwnedCapabilitySid { ptr: sid_ptr });
    }

    let capability_entries = capability_sids
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.ptr,
            Attributes: GROUP_ATTRIBUTE_ENABLED,
        })
        .collect::<Vec<_>>();

    Ok((capability_sids, capability_entries))
}
