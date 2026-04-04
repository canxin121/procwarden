#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::NetworkManagement::WindowsFirewall::{
    NetworkIsolationGetAppContainerConfig, NetworkIsolationSetAppContainerConfig,
    NetworkIsolationSetupAppContainerBinaries,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::EqualSid;
use windows_sys::Win32::Security::Isolation::CreateAppContainerProfile;
use windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile;
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::PSID;
use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapFree};

use crate::{SandboxError, SandboxNetworkMode};

use super::util::{format_last_error, to_wide};

const GROUP_ATTRIBUTE_ENABLED: u32 = 0x0000_0004;

static LOOPBACK_CONFIG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

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
    loopback_exemption: Option<LoopbackExemptionGuard>,
}

impl AppContainerContext {
    pub(super) fn sid(&self) -> PSID {
        self.sid.raw()
    }

    pub(super) fn profile_name(&self) -> &str {
        &self.profile_name
    }

    pub(super) fn register_network_binary(
        &self,
        executable: &std::path::Path,
    ) -> Result<(), SandboxError> {
        let executable_parent = executable.parent().ok_or_else(|| {
            SandboxError::InvalidRequest(format!(
                "resolved executable has no parent directory: {}",
                executable.display()
            ))
        })?;

        let package_full_name = to_wide(&self.profile_name);
        let package_folder = to_wide(executable_parent);
        let display_name = to_wide(&self.profile_name);
        let binary = to_wide(executable);
        let binaries = [binary.as_ptr()];

        let hr = unsafe {
            NetworkIsolationSetupAppContainerBinaries(
                self.sid.raw(),
                package_full_name.as_ptr(),
                package_folder.as_ptr(),
                display_name.as_ptr(),
                1,
                binaries.as_ptr(),
                binaries.len() as u32,
            )
        };
        if hr < 0 {
            return Err(SandboxError::Windows(format!(
                "NetworkIsolationSetupAppContainerBinaries failed: 0x{hr:08x}"
            )));
        }

        Ok(())
    }
}

impl Drop for AppContainerContext {
    fn drop(&mut self) {
        self.loopback_exemption = None;

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
    network_mode: SandboxNetworkMode,
) -> Result<AppContainerContext, SandboxError> {
    let profile_name = format!(
        "procwarden_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    );
    let wide_name = to_wide(&profile_name);

    let (_capability_sids, capability_entries) = network_capabilities(network_mode)?;

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

    let mut appcontainer = AppContainerContext {
        sid,
        profile_name,
        profile_created,
        loopback_exemption: None,
    };

    if matches!(network_mode, SandboxNetworkMode::Bidirectional) {
        appcontainer.loopback_exemption =
            Some(LoopbackExemptionGuard::install(appcontainer.sid.raw())?);
    }

    Ok(appcontainer)
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
    network_mode: SandboxNetworkMode,
) -> Result<(Vec<OwnedCapabilitySid>, Vec<SID_AND_ATTRIBUTES>), SandboxError> {
    if !network_mode.allows_ip_network() {
        return Ok((Vec::new(), Vec::new()));
    }

    const NETWORK_CAPABILITY_SIDS: [&str; 3] = ["S-1-15-3-1", "S-1-15-3-2", "S-1-15-3-3"];

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

struct LoopbackExemptionGuard {
    sid: PSID,
    added: bool,
}

impl LoopbackExemptionGuard {
    fn install(sid: PSID) -> Result<Self, SandboxError> {
        let _lock = lock_loopback_config();
        let current = AppContainerConfig::get()?;
        if current.contains_sid(sid) {
            return Ok(Self { sid, added: false });
        }

        let mut updated = current.entries().to_vec();
        updated.push(SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: GROUP_ATTRIBUTE_ENABLED,
        });
        set_loopback_exemption_config(&updated)?;
        let refreshed = AppContainerConfig::get()?;
        if !refreshed.contains_sid(sid) {
            return Err(SandboxError::Windows(
                "NetworkIsolationSetAppContainerConfig did not retain the requested AppContainer SID"
                    .to_string(),
            ));
        }

        Ok(Self { sid, added: true })
    }

    fn restore(&mut self) {
        if !self.added {
            return;
        }

        let _lock = lock_loopback_config();
        let current = match AppContainerConfig::get() {
            Ok(config) => config,
            Err(_) => return,
        };

        let updated = current
            .entries()
            .iter()
            .copied()
            .filter(|entry| unsafe { EqualSid(entry.Sid, self.sid) == 0 })
            .collect::<Vec<_>>();

        if set_loopback_exemption_config(&updated).is_ok() {
            self.added = false;
        }
    }
}

impl Drop for LoopbackExemptionGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

struct AppContainerConfig {
    entries_ptr: *mut SID_AND_ATTRIBUTES,
    len: usize,
}

impl AppContainerConfig {
    fn get() -> Result<Self, SandboxError> {
        let mut count = 0_u32;
        let mut entries_ptr = std::ptr::null_mut();
        let status = unsafe { NetworkIsolationGetAppContainerConfig(&mut count, &mut entries_ptr) };
        if status != 0 {
            return Err(SandboxError::Windows(format!(
                "NetworkIsolationGetAppContainerConfig failed: {status} ({})",
                format_last_error(status as i32)
            )));
        }

        if count == 0 {
            return Ok(Self {
                entries_ptr: std::ptr::null_mut(),
                len: 0,
            });
        }

        if entries_ptr.is_null() {
            return Err(SandboxError::Windows(
                "NetworkIsolationGetAppContainerConfig returned null entries for a non-zero count"
                    .to_string(),
            ));
        }

        Ok(Self {
            entries_ptr,
            len: count as usize,
        })
    }

    fn entries(&self) -> &[SID_AND_ATTRIBUTES] {
        if self.len == 0 {
            return &[];
        }

        unsafe { std::slice::from_raw_parts(self.entries_ptr, self.len) }
    }

    fn contains_sid(&self, sid: PSID) -> bool {
        self.entries()
            .iter()
            .any(|entry| unsafe { EqualSid(entry.Sid, sid) != 0 })
    }
}

impl Drop for AppContainerConfig {
    fn drop(&mut self) {
        if self.entries_ptr.is_null() {
            return;
        }

        let heap = unsafe { GetProcessHeap() };
        if heap.is_null() {
            return;
        }

        for entry in self.entries() {
            if entry.Sid.is_null() {
                continue;
            }

            unsafe {
                let _ = HeapFree(heap, 0, entry.Sid);
            }
        }

        unsafe {
            let _ = HeapFree(heap, 0, self.entries_ptr as *mut c_void);
        }
    }
}

fn lock_loopback_config() -> std::sync::MutexGuard<'static, ()> {
    LOOPBACK_CONFIG_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn set_loopback_exemption_config(entries: &[SID_AND_ATTRIBUTES]) -> Result<(), SandboxError> {
    let status = unsafe {
        NetworkIsolationSetAppContainerConfig(
            entries.len() as u32,
            if entries.is_empty() {
                std::ptr::null_mut()
            } else {
                entries.as_ptr() as *mut SID_AND_ATTRIBUTES
            },
        )
    };
    if status != 0 {
        return Err(SandboxError::Windows(format!(
            "NetworkIsolationSetAppContainerConfig failed: {status} ({})",
            format_last_error(status as i32)
        )));
    }

    Ok(())
}

#[cfg(test)]
fn public_appcontainers_contain_sid(sid: PSID) -> Result<bool, SandboxError> {
    let mut count = 0_u32;
    let mut appcontainers_ptr: *mut windows_sys::Win32::NetworkManagement::WindowsFirewall::INET_FIREWALL_APP_CONTAINER =
        std::ptr::null_mut();
    let status = unsafe {
        windows_sys::Win32::NetworkManagement::WindowsFirewall::NetworkIsolationEnumAppContainers(
            0,
            &mut count,
            &mut appcontainers_ptr,
        )
    };
    if status != 0 {
        return Err(SandboxError::Windows(format!(
            "NetworkIsolationEnumAppContainers failed: {status} ({})",
            format_last_error(status as i32)
        )));
    }

    let found = if count == 0 || appcontainers_ptr.is_null() {
        false
    } else {
        let appcontainers =
            unsafe { std::slice::from_raw_parts(appcontainers_ptr, count as usize) };
        appcontainers
            .iter()
            .any(|appcontainer| unsafe { EqualSid(appcontainer.appContainerSid as PSID, sid) != 0 })
    };

    if !appcontainers_ptr.is_null() {
        unsafe {
            let _ = windows_sys::Win32::NetworkManagement::WindowsFirewall::NetworkIsolationFreeAppContainers(appcontainers_ptr);
        }
    }

    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::{create_appcontainer_context_with_network, public_appcontainers_contain_sid};

    #[cfg(target_os = "windows")]
    #[test]
    #[ignore = "diagnostic helper for Windows AppContainer loopback investigation"]
    fn debug_network_appcontainer_public_registration_state() {
        let appcontainer =
            create_appcontainer_context_with_network(true).expect("appcontainer should be created");

        let is_public = public_appcontainers_contain_sid(appcontainer.sid())
            .expect("public appcontainer enumeration should succeed");
        eprintln!("appcontainer_public={is_public}");
    }
}
