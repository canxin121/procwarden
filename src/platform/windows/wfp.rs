#![allow(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::path::Path;

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_SID, FWP_VALUE0, FWPM_ACTION0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_PACKAGE_ID, FWPM_FILTER_CONDITION0, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER_UNIVERSAL, FwpmEngineClose0,
    FwpmEngineOpen0, FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::Security::SID;

use crate::SandboxError;

use super::util::{format_last_error, to_wide};

const BLOCK_LAYERS: [windows_sys::core::GUID; 6] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
    FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
];

pub(super) struct NetworkFilterGuard {
    engine: HANDLE,
    _app_id: AppIdBlob,
}

impl Drop for NetworkFilterGuard {
    fn drop(&mut self) {
        if !self.engine.is_null() {
            unsafe {
                let _ = FwpmEngineClose0(self.engine);
            }
            self.engine = std::ptr::null_mut();
        }
    }
}

pub(super) fn install_block_all_network_filters(
    executable: &Path,
    appcontainer_sid: *mut c_void,
) -> Result<NetworkFilterGuard, SandboxError> {
    let app_id = AppIdBlob::from_executable(executable)?;
    let engine = open_dynamic_engine()?;

    if let Err(error) = unsafe { install_filters(engine, app_id.ptr(), appcontainer_sid) } {
        unsafe {
            let _ = FwpmEngineClose0(engine);
        }
        return Err(error);
    }

    Ok(NetworkFilterGuard {
        engine,
        _app_id: app_id,
    })
}

unsafe fn install_filters(
    engine: HANDLE,
    app_id: *mut FWP_BYTE_BLOB,
    appcontainer_sid: *mut c_void,
) -> Result<(), SandboxError> {
    let begin_status = FwpmTransactionBegin0(engine, 0);
    if begin_status != 0 {
        return Err(wfp_error("FwpmTransactionBegin0", begin_status));
    }

    for (index, layer) in BLOCK_LAYERS.into_iter().enumerate() {
        if let Err(error) = add_block_filter(engine, layer, app_id, appcontainer_sid, index) {
            let _ = FwpmTransactionAbort0(engine);
            return Err(error);
        }
    }

    let commit_status = FwpmTransactionCommit0(engine);
    if commit_status != 0 {
        let _ = FwpmTransactionAbort0(engine);
        return Err(wfp_error("FwpmTransactionCommit0", commit_status));
    }

    Ok(())
}

unsafe fn add_block_filter(
    engine: HANDLE,
    layer_key: windows_sys::core::GUID,
    app_id: *mut FWP_BYTE_BLOB,
    appcontainer_sid: *mut c_void,
    index: usize,
) -> Result<(), SandboxError> {
    let mut conditions = [
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
            },
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_SID,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    sid: appcontainer_sid as *mut SID,
                },
            },
        },
    ];

    let mut filter = FWPM_FILTER0 {
        layerKey: layer_key,
        subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            ..FWPM_ACTION0::default()
        },
        weight: FWP_VALUE0 {
            r#type: FWP_EMPTY,
            ..FWP_VALUE0::default()
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        ..FWPM_FILTER0::default()
    };

    let filter_name = format!("procwarden-network-block-{index}");
    let mut filter_name_wide = to_wide(filter_name);
    filter.displayData.name = filter_name_wide.as_mut_ptr();

    let status = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), std::ptr::null_mut());
    if status != 0 {
        return Err(wfp_error("FwpmFilterAdd0", status));
    }

    Ok(())
}

fn open_dynamic_engine() -> Result<HANDLE, SandboxError> {
    let session = FWPM_SESSION0 {
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        ..FWPM_SESSION0::default()
    };

    let mut engine: HANDLE = std::ptr::null_mut();
    let status =
        unsafe { FwpmEngineOpen0(std::ptr::null(), 0, std::ptr::null(), &session, &mut engine) };
    if status != 0 {
        return Err(wfp_error("FwpmEngineOpen0", status));
    }
    if engine.is_null() {
        return Err(SandboxError::Windows(
            "FwpmEngineOpen0 returned a null engine handle".to_string(),
        ));
    }

    Ok(engine)
}

fn wfp_error(context: &str, status: u32) -> SandboxError {
    let detail = format_last_error(status as i32);
    if status == ERROR_ACCESS_DENIED {
        SandboxError::Denied(format!(
            "{context} failed with access denied ({}): requires privileges to install temporary WFP filters",
            detail
        ))
    } else {
        SandboxError::Windows(format!("{context} failed: {status} ({detail})"))
    }
}

struct AppIdBlob {
    ptr: *mut FWP_BYTE_BLOB,
}

impl AppIdBlob {
    fn from_executable(executable: &Path) -> Result<Self, SandboxError> {
        let wide_executable = to_wide(executable);
        let mut ptr: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let status = unsafe { FwpmGetAppIdFromFileName0(wide_executable.as_ptr(), &mut ptr) };
        if status != 0 {
            return Err(wfp_error("FwpmGetAppIdFromFileName0", status));
        }
        if ptr.is_null() {
            return Err(SandboxError::Windows(
                "FwpmGetAppIdFromFileName0 returned null app id blob".to_string(),
            ));
        }

        Ok(Self { ptr })
    }

    fn ptr(&self) -> *mut FWP_BYTE_BLOB {
        self.ptr
    }
}

impl Drop for AppIdBlob {
    fn drop(&mut self) {
        if self.ptr.is_null() {
            return;
        }

        unsafe {
            let mut pointer = self.ptr as *mut c_void;
            FwpmFreeMemory0(&mut pointer);
        }
        self.ptr = std::ptr::null_mut();
    }
}

#[cfg(test)]
mod tests {
    use super::BLOCK_LAYERS;

    #[test]
    fn block_layer_list_covers_connect_accept_and_resource_assignment() {
        assert_eq!(
            BLOCK_LAYERS.len(),
            6,
            "expected IPv4/IPv6 layers for connect, recv_accept, and resource_assignment"
        );
    }
}
