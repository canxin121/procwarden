use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::time::Instant;

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::NetworkManagement::WindowsFirewall::NetworkIsolationGetAppContainerConfig;
use windows_sys::Win32::Security::{EqualSid, PSID, SID_AND_ATTRIBUTES};

use crate::{
    DegradeReasonCode, EnforcementReport, EnforcementStrength, PathInterceptionStats,
    SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy, cap_fs,
};

use super::{acl, audit, process, token, util};

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    workspace_root: &Path,
    env_map: &HashMap<String, String>,
) -> Result<SandboxExecOutput, SandboxError> {
    let start = Instant::now();

    let acl_plan = collect_acl_plan(policy, workspace_root)?;
    let allow_paths = sanitize_allow_paths(policy, acl_plan.allow_paths)?;
    let deny_paths = sanitize_allow_paths(policy, acl_plan.deny_paths)?;

    if policy.enforce_world_writable_audit() {
        audit::audit_paths_for_world_writable(&allow_paths, env_map, &request.cwd)?;
    }

    let executable = process::resolve_executable(&request.command[0], &request.cwd, env_map)
        .ok_or_else(|| {
            SandboxError::InvalidRequest(format!(
                "unable to resolve executable '{}' from cwd {}",
                request.command[0],
                request.cwd.display()
            ))
        })?;

    let appcontainer = token::create_appcontainer_context()?;
    let sid = appcontainer.sid();

    let acl_plan = acl::AclAccessPlan {
        allow_paths,
        deny_paths,
    };
    let acl_rollback = unsafe { acl::apply_access_plan(&acl_plan, sid)? };

    let capture = process::run_process_in_appcontainer(
        sid,
        &executable,
        &request.command,
        &request.cwd,
        env_map,
        request.timeout_ms,
    )?;

    drop(acl_rollback);
    drop(appcontainer);

    let stdout = String::from_utf8_lossy(&capture.stdout).to_string();
    let stderr = String::from_utf8_lossy(&capture.stderr).to_string();
    let (network_strength, mut degraded_reason_codes, mut degraded_reasons) =
        assess_network_enforcement(policy, sid);

    Ok(SandboxExecOutput {
        exit_code: capture.exit_code,
        stdout: stdout.clone(),
        stderr: stderr.clone(),
        aggregated_output: format!("{stdout}{stderr}"),
        duration: start.elapsed(),
        timed_out: capture.timed_out,
        enforcement: EnforcementReport {
            backend: "windows-appcontainer".to_string(),
            requested_read_allowlist: policy.requested_read_enforcement(),
            requested_write_allowlist: policy.requested_write_enforcement(),
            effective_read_enforcement: if policy.requested_read_enforcement() {
                EnforcementStrength::Strong
            } else {
                EnforcementStrength::None
            },
            effective_write_enforcement: if policy.requested_write_enforcement() {
                EnforcementStrength::Strong
            } else {
                EnforcementStrength::None
            },
            read_allowlist_enforced: policy.requested_read_enforcement(),
            write_allowlist_enforced: policy.requested_write_enforcement(),
            network_restricted: !policy.has_full_network_access(),
            effective_network_enforcement: network_strength,
            path_interception: PathInterceptionStats {
                allow_paths_checked: acl_plan.allow_paths.len() as u32,
                deny_paths_checked: acl_plan.deny_paths.len() as u32,
                dangerous_namespace_blocks: 0,
                unc_blocks: 0,
                reparse_blocks: 0,
                symlink_blocks: 0,
            },
            degraded_reason_codes: {
                degraded_reason_codes.shrink_to_fit();
                degraded_reason_codes
            },
            degraded_reasons: {
                degraded_reasons.shrink_to_fit();
                degraded_reasons
            },
        },
    })
}

fn assess_network_enforcement(
    policy: &SandboxPolicy,
    appcontainer_sid: PSID,
) -> (EnforcementStrength, Vec<DegradeReasonCode>, Vec<String>) {
    if policy.has_full_network_access() {
        return (EnforcementStrength::None, Vec::new(), Vec::new());
    }

    match is_loopback_exempt(appcontainer_sid) {
        Ok(true) => (
            EnforcementStrength::BestEffort,
            vec![DegradeReasonCode::WindowsLoopbackExemptionDetected],
            vec![
                "appcontainer sid is present in loopback exemption list; network block is not strictly strong"
                    .to_string(),
            ],
        ),
        Ok(false) => (EnforcementStrength::Strong, Vec::new(), Vec::new()),
        Err(err) => (
            EnforcementStrength::BestEffort,
            vec![DegradeReasonCode::WindowsLoopbackExemptionCheckFailed],
            vec![format!("failed to verify loopback exemptions: {err}")],
        ),
    }
}

fn is_loopback_exempt(appcontainer_sid: PSID) -> Result<bool, SandboxError> {
    let mut count: u32 = 0;
    let mut entries: *mut SID_AND_ATTRIBUTES = std::ptr::null_mut();
    let status = unsafe { NetworkIsolationGetAppContainerConfig(&mut count, &mut entries) };
    if status != 0 {
        return Err(SandboxError::Windows(format!(
            "NetworkIsolationGetAppContainerConfig failed: {}",
            status
        )));
    }

    let mut exempt = false;
    if !entries.is_null() {
        let list = unsafe { std::slice::from_raw_parts(entries, count as usize) };
        exempt = list.iter().any(|entry| unsafe {
            !entry.Sid.is_null() && EqualSid(entry.Sid, appcontainer_sid) != 0
        });

        unsafe {
            LocalFree(entries as *mut c_void as HLOCAL);
        }
    }

    Ok(exempt)
}

struct AclPlan {
    allow_paths: Vec<PathBuf>,
    deny_paths: Vec<PathBuf>,
}

fn collect_acl_plan(
    policy: &SandboxPolicy,
    workspace_root: &Path,
) -> Result<AclPlan, SandboxError> {
    if policy.has_full_disk_write_access() {
        return Ok(AclPlan {
            allow_paths: Vec::new(),
            deny_paths: Vec::new(),
        });
    }

    let writable_roots = policy.writable_roots_with_workspace(workspace_root);
    let readable_roots = policy.readable_roots_with_workspace(workspace_root);

    let mut allow_paths = readable_roots;
    let mut deny_paths = Vec::new();
    for writable_root in writable_roots {
        allow_paths.push(writable_root.root);
        deny_paths.extend(writable_root.read_only_subpaths);
    }

    Ok(AclPlan {
        allow_paths,
        deny_paths,
    })
}

fn sanitize_allow_paths(
    policy: &SandboxPolicy,
    allow_paths: Vec<PathBuf>,
) -> Result<Vec<PathBuf>, SandboxError> {
    cap_fs::PathPolicy::ascii_case_insensitive().validate_and_dedupe(allow_paths, |path| {
        util::ensure_safe_allow_path(
            path,
            util::PathSafetyOptions {
                reject_reparse_points: policy.reject_reparse_points(),
                allow_unc_paths: policy.allow_unc_paths(),
            },
        )
    })
}
