use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::{
    EnforcementReport, EnforcementStrength, PathInterceptionStats, SandboxCommandRequest,
    SandboxError, SandboxExecOutput, SandboxPolicy, cap_fs,
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
            path_interception: PathInterceptionStats {
                allow_paths_checked: acl_plan.allow_paths.len() as u32,
                deny_paths_checked: acl_plan.deny_paths.len() as u32,
                dangerous_namespace_blocks: 0,
                unc_blocks: 0,
                reparse_blocks: 0,
                symlink_blocks: 0,
            },
            degraded_reason_codes: Vec::new(),
            degraded_reasons: Vec::new(),
        },
    })
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
