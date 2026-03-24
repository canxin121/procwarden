use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::{SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy, cap_fs};

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

    if policy.enforce_world_writable_audit {
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
    })
}

struct AclPlan {
    allow_paths: Vec<PathBuf>,
    deny_paths: Vec<PathBuf>,
}

fn collect_acl_plan(
    policy: &SandboxPolicy,
    _workspace_root: &Path,
) -> Result<AclPlan, SandboxError> {
    if matches!(policy.global_access, crate::SandboxAccess::ReadWrite) {
        return Ok(AclPlan {
            allow_paths: Vec::new(),
            deny_paths: Vec::new(),
        });
    }

    let mut allow_paths = policy
        .path_permissions
        .iter()
        .filter(|permission| {
            matches!(
                permission.access,
                crate::SandboxAccess::ReadOnly | crate::SandboxAccess::ReadWrite
            )
        })
        .map(|permission| permission.path.clone())
        .collect::<Vec<_>>();
    allow_paths.extend(
        policy
            .path_permissions
            .iter()
            .filter(|permission| matches!(permission.access, crate::SandboxAccess::ReadWrite))
            .map(|permission| permission.path.clone()),
    );
    let deny_paths = policy
        .path_permissions
        .iter()
        .filter(|permission| matches!(permission.access, crate::SandboxAccess::NoAccess))
        .map(|permission| permission.path.clone())
        .collect::<Vec<_>>();

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
                reject_reparse_points: policy.reject_reparse_points,
                allow_unc_paths: policy.allow_unc_paths,
            },
        )
    })
}
