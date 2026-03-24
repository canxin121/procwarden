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

    let acl_plan = collect_acl_plan(policy, workspace_root);
    let allow_paths = sanitize_policy_paths(policy, acl_plan.allow_paths)?;
    let deny_paths = sanitize_policy_paths(policy, acl_plan.deny_paths)?;

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

    Ok(SandboxExecOutput::from_utf8_lossy(
        capture.exit_code,
        &capture.stdout,
        &capture.stderr,
        start.elapsed(),
        capture.timed_out,
    ))
}

struct AclPlan {
    allow_paths: Vec<PathBuf>,
    deny_paths: Vec<PathBuf>,
}

fn collect_acl_plan(policy: &SandboxPolicy, _workspace_root: &Path) -> AclPlan {
    if policy.full_disk_write_access() {
        return AclPlan {
            allow_paths: Vec::new(),
            deny_paths: Vec::new(),
        };
    }

    let allow_paths = policy.readable_paths();
    let deny_paths = policy.denied_paths();

    AclPlan {
        allow_paths,
        deny_paths,
    }
}

fn sanitize_policy_paths(
    policy: &SandboxPolicy,
    paths: Vec<PathBuf>,
) -> Result<Vec<PathBuf>, SandboxError> {
    cap_fs::PathPolicy::ascii_case_insensitive().validate_and_dedupe(paths, |path| {
        util::ensure_safe_allow_path(
            path,
            util::PathSafetyOptions {
                reject_reparse_points: policy.reject_reparse_points,
                allow_unc_paths: policy.allow_unc_paths,
            },
        )
    })
}
