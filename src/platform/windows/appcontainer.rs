use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use crate::{SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy, cap_fs};

use super::{acl, process, token, util, wfp};

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    env_map: &HashMap<String, String>,
) -> Result<SandboxExecOutput, SandboxError> {
    let start = Instant::now();

    let acl_plan = collect_acl_plan(policy);
    let allow_paths = sanitize_policy_paths(acl_plan.allow_paths)?;
    let deny_paths = sanitize_policy_paths(acl_plan.deny_paths)?;

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

    let _network_guard = if policy.network_access {
        None
    } else {
        Some(wfp::install_block_all_network_filters(&executable, sid)?)
    };

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

fn collect_acl_plan(policy: &SandboxPolicy) -> AclPlan {
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

fn sanitize_policy_paths(paths: Vec<PathBuf>) -> Result<Vec<PathBuf>, SandboxError> {
    cap_fs::PathPolicy::ascii_case_insensitive()
        .validate_and_dedupe(paths, util::ensure_safe_allow_path)
}
