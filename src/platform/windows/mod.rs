mod acl;
mod appcontainer;
mod audit;
mod env;
mod process;
mod token;
mod util;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::{
    ChildProcessCoverage, DegradeReasonCode, EnforcementReport, EnforcementStrength, FailStrategy,
    PathInterceptionStats, SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy,
    WindowsEnforcementLevel, cap_fs,
};

use super::command_runner::{configure_piped_stdio, run_command_with_timeout};

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    workspace_root: &Path,
) -> Result<SandboxExecOutput, SandboxError> {
    if policy.is_danger_full_access() {
        return execute_without_sandbox(request);
    }

    let mut env_map = request.env.clone();
    util::normalize_null_device_env(&mut env_map);
    util::ensure_non_interactive_pager(&mut env_map);

    if !policy.has_full_network_access() {
        env::apply_no_network_hardening(&mut env_map)?;
    }

    let backend = select_backend(policy);
    if policy.requires_read_allowlist_enforcement()
        && matches!(backend, WindowsBackend::CompatAclTokenJob)
    {
        return match policy.fail_strategy() {
            FailStrategy::FailClosed => Err(SandboxError::Unavailable(
                "windows compat backend cannot enforce read allowlists; switch to appcontainer/lpac or fail-open strategy"
                    .to_string(),
            )),
            FailStrategy::FailOpenWithReport => execute_compat_acl_token_job(
                request,
                policy,
                workspace_root,
                &env_map,
            ),
        };
    }

    match backend {
        WindowsBackend::CompatAclTokenJob => {
            execute_compat_acl_token_job(request, policy, workspace_root, &env_map)
        }
        WindowsBackend::AppContainer => {
            appcontainer::execute(request, policy, workspace_root, &env_map, false)
        }
        WindowsBackend::Lpac => {
            appcontainer::execute(request, policy, workspace_root, &env_map, true)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsBackend {
    CompatAclTokenJob,
    AppContainer,
    Lpac,
}

fn select_backend(policy: &SandboxPolicy) -> WindowsBackend {
    match policy.windows_enforcement() {
        WindowsEnforcementLevel::CompatAclTokenJob => WindowsBackend::CompatAclTokenJob,
        WindowsEnforcementLevel::AppContainer => WindowsBackend::AppContainer,
        WindowsEnforcementLevel::Lpac => WindowsBackend::Lpac,
        WindowsEnforcementLevel::Auto => {
            if policy.requires_read_allowlist_enforcement() {
                WindowsBackend::AppContainer
            } else {
                WindowsBackend::CompatAclTokenJob
            }
        }
    }
}

fn execute_compat_acl_token_job(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    workspace_root: &Path,
    env_map: &std::collections::HashMap<String, String>,
) -> Result<SandboxExecOutput, SandboxError> {
    let start = Instant::now();

    let acl_plan = collect_acl_plan(policy, workspace_root)?;
    let allow_paths = sanitize_allow_paths(policy, acl_plan.allow_paths)?;
    let deny_paths = sanitize_allow_paths(policy, acl_plan.deny_paths)?;

    if policy.enforce_world_writable_audit() {
        audit::audit_paths_for_world_writable(&allow_paths, &env_map, &request.cwd)?;
    }

    let executable = process::resolve_executable(&request.command[0], &request.cwd, &env_map)
        .ok_or_else(|| {
            SandboxError::InvalidRequest(format!(
                "unable to resolve executable '{}' from cwd {}",
                request.command[0],
                request.cwd.display()
            ))
        })?;

    let capability_sid_string = token::random_capability_sid();
    let capability_sid = token::OwnedSid::from_string_sid(&capability_sid_string)?;
    let restricted_token = token::create_restricted_token_with_capability(capability_sid.raw())?;

    let acl_plan = acl::AclAccessPlan {
        allow_paths,
        deny_paths,
    };
    let acl_rollback = unsafe { acl::apply_access_plan(&acl_plan, capability_sid.raw())? };

    let capture = process::run_process_as_user(
        restricted_token.raw(),
        &executable,
        &request.command,
        &request.cwd,
        env_map,
        request.timeout_ms,
    )?;

    drop(acl_rollback);

    let stdout = String::from_utf8_lossy(&capture.stdout).to_string();
    let stderr = String::from_utf8_lossy(&capture.stderr).to_string();
    let mut degraded = Vec::new();
    let mut degraded_codes = Vec::new();
    if policy.requested_read_enforcement() {
        degraded.push("read-allowlist-not-strongly-enforced-on-compat-backend".to_string());
        degraded_codes.push(DegradeReasonCode::CompatReadAllowlistBestEffort);
    }
    if policy.allows_degraded_execution() && policy.requested_read_enforcement() {
        degraded_codes.push(DegradeReasonCode::FailOpenDegraded);
    }

    Ok(SandboxExecOutput {
        exit_code: capture.exit_code,
        stdout: stdout.clone(),
        stderr: stderr.clone(),
        aggregated_output: format!("{stdout}{stderr}"),
        duration: start.elapsed(),
        timed_out: capture.timed_out,
        enforcement: EnforcementReport {
            backend: "windows-compat-acl-token-job".to_string(),
            requested_read_allowlist: policy.requested_read_enforcement(),
            requested_write_allowlist: policy.requested_write_enforcement(),
            effective_read_enforcement: if policy.requested_read_enforcement() {
                EnforcementStrength::BestEffort
            } else {
                EnforcementStrength::None
            },
            effective_write_enforcement: if policy.requested_write_enforcement() {
                EnforcementStrength::Strong
            } else {
                EnforcementStrength::None
            },
            read_allowlist_enforced: false,
            write_allowlist_enforced: policy.requested_write_enforcement(),
            network_restricted: !policy.has_full_network_access(),
            child_process_coverage: ChildProcessCoverage::RestrictedAndJob,
            path_interception: PathInterceptionStats {
                allow_paths_checked: acl_plan.allow_paths.len() as u32,
                deny_paths_checked: acl_plan.deny_paths.len() as u32,
                dangerous_namespace_blocks: 0,
                unc_blocks: 0,
                reparse_blocks: 0,
                symlink_blocks: 0,
            },
            degraded_reason_codes: degraded_codes,
            degraded_reasons: degraded,
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
    if writable_roots.is_empty() && readable_roots.is_empty() {
        return Ok(AclPlan {
            allow_paths: Vec::new(),
            deny_paths: Vec::new(),
        });
    }

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

fn execute_without_sandbox(
    request: &SandboxCommandRequest,
) -> Result<SandboxExecOutput, SandboxError> {
    execute_without_sandbox_with_env(request, &request.env)
}

fn execute_without_sandbox_with_env(
    request: &SandboxCommandRequest,
    env_map: &std::collections::HashMap<String, String>,
) -> Result<SandboxExecOutput, SandboxError> {
    let start = Instant::now();

    let mut command = Command::new(&request.command[0]);
    if request.command.len() > 1 {
        command.args(&request.command[1..]);
    }

    command
        .current_dir(&request.cwd)
        .env_clear()
        .envs(env_map.clone());
    configure_piped_stdio(&mut command);

    let enforcement = EnforcementReport {
        backend: "windows-unsandboxed".to_string(),
        requested_read_allowlist: false,
        requested_write_allowlist: false,
        effective_read_enforcement: EnforcementStrength::None,
        effective_write_enforcement: EnforcementStrength::None,
        read_allowlist_enforced: false,
        write_allowlist_enforced: false,
        network_restricted: false,
        child_process_coverage: ChildProcessCoverage::None,
        path_interception: PathInterceptionStats::default(),
        degraded_reason_codes: Vec::new(),
        degraded_reasons: Vec::new(),
    };

    run_command_with_timeout(&mut command, request.timeout_ms, start, enforcement)
}

#[cfg(test)]
mod tests {
    use crate::{FailStrategy, SandboxPolicy, WindowsEnforcementLevel};

    use super::{WindowsBackend, select_backend};

    #[test]
    fn auto_backend_prefers_appcontainer_for_read_allowlist() {
        let policy = SandboxPolicy::new_custom_policy()
            .with_additional_readable_roots([std::path::PathBuf::from(r"C:\temp")])
            .with_windows_enforcement(WindowsEnforcementLevel::Auto);

        assert_eq!(select_backend(&policy), WindowsBackend::AppContainer);
    }

    #[test]
    fn explicit_compat_backend_is_honored() {
        let policy = SandboxPolicy::new_custom_policy()
            .with_windows_enforcement(WindowsEnforcementLevel::CompatAclTokenJob)
            .with_fail_strategy(FailStrategy::FailClosed);

        assert_eq!(select_backend(&policy), WindowsBackend::CompatAclTokenJob);
    }
}
