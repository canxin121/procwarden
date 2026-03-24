use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::{
    EnforcementReport, EnforcementStrength, PathInterceptionStats, SandboxAccess,
    SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy,
};

use super::command_runner::{configure_piped_stdio, run_command_with_timeout};

const DEFAULT_MACOS_RUNNER_PATH: &str = "/usr/local/bin/procwarden-macos-runner";
const MACOS_RUNNER_ENV: &str = "PROCWARDEN_MACOS_RUNNER";

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    workspace_root: &Path,
) -> Result<SandboxExecOutput, SandboxError> {
    if policy.is_danger_full_access() {
        return execute_without_sandbox(request);
    }

    execute_with_virtualization_runner(request, policy, workspace_root)
}

fn execute_with_virtualization_runner(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    workspace_root: &Path,
) -> Result<SandboxExecOutput, SandboxError> {
    let runner_path = std::env::var(MACOS_RUNNER_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MACOS_RUNNER_PATH.to_string());

    let runner = Path::new(&runner_path);
    if !runner.is_file() {
        return Err(SandboxError::Unavailable(format!(
            "macOS virtualization runner not found at {}; set {} to the runner binary path",
            runner.display(),
            MACOS_RUNNER_ENV
        )));
    }

    let mut argv = vec![runner_path];
    argv.extend(build_runner_policy_args(policy, workspace_root));
    if let Some(timeout_ms) = request.timeout_ms {
        argv.push("--timeout-ms".to_string());
        argv.push(timeout_ms.to_string());
    }
    argv.push("--cwd".to_string());
    argv.push(request.cwd.to_string_lossy().to_string());
    argv.push("--".to_string());
    argv.extend(request.command.clone());

    execute_command(
        &argv,
        &request.cwd,
        &request.env,
        request.timeout_ms,
        EnforcementReport {
            backend: "macos-virtualization-runner".to_string(),
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
            effective_network_enforcement: if policy.has_full_network_access() {
                EnforcementStrength::None
            } else {
                EnforcementStrength::Strong
            },
            path_interception: PathInterceptionStats {
                allow_paths_checked: policy.path_permissions().len() as u32,
                deny_paths_checked: policy
                    .path_permissions()
                    .iter()
                    .filter(|permission| matches!(permission.access, SandboxAccess::NoAccess))
                    .count() as u32,
                dangerous_namespace_blocks: 0,
                unc_blocks: 0,
                reparse_blocks: 0,
                symlink_blocks: 0,
            },
            degraded_reason_codes: Vec::new(),
            degraded_reasons: Vec::new(),
        },
    )
}

fn build_runner_policy_args(policy: &SandboxPolicy, workspace_root: &Path) -> Vec<String> {
    let mut args = Vec::new();

    if policy.has_full_network_access() {
        args.push("--allow-network".to_string());
    } else {
        args.push("--deny-network".to_string());
    }

    match policy.global_access() {
        SandboxAccess::ReadWrite => args.push("--global-rw".to_string()),
        SandboxAccess::ReadOnly => args.push("--global-ro".to_string()),
        SandboxAccess::NoAccess => args.push("--global-none".to_string()),
    }

    for permission in policy.path_permissions() {
        match permission.access {
            SandboxAccess::NoAccess => {
                args.push("--deny-path".to_string());
                args.push(permission.path.to_string_lossy().to_string());
            }
            SandboxAccess::ReadOnly => {
                args.push("--ro-path".to_string());
                args.push(permission.path.to_string_lossy().to_string());
            }
            SandboxAccess::ReadWrite => {
                args.push("--rw-path".to_string());
                args.push(permission.path.to_string_lossy().to_string());
            }
        }
    }

    for writable in policy.writable_roots_with_workspace(workspace_root) {
        args.push("--rw-path".to_string());
        args.push(writable.root.to_string_lossy().to_string());
        for read_only in writable.read_only_subpaths {
            args.push("--deny-path".to_string());
            args.push(read_only.to_string_lossy().to_string());
        }
    }

    args
}

fn execute_without_sandbox(
    request: &SandboxCommandRequest,
) -> Result<SandboxExecOutput, SandboxError> {
    execute_command(
        &request.command,
        &request.cwd,
        &request.env,
        request.timeout_ms,
        EnforcementReport {
            backend: "danger-full-access".to_string(),
            requested_read_allowlist: false,
            requested_write_allowlist: false,
            effective_read_enforcement: EnforcementStrength::None,
            effective_write_enforcement: EnforcementStrength::None,
            read_allowlist_enforced: false,
            write_allowlist_enforced: false,
            network_restricted: false,
            effective_network_enforcement: EnforcementStrength::None,
            path_interception: PathInterceptionStats::default(),
            degraded_reason_codes: Vec::new(),
            degraded_reasons: Vec::new(),
        },
    )
}

fn execute_command(
    argv: &[String],
    cwd: &Path,
    env_map: &std::collections::HashMap<String, String>,
    timeout_ms: Option<u64>,
    enforcement: EnforcementReport,
) -> Result<SandboxExecOutput, SandboxError> {
    let start = Instant::now();
    let mut command = Command::new(&argv[0]);
    if argv.len() > 1 {
        command.args(&argv[1..]);
    }

    command.current_dir(cwd).env_clear().envs(env_map.clone());
    configure_piped_stdio(&mut command);

    run_command_with_timeout(&mut command, timeout_ms, start, enforcement)
}
