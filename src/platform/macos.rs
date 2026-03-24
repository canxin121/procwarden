use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::{SandboxAccess, SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy};

use super::command_runner::{configure_piped_stdio, run_command_with_timeout};

const DEFAULT_MACOS_RUNNER_PATH: &str = "/usr/local/bin/procwarden-macos-runner";
const MACOS_RUNNER_ENV: &str = "PROCWARDEN_MACOS_RUNNER";

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    workspace_root: &Path,
) -> Result<SandboxExecOutput, SandboxError> {
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

    execute_command(&argv, &request.cwd, &request.env, request.timeout_ms)
}

fn build_runner_policy_args(policy: &SandboxPolicy, _workspace_root: &Path) -> Vec<String> {
    let mut args = Vec::new();

    if policy.network_access {
        args.push("--allow-network".to_string());
    } else {
        args.push("--deny-network".to_string());
    }

    match policy.global_access {
        SandboxAccess::ReadWrite => args.push("--global-rw".to_string()),
        SandboxAccess::ReadOnly => args.push("--global-ro".to_string()),
        SandboxAccess::NoAccess => args.push("--global-none".to_string()),
    }

    for permission in &policy.path_permissions {
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

    for writable in policy.writable_paths() {
        args.push("--rw-path".to_string());
        args.push(writable.to_string_lossy().to_string());
    }

    for denied in policy.denied_paths() {
        args.push("--deny-path".to_string());
        args.push(denied.to_string_lossy().to_string());
    }

    args
}

fn execute_command(
    argv: &[String],
    cwd: &Path,
    env_map: &std::collections::HashMap<String, String>,
    timeout_ms: Option<u64>,
) -> Result<SandboxExecOutput, SandboxError> {
    let start = Instant::now();
    let mut command = Command::new(&argv[0]);
    if argv.len() > 1 {
        command.args(&argv[1..]);
    }

    command.current_dir(cwd).env_clear().envs(env_map.clone());
    configure_piped_stdio(&mut command);

    run_command_with_timeout(&mut command, timeout_ms, start)
}
