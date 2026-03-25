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
    argv.extend(build_runner_policy_args(policy));
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

fn build_runner_policy_args(policy: &SandboxPolicy) -> Vec<String> {
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

    for read_only in policy.read_only_paths() {
        args.push("--ro-path".to_string());
        args.push(read_only.to_string_lossy().to_string());
    }

    for writable in policy.read_write_paths() {
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

#[cfg(test)]
mod tests {
    use crate::{
        SandboxAccess, SandboxCommandRequest, SandboxError, SandboxPathPermission, SandboxPolicy,
    };
    use std::collections::HashMap;

    use super::{MACOS_RUNNER_ENV, build_runner_policy_args, execute};

    #[test]
    fn policy_args_map_to_expected_flags_without_duplicates() {
        let policy = SandboxPolicy {
            path_permissions: vec![
                SandboxPathPermission::read_only("/tmp/ro"),
                SandboxPathPermission::read_write("/tmp/rw"),
                SandboxPathPermission::deny("/tmp/no"),
            ],
            global_access: SandboxAccess::NoAccess,
            network_access: false,
        };

        let args = build_runner_policy_args(&policy);

        assert!(args.contains(&"--deny-network".to_string()));
        assert!(args.contains(&"--global-none".to_string()));
        assert_eq!(args.iter().filter(|entry| *entry == "--ro-path").count(), 1);
        assert_eq!(args.iter().filter(|entry| *entry == "--rw-path").count(), 1);
        assert_eq!(
            args.iter().filter(|entry| *entry == "--deny-path").count(),
            1
        );
    }

    #[test]
    fn execute_fails_closed_when_runner_is_missing() {
        let _guard = EnvVarGuard::set(
            MACOS_RUNNER_ENV,
            "/definitely/not/installed/procwarden-runner",
        );
        let cwd = std::env::temp_dir();
        let request = SandboxCommandRequest {
            command: vec!["true".to_string()],
            cwd: cwd.clone(),
            env: HashMap::new(),
            timeout_ms: Some(100),
        };

        let result = execute(&request, &SandboxPolicy::default());
        let message = match result {
            Err(SandboxError::Unavailable(message)) => message,
            other => panic!("expected unavailable error, got {other:?}"),
        };
        assert!(message.contains(MACOS_RUNNER_ENV));
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                unsafe {
                    std::env::set_var(self.key, previous);
                }
            } else {
                unsafe {
                    std::env::remove_var(self.key);
                }
            }
        }
    }
}
