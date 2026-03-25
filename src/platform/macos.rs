use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::{SandboxAccess, SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxPolicy};

use super::command_runner::{configure_piped_stdio, run_command_with_timeout};

const DEFAULT_SANDBOX_EXEC_PATH: &str = "/usr/bin/sandbox-exec";
const MACOS_SANDBOX_EXEC_ENV: &str = "PROCWARDEN_MACOS_SANDBOX_EXEC";

pub(super) fn execute(
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
) -> Result<SandboxExecOutput, SandboxError> {
    let sandbox_exec_path = std::env::var(MACOS_SANDBOX_EXEC_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SANDBOX_EXEC_PATH.to_string());

    let sandbox_exec = Path::new(&sandbox_exec_path);
    if !sandbox_exec.is_file() {
        return Err(SandboxError::Unavailable(format!(
            "macOS sandbox executable not found at {}; set {} to override the path",
            sandbox_exec.display(),
            MACOS_SANDBOX_EXEC_ENV
        )));
    }

    let profile = build_sbpl_profile(policy);

    let mut argv = vec![
        sandbox_exec_path,
        "-p".to_string(),
        profile,
        "--".to_string(),
    ];
    argv.extend(request.command.clone());

    execute_command(&argv, &request.cwd, &request.env, request.timeout_ms)
}

fn build_sbpl_profile(policy: &SandboxPolicy) -> String {
    let mut lines = vec!["(version 1)".to_string(), "(allow default)".to_string()];

    if !policy.network_access {
        lines.push("(deny network*)".to_string());
    }

    for denied in dedupe_paths(policy.denied_paths()) {
        push_path_rule(&mut lines, "deny", "file-read*", &denied);
        push_path_rule(&mut lines, "deny", "file-write*", &denied);
    }

    match policy.global_access {
        SandboxAccess::ReadWrite => {
            for read_only in dedupe_paths(policy.read_only_paths()) {
                push_path_rule(&mut lines, "deny", "file-write*", &read_only);
            }
        }
        SandboxAccess::ReadOnly => {
            for writable in dedupe_paths(policy.read_write_paths()) {
                push_path_rule(&mut lines, "allow", "file-write*", &writable);
            }
            lines.push("(deny file-write*)".to_string());
        }
        SandboxAccess::NoAccess => {
            for readable in dedupe_paths(policy.readable_paths()) {
                push_path_rule(&mut lines, "allow", "file-read*", &readable);
            }
            for writable in dedupe_paths(policy.read_write_paths()) {
                push_path_rule(&mut lines, "allow", "file-write*", &writable);
            }
            lines.push("(deny file-read*)".to_string());
            lines.push("(deny file-write*)".to_string());
        }
    }

    lines.join("\n")
}

fn push_path_rule(lines: &mut Vec<String>, action: &str, operation: &str, path: &Path) {
    let path = quote_sbpl_string(path);
    lines.push(format!("({action} {operation} (literal {path}))"));
    lines.push(format!("({action} {operation} (subpath {path}))"));
}

fn quote_sbpl_string(path: &Path) -> String {
    let mut escaped = String::from("\"");
    for ch in path.to_string_lossy().chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();

    for path in paths {
        let key = path.to_string_lossy().to_string();
        if seen.insert(key) {
            deduped.push(path);
        }
    }

    deduped
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

    use super::{MACOS_SANDBOX_EXEC_ENV, build_sbpl_profile, execute};

    #[test]
    fn profile_contains_network_deny_when_disabled() {
        let profile = build_sbpl_profile(&SandboxPolicy {
            network_access: false,
            ..SandboxPolicy::default()
        });

        assert!(profile.contains("(deny network*)"));
    }

    #[test]
    fn profile_readonly_allows_rw_paths_before_global_write_deny() {
        let policy = SandboxPolicy {
            path_permissions: vec![SandboxPathPermission::read_write("/tmp/w")],
            global_access: SandboxAccess::ReadOnly,
            network_access: true,
        };
        let profile = build_sbpl_profile(&policy);

        let allow_pos = profile
            .find("(allow file-write* (subpath \"/tmp/w\"))")
            .expect("rw carve-out should be present");
        let deny_pos = profile
            .find("(deny file-write*)")
            .expect("global write deny should be present");

        assert!(
            allow_pos < deny_pos,
            "allow carve-out must appear before fallback deny"
        );
    }

    #[test]
    fn profile_noaccess_adds_read_write_fallback_denies() {
        let policy = SandboxPolicy {
            path_permissions: vec![
                SandboxPathPermission::read_only("/tmp/ro"),
                SandboxPathPermission::read_write("/tmp/rw"),
                SandboxPathPermission::deny("/tmp/no"),
            ],
            global_access: SandboxAccess::NoAccess,
            network_access: true,
        };
        let profile = build_sbpl_profile(&policy);

        assert!(profile.contains("(allow file-read* (subpath \"/tmp/ro\"))"));
        assert!(profile.contains("(allow file-write* (subpath \"/tmp/rw\"))"));
        assert!(profile.contains("(deny file-read*)"));
        assert!(profile.contains("(deny file-write*)"));
        assert!(profile.contains("(deny file-read* (subpath \"/tmp/no\"))"));
    }

    #[test]
    fn execute_fails_closed_when_sandbox_executable_is_missing() {
        let _guard = EnvVarGuard::set(
            MACOS_SANDBOX_EXEC_ENV,
            "/definitely/not/installed/sandbox-exec",
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
        assert!(message.contains(MACOS_SANDBOX_EXEC_ENV));
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
