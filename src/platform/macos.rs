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

    match policy.default_access {
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
