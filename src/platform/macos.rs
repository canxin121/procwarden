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

    match policy.default_access {
        SandboxAccess::ReadWrite => {
            for read_only in dedupe_paths(policy.read_only_paths()) {
                push_path_rule(&mut lines, "deny", "file-write*", &read_only);
            }
            for denied in dedupe_paths(policy.denied_paths()) {
                push_path_rule(&mut lines, "deny", "file-read*", &denied);
                push_path_rule(&mut lines, "deny", "file-write*", &denied);
            }
        }
        SandboxAccess::ReadOnly => {
            lines.push("(deny file-write*)".to_string());
            for writable in dedupe_paths(policy.read_write_paths()) {
                push_path_rule(&mut lines, "allow", "file-write*", &writable);
            }
            for denied in dedupe_paths(policy.denied_paths()) {
                push_path_rule(&mut lines, "deny", "file-read*", &denied);
                push_path_rule(&mut lines, "deny", "file-write*", &denied);
            }
        }
        SandboxAccess::NoAccess => {
            lines.push("(deny file-read*)".to_string());
            lines.push("(deny file-write*)".to_string());
            for readable in dedupe_paths(policy.readable_paths()) {
                push_path_rule(&mut lines, "allow", "file-read*", &readable);
            }
            for writable in dedupe_paths(policy.read_write_paths()) {
                push_path_rule(&mut lines, "allow", "file-write*", &writable);
            }
            for denied in dedupe_paths(policy.denied_paths()) {
                push_path_rule(&mut lines, "deny", "file-read*", &denied);
                push_path_rule(&mut lines, "deny", "file-write*", &denied);
            }
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
    use std::path::PathBuf;

    use crate::{SandboxAccess, SandboxPathPermission, SandboxPolicy};

    use super::build_sbpl_profile;

    #[test]
    fn read_only_profile_denies_writes_before_write_carveouts() {
        let writable = PathBuf::from("/private/tmp/procwarden/rw");
        let denied = PathBuf::from("/private/tmp/procwarden/deny");
        let profile = build_sbpl_profile(&SandboxPolicy {
            default_access: SandboxAccess::ReadOnly,
            network_access: false,
            path_permissions: vec![
                SandboxPathPermission::read_write(writable.clone()),
                SandboxPathPermission::deny(denied.clone()),
            ],
        });

        assert_line_before(
            &profile,
            "(deny file-write*)",
            &format!("(allow file-write* (literal \"{}\"))", writable.display()),
        );
        assert_line_before(
            &profile,
            &format!("(allow file-write* (subpath \"{}\"))", writable.display()),
            &format!("(deny file-read* (literal \"{}\"))", denied.display()),
        );
        assert!(
            profile.contains(&format!(
                "(deny file-write* (subpath \"{}\"))",
                denied.display()
            )),
            "read-only profile should emit deny override for denied write path"
        );
    }

    #[test]
    fn no_access_profile_denies_globally_before_allowlist_and_reapplies_explicit_denies() {
        let readable = PathBuf::from("/private/tmp/procwarden/ro");
        let writable = PathBuf::from("/private/tmp/procwarden/rw");
        let denied = PathBuf::from("/private/tmp/procwarden/deny");
        let profile = build_sbpl_profile(&SandboxPolicy {
            default_access: SandboxAccess::NoAccess,
            network_access: false,
            path_permissions: vec![
                SandboxPathPermission::read_only(readable.clone()),
                SandboxPathPermission::read_write(writable.clone()),
                SandboxPathPermission::deny(denied.clone()),
            ],
        });

        assert_line_before(
            &profile,
            "(deny file-read*)",
            &format!("(allow file-read* (literal \"{}\"))", readable.display()),
        );
        assert_line_before(
            &profile,
            "(deny file-write*)",
            &format!("(allow file-write* (literal \"{}\"))", writable.display()),
        );
        assert_line_before(
            &profile,
            &format!("(allow file-write* (subpath \"{}\"))", writable.display()),
            &format!("(deny file-read* (literal \"{}\"))", denied.display()),
        );
        assert!(
            profile.contains(&format!(
                "(deny file-write* (subpath \"{}\"))",
                denied.display()
            )),
            "no-access profile should reapply explicit deny after allowlist rules"
        );
    }

    #[test]
    fn read_write_profile_emits_subtractive_overlays_only() {
        let read_only = PathBuf::from("/private/tmp/procwarden/ro");
        let denied = PathBuf::from("/private/tmp/procwarden/deny");
        let profile = build_sbpl_profile(&SandboxPolicy {
            default_access: SandboxAccess::ReadWrite,
            network_access: false,
            path_permissions: vec![
                SandboxPathPermission::read_only(read_only.clone()),
                SandboxPathPermission::deny(denied.clone()),
            ],
        });

        assert!(
            profile.contains(&format!(
                "(deny file-write* (literal \"{}\"))",
                read_only.display()
            )),
            "read-write default should make read_only paths write-denied"
        );
        assert!(
            profile.contains(&format!(
                "(deny file-read* (literal \"{}\"))",
                denied.display()
            )),
            "read-write default should fully deny explicitly denied paths"
        );
        assert!(
            !profile.contains(&format!(
                "(allow file-write* (literal \"{}\"))",
                denied.display()
            )),
            "read-write default should not need allow carveouts"
        );
    }

    fn assert_line_before(profile: &str, earlier: &str, later: &str) {
        let earlier_index = profile
            .find(earlier)
            .unwrap_or_else(|| panic!("missing earlier line: {earlier}"));
        let later_index = profile
            .find(later)
            .unwrap_or_else(|| panic!("missing later line: {later}"));
        assert!(
            earlier_index < later_index,
            "expected `{earlier}` before `{later}` in profile:\n{profile}"
        );
    }
}
