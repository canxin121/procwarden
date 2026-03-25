use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};

use procwarden::{
    SandboxAccess, SandboxCommandRequest, SandboxError, SandboxExecOutput, SandboxManager,
    SandboxPolicy,
};

#[derive(Clone, Copy)]
enum RuntimeKind {
    Python,
    Node,
}

impl RuntimeKind {
    fn name(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Node => "node",
        }
    }

    fn candidates(self) -> Vec<Vec<&'static str>> {
        match self {
            Self::Python => vec![vec!["python3"], vec!["python"], vec!["py", "-3"]],
            Self::Node => vec![vec!["node"]],
        }
    }

    fn probe_args(self) -> Vec<&'static str> {
        match self {
            Self::Python => vec!["-c", "import sys; sys.exit(0)"],
            Self::Node => vec!["-e", "process.exit(0)"],
        }
    }

    fn output_contract_args(self) -> Vec<String> {
        match self {
            Self::Python => vec![
                "-c".to_string(),
                "import sys; sys.stdout.write('out'); sys.stderr.write('err'); raise SystemExit(7)"
                    .to_string(),
            ],
            Self::Node => vec![
                "-e".to_string(),
                "process.stdout.write('out'); process.stderr.write('err'); process.exit(7)"
                    .to_string(),
            ],
        }
    }

    fn timeout_contract_args(self) -> Vec<String> {
        match self {
            Self::Python => vec!["-c".to_string(), "import time; time.sleep(2)".to_string()],
            Self::Node => vec![
                "-e".to_string(),
                "setTimeout(() => process.exit(0), 2000)".to_string(),
            ],
        }
    }
}

#[test]
fn cross_platform_output_contract_for_python_and_node() {
    for kind in [RuntimeKind::Python, RuntimeKind::Node] {
        let Some(launcher) = resolve_launcher(kind.candidates(), kind.probe_args()) else {
            eprintln!(
                "skipping {} output contract: runtime unavailable",
                kind.name()
            );
            continue;
        };

        let manager = SandboxManager::new();
        let request = sandbox_request(
            append_command(&launcher, kind.output_contract_args()),
            std::env::current_dir().expect("cwd should resolve"),
            Some(10_000),
        );

        let policy = SandboxPolicy {
            path_permissions: Vec::new(),
            default_access: SandboxAccess::ReadWrite,
            network_access: true,
        };

        match manager.execute(&request, &policy) {
            Ok(output) if is_skippable_runtime_baseline_failure(kind, &output) => {
                eprintln!(
                    "skipping {} output contract due to runtime limitation: {}",
                    kind.name(),
                    output.stderr
                );
            }
            Ok(output) => {
                assert_eq!(
                    output.exit_code,
                    7,
                    "{} output contract exit mismatch, stdout: {}, stderr: {}",
                    kind.name(),
                    output.stdout,
                    output.stderr
                );
                assert!(
                    output.stdout.contains("out"),
                    "{} stdout missing marker",
                    kind.name()
                );
                assert!(
                    output.stderr.contains("err"),
                    "{} stderr missing marker",
                    kind.name()
                );
                assert!(
                    output.aggregated_output.contains("out")
                        && output.aggregated_output.contains("err"),
                    "{} aggregated output missing markers",
                    kind.name()
                );
            }
            Err(error) if is_skippable_environment_error(&error) => {
                eprintln!(
                    "skipping {} output contract due to environment limitation: {error:?}",
                    kind.name()
                );
            }
            Err(error) => panic!(
                "unexpected {} output contract manager error: {error:?}",
                kind.name()
            ),
        }
    }
}

#[test]
fn cross_platform_timeout_contract_for_python_and_node() {
    for kind in [RuntimeKind::Python, RuntimeKind::Node] {
        let Some(launcher) = resolve_launcher(kind.candidates(), kind.probe_args()) else {
            eprintln!(
                "skipping {} timeout contract: runtime unavailable",
                kind.name()
            );
            continue;
        };

        let manager = SandboxManager::new();
        let request = sandbox_request(
            append_command(&launcher, kind.timeout_contract_args()),
            std::env::current_dir().expect("cwd should resolve"),
            Some(50),
        );

        let policy = SandboxPolicy {
            path_permissions: Vec::new(),
            default_access: SandboxAccess::ReadWrite,
            network_access: true,
        };

        match manager.execute(&request, &policy) {
            Ok(output) if is_skippable_runtime_baseline_failure(kind, &output) => {
                eprintln!(
                    "skipping {} timeout contract due to runtime limitation: {}",
                    kind.name(),
                    output.stderr
                );
            }
            Ok(output) => {
                assert_eq!(
                    output.exit_code,
                    124,
                    "{} timeout contract should use timeout exit code",
                    kind.name()
                );
                assert!(
                    output.timed_out,
                    "{} timeout contract timed_out=false",
                    kind.name()
                );
            }
            Err(error) if is_skippable_environment_error(&error) => {
                eprintln!(
                    "skipping {} timeout contract due to environment limitation: {error:?}",
                    kind.name()
                );
            }
            Err(error) => panic!(
                "unexpected {} timeout contract manager error: {error:?}",
                kind.name()
            ),
        }
    }
}

#[test]
fn cross_platform_env_sanitization_contract() {
    let Some(python) = resolve_launcher(
        RuntimeKind::Python.candidates(),
        RuntimeKind::Python.probe_args(),
    ) else {
        eprintln!("skipping env sanitization contract: python runtime unavailable");
        return;
    };

    let mut env = sandbox_env();
    env.insert("LD_PRELOAD".to_string(), "evil.so".to_string());
    env.insert("LD_LIBRARY_PATH".to_string(), "/tmp/evil".to_string());
    env.insert(
        "DYLD_INSERT_LIBRARIES".to_string(),
        "evil.dylib".to_string(),
    );
    env.insert("BASH_ENV".to_string(), "/tmp/evil-rc".to_string());
    env.insert("ENV".to_string(), "evil-env".to_string());
    env.insert("SAFE_KEY".to_string(), "safe-value".to_string());

    let command = append_command(
        &python,
        vec![
            "-c".to_string(),
            "import os,sys; blocked=['LD_PRELOAD','LD_LIBRARY_PATH','DYLD_INSERT_LIBRARIES','BASH_ENV','ENV'];\nif any(os.environ.get(k) for k in blocked): sys.exit(1);\nif os.environ.get('SAFE_KEY')!='safe-value': sys.exit(2);\nsys.exit(0)"
                .to_string(),
        ],
    );

    let request = SandboxCommandRequest {
        command,
        cwd: std::env::current_dir().expect("cwd should resolve"),
        env,
        timeout_ms: Some(5_000),
    };
    let policy = SandboxPolicy {
        path_permissions: Vec::new(),
        default_access: SandboxAccess::ReadWrite,
        network_access: true,
    };

    let manager = SandboxManager::new();
    match manager.execute(&request, &policy) {
        Ok(output) => {
            assert_eq!(
                output.exit_code, 0,
                "blocked env vars should be removed while safe vars are preserved"
            );
        }
        Err(error) if is_skippable_environment_error(&error) => {
            eprintln!(
                "skipping env sanitization contract due to environment limitation: {error:?}"
            );
        }
        Err(error) => panic!("unexpected env sanitization manager error: {error:?}"),
    }
}

fn append_command(prefix: &[String], extra: Vec<String>) -> Vec<String> {
    let mut command = prefix.to_vec();
    command.extend(extra);
    command
}

fn resolve_launcher(candidates: Vec<Vec<&str>>, probe_args: Vec<&str>) -> Option<Vec<String>> {
    for candidate in candidates {
        if candidate.is_empty() {
            continue;
        }

        let mut command = Command::new(candidate[0]);
        if candidate.len() > 1 {
            command.args(&candidate[1..]);
        }
        command
            .args(&probe_args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if command.status().is_ok_and(|status| status.success()) {
            return Some(candidate.into_iter().map(str::to_string).collect());
        }
    }

    None
}

fn sandbox_request(
    command: Vec<String>,
    cwd: impl AsRef<Path>,
    timeout_ms: Option<u64>,
) -> SandboxCommandRequest {
    SandboxCommandRequest {
        command,
        cwd: cwd.as_ref().to_path_buf(),
        env: sandbox_env(),
        timeout_ms,
    }
}

fn sandbox_env() -> HashMap<String, String> {
    let mut env = HashMap::new();
    for key in [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "WINDIR",
        "HOME",
        "USERPROFILE",
        "TMP",
        "TEMP",
        "TMPDIR",
    ] {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    env
}

fn is_skippable_environment_error(error: &SandboxError) -> bool {
    match error {
        SandboxError::Unavailable(_) => true,
        SandboxError::Windows(message) => {
            message.contains("UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)")
        }
        _ => false,
    }
}

fn is_skippable_runtime_baseline_failure(kind: RuntimeKind, output: &SandboxExecOutput) -> bool {
    matches!(kind, RuntimeKind::Node)
        && output
            .stderr
            .contains("snap-confine has elevated permissions")
}
