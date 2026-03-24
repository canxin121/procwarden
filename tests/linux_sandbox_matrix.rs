#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use procwarden::{
    SandboxAccess, SandboxCommandRequest, SandboxManager, SandboxPathPermission, SandboxPolicy,
};

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("procwarden-linux-matrix-{prefix}-{nonce}"));
        fs::create_dir_all(&path).expect("temp directory should be created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone)]
struct WriteCase {
    name: &'static str,
    policy: SandboxPolicy,
    target: PathBuf,
    payload: &'static str,
    expect_success: bool,
}

#[test]
fn data_driven_write_policy_matrix_executes_expected_results() {
    let shell = linux_shell_path();
    let manager = SandboxManager::new();

    let workspace = TempDir::new("write-workspace");
    let outside = TempDir::new("write-outside");
    let weird_dir = workspace.path().join("dir with space-空格");
    fs::create_dir_all(&weird_dir).expect("weird directory should be created");

    let workspace_path = workspace.path().to_path_buf();
    let outside_path = outside.path().to_path_buf();

    let cases = vec![
        WriteCase {
            name: "global_rw_writes_workspace",
            policy: policy(SandboxAccess::ReadWrite, true, vec![]),
            target: workspace_path.join("rw.txt"),
            payload: "alpha",
            expect_success: true,
        },
        WriteCase {
            name: "global_ro_denies_workspace_write",
            policy: policy(SandboxAccess::ReadOnly, true, vec![]),
            target: workspace_path.join("ro-denied.txt"),
            payload: "blocked",
            expect_success: false,
        },
        WriteCase {
            name: "global_ro_plus_rw_permission_allows_workspace_write",
            policy: policy(
                SandboxAccess::ReadOnly,
                true,
                vec![SandboxPathPermission::read_write(workspace_path.clone())],
            ),
            target: workspace_path.join("ro-with-grant.txt"),
            payload: "granted",
            expect_success: true,
        },
        WriteCase {
            name: "global_ro_rw_permission_does_not_escape_to_outside",
            policy: policy(
                SandboxAccess::ReadOnly,
                true,
                vec![SandboxPathPermission::read_write(workspace_path.clone())],
            ),
            target: outside_path.join("outside-denied.txt"),
            payload: "escape",
            expect_success: false,
        },
        WriteCase {
            name: "global_rw_handles_space_and_unicode_paths",
            policy: policy(SandboxAccess::ReadWrite, true, vec![]),
            target: weird_dir.join("文件 name.txt"),
            payload: "utf8-ok",
            expect_success: true,
        },
    ];

    for case in cases {
        assert!(
            !case.target.exists(),
            "case {} should start with missing target",
            case.name
        );

        let request = SandboxCommandRequest {
            command: write_file_command(&shell, &case.target, case.payload),
            cwd: workspace_path.clone(),
            env: HashMap::new(),
            timeout_ms: Some(4_000),
        };

        let output = manager
            .execute(&request, &case.policy, workspace.path())
            .unwrap_or_else(|error| panic!("case {} execution failed: {error:?}", case.name));

        assert!(!output.timed_out, "case {} should not time out", case.name);
        if case.expect_success {
            assert_eq!(
                output.exit_code, 0,
                "case {} should succeed, stderr: {}",
                case.name, output.stderr
            );
            let content = fs::read_to_string(&case.target).unwrap_or_else(|error| {
                panic!(
                    "case {} should write file {}: {error}",
                    case.name,
                    case.target.display()
                )
            });
            assert_eq!(content, case.payload, "case {} content mismatch", case.name);
        } else {
            assert_ne!(
                output.exit_code, 0,
                "case {} should fail to write outside policy",
                case.name
            );
            assert!(
                !case.target.exists(),
                "case {} should not create denied file {}",
                case.name,
                case.target.display()
            );
        }
    }
}

#[test]
fn timeout_matrix_case_uses_standard_timeout_semantics() {
    let sleep_bin = linux_sleep_path();
    let manager = SandboxManager::new();
    let workspace = TempDir::new("timeout");

    let request = SandboxCommandRequest {
        command: vec![sleep_bin, "2".to_string()],
        cwd: workspace.path().to_path_buf(),
        env: HashMap::new(),
        timeout_ms: Some(80),
    };

    let output = manager
        .execute(
            &request,
            &policy(SandboxAccess::ReadWrite, true, vec![]),
            workspace.path(),
        )
        .expect("timeout case should return output");

    assert!(output.timed_out, "timeout case should be flagged");
    assert_eq!(
        output.exit_code, 124,
        "timeout exit code should be normalized"
    );
    assert!(
        output.duration >= Duration::from_millis(50),
        "duration should reflect waiting before timeout"
    );
}

#[test]
fn data_driven_env_sanitization_applies_during_real_execution() {
    let shell = linux_shell_path();
    let manager = SandboxManager::new();
    let workspace = TempDir::new("env-sanitize");

    let blocked_cases = [
        "LD_PRELOAD",
        "Ld_Library_Path",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "dyld_force_flat_namespace",
        "BASH_FUNC_custom",
        "ENV",
        "bash_env",
    ];

    for blocked in blocked_cases {
        let mut env = HashMap::new();
        env.insert(blocked.to_string(), "evil-value".to_string());
        env.insert("SAFE_VAR".to_string(), "safe-value".to_string());

        let script = format!("printf '%s|%s' \"${{{blocked}-unset}}\" \"${{SAFE_VAR-unset}}\"");
        let request = SandboxCommandRequest {
            command: vec![shell.clone(), "-c".to_string(), script],
            cwd: workspace.path().to_path_buf(),
            env,
            timeout_ms: Some(2_000),
        };

        let output = manager
            .execute(
                &request,
                &policy(SandboxAccess::ReadWrite, true, vec![]),
                workspace.path(),
            )
            .unwrap_or_else(|error| panic!("blocked key {blocked} execution failed: {error:?}"));

        assert_eq!(
            output.exit_code, 0,
            "blocked key {blocked} should still run"
        );
        let parts = output.stdout.split('|').collect::<Vec<_>>();
        assert_eq!(parts, vec!["unset", "safe-value"], "blocked key {blocked}");
    }
}

#[test]
fn network_enabled_can_connect_loopback_via_bash_dev_tcp() {
    let Some(bash) = linux_bash_path() else {
        return;
    };
    if !bash_dev_tcp_supported(&bash) {
        return;
    }

    let manager = SandboxManager::new();
    let workspace = TempDir::new("network-allow");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener should bind");
    let port = listener
        .local_addr()
        .expect("listener addr should resolve")
        .port();
    let accepted_rx = spawn_accept_probe(listener, Duration::from_secs(2));

    let request = SandboxCommandRequest {
        command: vec![
            bash,
            "-lc".to_string(),
            format!("exec 3<>/dev/tcp/127.0.0.1/{port}"),
        ],
        cwd: workspace.path().to_path_buf(),
        env: HashMap::new(),
        timeout_ms: Some(2_000),
    };

    let output = manager
        .execute(
            &request,
            &policy(SandboxAccess::ReadWrite, true, vec![]),
            workspace.path(),
        )
        .expect("network-allow execution should return output");

    let accepted = accepted_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or(false);
    assert_eq!(output.exit_code, 0, "loopback connect should succeed");
    assert!(
        accepted,
        "listener should observe a connection when network is allowed"
    );
}

#[test]
fn network_disabled_blocks_loopback_connect_via_bash_dev_tcp() {
    let Some(bash) = linux_bash_path() else {
        return;
    };
    if !bash_dev_tcp_supported(&bash) {
        return;
    }

    let manager = SandboxManager::new();
    let workspace = TempDir::new("network-deny");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener should bind");
    let port = listener
        .local_addr()
        .expect("listener addr should resolve")
        .port();
    let accepted_rx = spawn_accept_probe(listener, Duration::from_secs(2));

    let request = SandboxCommandRequest {
        command: vec![
            bash,
            "-lc".to_string(),
            format!("exec 3<>/dev/tcp/127.0.0.1/{port}"),
        ],
        cwd: workspace.path().to_path_buf(),
        env: HashMap::new(),
        timeout_ms: Some(2_000),
    };

    let output = manager
        .execute(
            &request,
            &policy(SandboxAccess::ReadWrite, false, vec![]),
            workspace.path(),
        )
        .expect("network-deny execution should return output");

    let accepted = accepted_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or(false);
    assert_ne!(output.exit_code, 0, "loopback connect should be blocked");
    assert!(
        !accepted,
        "listener should not receive connection when network is denied"
    );
}

fn policy(
    global_access: SandboxAccess,
    network_access: bool,
    path_permissions: Vec<SandboxPathPermission>,
) -> SandboxPolicy {
    SandboxPolicy {
        path_permissions,
        global_access,
        network_access,
        enforce_world_writable_audit: false,
        reject_reparse_points: true,
        allow_unc_paths: false,
    }
}

fn write_file_command(shell: &str, target: &Path, payload: &str) -> Vec<String> {
    vec![
        shell.to_string(),
        "-c".to_string(),
        "printf '%s' \"$2\" > \"$1\"".to_string(),
        "procwarden-write".to_string(),
        target.to_string_lossy().to_string(),
        payload.to_string(),
    ]
}

fn spawn_accept_probe(listener: TcpListener, timeout: Duration) -> mpsc::Receiver<bool> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = listener.set_nonblocking(true);
        let start = Instant::now();
        let mut accepted = false;
        while start.elapsed() < timeout {
            match listener.accept() {
                Ok((_stream, _addr)) => {
                    accepted = true;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        let _ = tx.send(accepted);
    });
    rx
}

fn bash_dev_tcp_supported(bash: &str) -> bool {
    let listener = match TcpListener::bind(("127.0.0.1", 0)) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(_) => return false,
    };
    let accepted_rx = spawn_accept_probe(listener, Duration::from_secs(1));
    let status = Command::new(bash)
        .args(["-lc", &format!("exec 3<>/dev/tcp/127.0.0.1/{port}")])
        .status();

    let accepted = accepted_rx
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or(false);
    status.is_ok_and(|code| code.success()) && accepted
}

fn linux_shell_path() -> String {
    ["/bin/sh", "/usr/bin/sh"]
        .iter()
        .find(|path| Path::new(path).is_file())
        .expect("linux shell binary should exist")
        .to_string()
}

fn linux_sleep_path() -> String {
    ["/bin/sleep", "/usr/bin/sleep"]
        .iter()
        .find(|path| Path::new(path).is_file())
        .expect("sleep binary should exist")
        .to_string()
}

fn linux_bash_path() -> Option<String> {
    ["/bin/bash", "/usr/bin/bash"]
        .iter()
        .find(|path| Path::new(path).is_file())
        .map(|path| (*path).to_string())
}
