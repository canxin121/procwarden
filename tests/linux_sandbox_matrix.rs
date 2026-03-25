#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::os::unix::fs::{PermissionsExt, symlink};
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

struct WriteScriptHarness {
    direct: PathBuf,
    child: PathBuf,
    grandchild: PathBuf,
}

struct ReadScriptHarness {
    direct: PathBuf,
    child: PathBuf,
    grandchild: PathBuf,
}

impl ReadScriptHarness {
    fn new(base_dir: &Path) -> Self {
        let direct = base_dir.join("read-direct.sh");
        let child = base_dir.join("read-child.sh");
        let grandchild = base_dir.join("read-grandchild.sh");

        write_script(
            &direct,
            r#"
cat -- "$1"
"#,
        );
        write_script(
            &child,
            r#"
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /bin/sh "$dir/read-direct.sh" "$1"
"#,
        );
        write_script(
            &grandchild,
            r#"
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /bin/sh "$dir/read-child.sh" "$1"
"#,
        );

        Self {
            direct,
            child,
            grandchild,
        }
    }

    fn command_for_depth(&self, shell: &str, depth: usize, target: &Path) -> Vec<String> {
        vec![
            shell.to_string(),
            self.script_for_depth(depth).to_string_lossy().to_string(),
            target.to_string_lossy().to_string(),
        ]
    }

    fn script_for_depth(&self, depth: usize) -> &Path {
        match depth {
            1 => &self.direct,
            2 => &self.child,
            3 => &self.grandchild,
            _ => panic!("unsupported read depth: {depth}"),
        }
    }
}

impl WriteScriptHarness {
    fn new(base_dir: &Path) -> Self {
        let direct = base_dir.join("write-direct.sh");
        let child = base_dir.join("write-child.sh");
        let grandchild = base_dir.join("write-grandchild.sh");

        write_script(
            &direct,
            r#"
printf '%s' "$2" > "$1"
"#,
        );
        write_script(
            &child,
            r#"
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /bin/sh "$dir/write-direct.sh" "$1" "$2"
"#,
        );
        write_script(
            &grandchild,
            r#"
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /bin/sh "$dir/write-child.sh" "$1" "$2"
"#,
        );

        Self {
            direct,
            child,
            grandchild,
        }
    }

    fn command_for_depth(
        &self,
        shell: &str,
        depth: usize,
        target: &Path,
        payload: &str,
    ) -> Vec<String> {
        vec![
            shell.to_string(),
            self.script_for_depth(depth).to_string_lossy().to_string(),
            target.to_string_lossy().to_string(),
            payload.to_string(),
        ]
    }

    fn script_for_depth(&self, depth: usize) -> &Path {
        match depth {
            1 => &self.direct,
            2 => &self.child,
            3 => &self.grandchild,
            _ => panic!("unsupported write depth: {depth}"),
        }
    }
}

struct NetworkScriptHarness {
    direct: PathBuf,
    child: PathBuf,
    grandchild: PathBuf,
}

impl NetworkScriptHarness {
    fn new(base_dir: &Path) -> Self {
        let direct = base_dir.join("net-direct.sh");
        let child = base_dir.join("net-child.sh");
        let grandchild = base_dir.join("net-grandchild.sh");

        write_script(
            &direct,
            r#"
exec "$1" -lc "exec 3<>/dev/tcp/127.0.0.1/$2"
"#,
        );
        write_script(
            &child,
            r#"
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /bin/sh "$dir/net-direct.sh" "$1" "$2"
"#,
        );
        write_script(
            &grandchild,
            r#"
dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec /bin/sh "$dir/net-child.sh" "$1" "$2"
"#,
        );

        Self {
            direct,
            child,
            grandchild,
        }
    }

    fn command_for_depth(&self, shell: &str, depth: usize, bash: &str, port: u16) -> Vec<String> {
        vec![
            shell.to_string(),
            self.script_for_depth(depth).to_string_lossy().to_string(),
            bash.to_string(),
            port.to_string(),
        ]
    }

    fn script_for_depth(&self, depth: usize) -> &Path {
        match depth {
            1 => &self.direct,
            2 => &self.child,
            3 => &self.grandchild,
            _ => panic!("unsupported network depth: {depth}"),
        }
    }
}

struct DeterministicRng(u64);

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) == 1
    }

    fn choose_depth(&mut self) -> usize {
        ((self.next_u64() % 3) as usize) + 1
    }
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

#[test]
fn concurrent_stress_matrix_parallel_10_to_50_execs() {
    let shell = linux_shell_path();
    let manager = SandboxManager::new();

    for concurrency in [10_usize, 25, 50] {
        let workspace = TempDir::new(&format!("parallel-{concurrency}"));
        let harness = WriteScriptHarness::new(workspace.path());
        let workspace_path = workspace.path().to_path_buf();
        let policy = policy(SandboxAccess::ReadWrite, true, vec![]);

        let mut handles = Vec::new();
        for index in 0..concurrency {
            let manager = manager.clone();
            let policy = policy.clone();
            let cwd = workspace_path.clone();
            let workspace_root = workspace_path.clone();
            let target = workspace_path.join(format!("parallel-{index}.txt"));
            let payload = format!("payload-{index}");
            let command = harness.command_for_depth(&shell, (index % 3) + 1, &target, &payload);

            handles.push(thread::spawn(move || {
                let request = SandboxCommandRequest {
                    command,
                    cwd: cwd.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(5_000),
                };
                let output = manager
                    .execute(&request, &policy, &workspace_root)
                    .unwrap_or_else(|error| {
                        panic!(
                            "parallel case {index} should execute without manager error: {error:?}"
                        )
                    });
                (target, payload, output)
            }));
        }

        for handle in handles {
            let (target, payload, output) = handle
                .join()
                .expect("parallel execution thread should not panic");
            assert_eq!(
                output.exit_code, 0,
                "parallel write should succeed, stderr: {}",
                output.stderr
            );
            assert!(!output.timed_out, "parallel write should not time out");

            let content = fs::read_to_string(&target).unwrap_or_else(|error| {
                panic!("parallel target {} should exist: {error}", target.display())
            });
            assert_eq!(
                content, payload,
                "parallel target content should match payload"
            );
        }
    }
}

#[test]
fn write_permissions_hold_across_parent_child_and_grandchild_processes() {
    let shell = linux_shell_path();
    let manager = SandboxManager::new();
    let workspace = TempDir::new("depth-write-workspace");
    let outside = TempDir::new("depth-write-outside");
    let harness = WriteScriptHarness::new(workspace.path());

    #[derive(Clone)]
    struct DepthCase {
        name: &'static str,
        depth: usize,
        policy: SandboxPolicy,
        target: PathBuf,
        payload: &'static str,
        expect_success: bool,
    }

    let workspace_path = workspace.path().to_path_buf();
    let outside_path = outside.path().to_path_buf();
    let cases = vec![
        DepthCase {
            name: "ro_parent_write_denied",
            depth: 1,
            policy: policy(SandboxAccess::ReadOnly, true, vec![]),
            target: workspace_path.join("ro-parent.txt"),
            payload: "denied-parent",
            expect_success: false,
        },
        DepthCase {
            name: "ro_child_write_denied",
            depth: 2,
            policy: policy(SandboxAccess::ReadOnly, true, vec![]),
            target: workspace_path.join("ro-child.txt"),
            payload: "denied-child",
            expect_success: false,
        },
        DepthCase {
            name: "ro_grandchild_write_denied",
            depth: 3,
            policy: policy(SandboxAccess::ReadOnly, true, vec![]),
            target: workspace_path.join("ro-grandchild.txt"),
            payload: "denied-grandchild",
            expect_success: false,
        },
        DepthCase {
            name: "ro_plus_workspace_rw_child_write_allowed",
            depth: 2,
            policy: policy(
                SandboxAccess::ReadOnly,
                true,
                vec![SandboxPathPermission::read_write(workspace_path.clone())],
            ),
            target: workspace_path.join("ro-rw-child.txt"),
            payload: "allowed-child",
            expect_success: true,
        },
        DepthCase {
            name: "ro_plus_workspace_rw_grandchild_write_allowed",
            depth: 3,
            policy: policy(
                SandboxAccess::ReadOnly,
                true,
                vec![SandboxPathPermission::read_write(workspace_path.clone())],
            ),
            target: workspace_path.join("ro-rw-grandchild.txt"),
            payload: "allowed-grandchild",
            expect_success: true,
        },
        DepthCase {
            name: "rw_parent_write_allowed",
            depth: 1,
            policy: policy(SandboxAccess::ReadWrite, true, vec![]),
            target: workspace_path.join("rw-parent.txt"),
            payload: "rw-parent",
            expect_success: true,
        },
        DepthCase {
            name: "rw_child_write_allowed",
            depth: 2,
            policy: policy(SandboxAccess::ReadWrite, true, vec![]),
            target: workspace_path.join("rw-child.txt"),
            payload: "rw-child",
            expect_success: true,
        },
        DepthCase {
            name: "rw_grandchild_write_allowed",
            depth: 3,
            policy: policy(SandboxAccess::ReadWrite, true, vec![]),
            target: workspace_path.join("rw-grandchild.txt"),
            payload: "rw-grandchild",
            expect_success: true,
        },
        DepthCase {
            name: "ro_plus_outside_rw_grandchild_write_allowed",
            depth: 3,
            policy: policy(
                SandboxAccess::ReadOnly,
                true,
                vec![SandboxPathPermission::read_write(outside_path.clone())],
            ),
            target: outside_path.join("outside-rw-grandchild.txt"),
            payload: "outside-allowed",
            expect_success: true,
        },
    ];

    for case in cases {
        let request = SandboxCommandRequest {
            command: harness.command_for_depth(&shell, case.depth, &case.target, case.payload),
            cwd: workspace_path.clone(),
            env: HashMap::new(),
            timeout_ms: Some(4_000),
        };

        let output = manager
            .execute(&request, &case.policy, workspace.path())
            .unwrap_or_else(|error| panic!("case {} should execute: {error:?}", case.name));

        if case.expect_success {
            assert_eq!(
                output.exit_code, 0,
                "case {} should allow write, stderr: {}",
                case.name, output.stderr
            );
            let content = fs::read_to_string(&case.target)
                .unwrap_or_else(|error| panic!("case {} should create file: {error}", case.name));
            assert_eq!(
                content, case.payload,
                "case {} should preserve payload",
                case.name
            );
        } else {
            assert_ne!(
                output.exit_code, 0,
                "case {} should deny write through process depth {}",
                case.name, case.depth
            );
            assert!(
                !case.target.exists(),
                "case {} should not create file {}",
                case.name,
                case.target.display()
            );
        }
    }
}

#[test]
fn readonly_and_readwrite_read_behavior_across_parent_child_and_grandchild() {
    let shell = linux_shell_path();
    let manager = SandboxManager::new();
    let workspace = TempDir::new("read-depth-workspace");
    let script_dir = workspace.path().join("scripts");
    let data_dir = workspace.path().join("data");
    let child_dir = data_dir.join("child");
    fs::create_dir_all(&script_dir).expect("script directory should exist");
    fs::create_dir_all(&child_dir).expect("child data directory should exist");

    let parent_file = data_dir.join("parent-read.txt");
    let child_file = child_dir.join("child-read.txt");
    fs::write(&parent_file, "parent-content").expect("parent read file should be written");
    fs::write(&child_file, "child-content").expect("child read file should be written");

    let harness = ReadScriptHarness::new(&script_dir);

    for depth in [1_usize, 2, 3] {
        let ro_parent_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(&shell, depth, &parent_file),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy(SandboxAccess::ReadOnly, true, vec![]),
                workspace.path(),
            )
            .expect("readonly read should execute");
        assert_eq!(
            ro_parent_output.exit_code, 0,
            "readonly read should succeed at depth {depth}"
        );
        assert_eq!(
            ro_parent_output.stdout, "parent-content",
            "readonly read should preserve parent file output"
        );

        let rw_child_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(&shell, depth, &child_file),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy(SandboxAccess::ReadWrite, true, vec![]),
                workspace.path(),
            )
            .expect("readwrite read should execute");
        assert_eq!(
            rw_child_output.exit_code, 0,
            "readwrite read should succeed at depth {depth}"
        );
        assert_eq!(
            rw_child_output.stdout, "child-content",
            "readwrite read should preserve child file output"
        );
    }
}

#[test]
fn noaccess_unlisted_paths_are_not_readable_across_depths() {
    let shell = linux_shell_path();
    let manager = SandboxManager::new();
    let workspace = TempDir::new("noaccess-workspace");
    let outside = TempDir::new("noaccess-outside");
    let script_dir = workspace.path().join("scripts");
    fs::create_dir_all(&script_dir).expect("script directory should exist");

    let allowed_file = workspace.path().join("allowed.txt");
    let blocked_file = outside.path().join("blocked.txt");
    fs::write(&allowed_file, "allowed-data").expect("allowed file should be written");
    fs::write(&blocked_file, "blocked-data").expect("blocked file should be written");

    let harness = ReadScriptHarness::new(&script_dir);
    let policy = noaccess_policy_with_readable_paths(vec![
        workspace.path().to_path_buf(),
        script_dir.clone(),
    ]);

    for depth in [1_usize, 2, 3] {
        let allowed_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(&shell, depth, &allowed_file),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy,
                workspace.path(),
            )
            .expect("noaccess allowed read should execute");
        assert_eq!(
            allowed_output.exit_code, 0,
            "allowlisted read should succeed at depth {depth}"
        );
        assert_eq!(
            allowed_output.stdout, "allowed-data",
            "allowlisted read should preserve expected content"
        );

        let blocked_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(&shell, depth, &blocked_file),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy,
                workspace.path(),
            )
            .expect("noaccess blocked read should execute");

        assert_ne!(
            blocked_output.exit_code, 0,
            "non-allowlisted read should fail under noaccess at depth {depth}"
        );
    }
}

#[test]
fn noaccess_child_allowlist_blocks_parent_reads_across_depths() {
    let shell = linux_shell_path();
    let manager = SandboxManager::new();
    let workspace = TempDir::new("noaccess-parent-child");
    let script_dir = workspace.path().join("scripts");
    let parent_dir = workspace.path().join("parent");
    let child_dir = parent_dir.join("child");
    fs::create_dir_all(&script_dir).expect("script directory should exist");
    fs::create_dir_all(&child_dir).expect("child directory should exist");

    let parent_file = parent_dir.join("parent.txt");
    let child_file = child_dir.join("child.txt");
    fs::write(&parent_file, "parent-data").expect("parent file should be written");
    fs::write(&child_file, "child-data").expect("child file should be written");

    let harness = ReadScriptHarness::new(&script_dir);
    let policy = noaccess_policy_with_readable_paths(vec![script_dir.clone(), child_dir.clone()]);

    for depth in [1_usize, 2, 3] {
        let child_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(&shell, depth, &child_file),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy,
                workspace.path(),
            )
            .expect("child allowlisted read should execute");
        assert_eq!(
            child_output.exit_code, 0,
            "allowlisted child read should succeed at depth {depth}"
        );
        assert_eq!(child_output.stdout, "child-data");

        let parent_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(&shell, depth, &parent_file),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy,
                workspace.path(),
            )
            .expect("parent non-allowlisted read should execute");
        assert_ne!(
            parent_output.exit_code, 0,
            "parent path should remain unreadable at depth {depth}"
        );
    }
}

#[test]
fn readonly_and_readwrite_write_behavior_for_parent_and_subpaths_across_depths() {
    let shell = linux_shell_path();
    let manager = SandboxManager::new();
    let workspace = TempDir::new("write-parent-child");
    let script_dir = workspace.path().join("scripts");
    let parent_dir = workspace.path().join("parent");
    let child_dir = parent_dir.join("child");
    fs::create_dir_all(&script_dir).expect("script directory should exist");
    fs::create_dir_all(&child_dir).expect("child directory should exist");

    let harness = WriteScriptHarness::new(&script_dir);

    for depth in [1_usize, 2, 3] {
        let ro_parent_target = parent_dir.join(format!("ro-parent-depth-{depth}.txt"));
        let ro_child_target = child_dir.join(format!("ro-child-depth-{depth}.txt"));
        let rw_parent_target = parent_dir.join(format!("rw-parent-depth-{depth}.txt"));
        let rw_child_target = child_dir.join(format!("rw-child-depth-{depth}.txt"));
        let ro_rw_child_parent_target = parent_dir.join(format!("ro-rw-child-parent-{depth}.txt"));
        let ro_rw_child_child_target = child_dir.join(format!("ro-rw-child-child-{depth}.txt"));
        let ro_rw_parent_parent_target =
            parent_dir.join(format!("ro-rw-parent-parent-{depth}.txt"));
        let ro_rw_parent_child_target = child_dir.join(format!("ro-rw-parent-child-{depth}.txt"));

        let ro_parent_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(
                        &shell,
                        depth,
                        &ro_parent_target,
                        "ro-parent-blocked",
                    ),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy(SandboxAccess::ReadOnly, true, vec![]),
                workspace.path(),
            )
            .expect("readonly parent write should execute");
        assert_ne!(ro_parent_output.exit_code, 0);
        assert!(!ro_parent_target.exists());

        let ro_child_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(
                        &shell,
                        depth,
                        &ro_child_target,
                        "ro-child-blocked",
                    ),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy(SandboxAccess::ReadOnly, true, vec![]),
                workspace.path(),
            )
            .expect("readonly child write should execute");
        assert_ne!(ro_child_output.exit_code, 0);
        assert!(!ro_child_target.exists());

        let rw_parent_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(
                        &shell,
                        depth,
                        &rw_parent_target,
                        "rw-parent-ok",
                    ),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy(SandboxAccess::ReadWrite, true, vec![]),
                workspace.path(),
            )
            .expect("readwrite parent write should execute");
        assert_eq!(rw_parent_output.exit_code, 0);
        assert_eq!(
            fs::read_to_string(&rw_parent_target).expect("rw parent target should exist"),
            "rw-parent-ok"
        );

        let rw_child_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(
                        &shell,
                        depth,
                        &rw_child_target,
                        "rw-child-ok",
                    ),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy(SandboxAccess::ReadWrite, true, vec![]),
                workspace.path(),
            )
            .expect("readwrite child write should execute");
        assert_eq!(rw_child_output.exit_code, 0);
        assert_eq!(
            fs::read_to_string(&rw_child_target).expect("rw child target should exist"),
            "rw-child-ok"
        );

        let ro_rw_child_parent_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(
                        &shell,
                        depth,
                        &ro_rw_child_parent_target,
                        "ro-rw-child-parent",
                    ),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy(
                    SandboxAccess::ReadOnly,
                    true,
                    vec![SandboxPathPermission::read_write(child_dir.clone())],
                ),
                workspace.path(),
            )
            .expect("readonly plus child-rw parent write should execute");
        assert_ne!(
            ro_rw_child_parent_output.exit_code, 0,
            "parent should stay unwritable when only child is rw"
        );
        assert!(!ro_rw_child_parent_target.exists());

        let ro_rw_child_child_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(
                        &shell,
                        depth,
                        &ro_rw_child_child_target,
                        "ro-rw-child-child",
                    ),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy(
                    SandboxAccess::ReadOnly,
                    true,
                    vec![SandboxPathPermission::read_write(child_dir.clone())],
                ),
                workspace.path(),
            )
            .expect("readonly plus child-rw child write should execute");
        assert_eq!(
            ro_rw_child_child_output.exit_code, 0,
            "child should be writable when explicitly granted"
        );
        assert_eq!(
            fs::read_to_string(&ro_rw_child_child_target).expect("child rw target should exist"),
            "ro-rw-child-child"
        );

        let ro_rw_parent_parent_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(
                        &shell,
                        depth,
                        &ro_rw_parent_parent_target,
                        "ro-rw-parent-parent",
                    ),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy(
                    SandboxAccess::ReadOnly,
                    true,
                    vec![SandboxPathPermission::read_write(parent_dir.clone())],
                ),
                workspace.path(),
            )
            .expect("readonly plus parent-rw parent write should execute");
        assert_eq!(ro_rw_parent_parent_output.exit_code, 0);
        assert_eq!(
            fs::read_to_string(&ro_rw_parent_parent_target).expect("parent rw target should exist"),
            "ro-rw-parent-parent"
        );

        let ro_rw_parent_child_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(
                        &shell,
                        depth,
                        &ro_rw_parent_child_target,
                        "ro-rw-parent-child",
                    ),
                    cwd: script_dir.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(4_000),
                },
                &policy(
                    SandboxAccess::ReadOnly,
                    true,
                    vec![SandboxPathPermission::read_write(parent_dir.clone())],
                ),
                workspace.path(),
            )
            .expect("readonly plus parent-rw child write should execute");
        assert_eq!(ro_rw_parent_child_output.exit_code, 0);
        assert_eq!(
            fs::read_to_string(&ro_rw_parent_child_target)
                .expect("parent-rw child target should exist"),
            "ro-rw-parent-child"
        );
    }
}

#[test]
fn large_output_long_command_and_high_frequency_timeouts_are_stable() {
    let shell = linux_shell_path();
    let sleep_bin = linux_sleep_path();
    let manager = SandboxManager::new();
    let workspace = TempDir::new("large-output-timeout");

    let long_argument = "x".repeat(16 * 1024);
    let script = "printf '%s\\n' \"${#1}\"; \
        i=0; while [ \"$i\" -lt 3000 ]; do printf 'stdout-%04d\\n' \"$i\"; i=$((i + 1)); done; \
        i=0; while [ \"$i\" -lt 2500 ]; do printf 'stderr-%04d\\n' \"$i\" >&2; i=$((i + 1)); done";

    let output = manager
        .execute(
            &SandboxCommandRequest {
                command: vec![
                    shell.clone(),
                    "-c".to_string(),
                    script.to_string(),
                    "procwarden-long".to_string(),
                    long_argument.clone(),
                ],
                cwd: workspace.path().to_path_buf(),
                env: HashMap::new(),
                timeout_ms: Some(12_000),
            },
            &policy(SandboxAccess::ReadWrite, true, vec![]),
            workspace.path(),
        )
        .expect("large output command should execute");

    assert_eq!(output.exit_code, 0, "large output command should succeed");
    let mut stdout_lines = output.stdout.lines();
    let observed_len = stdout_lines
        .next()
        .expect("length line should be present")
        .trim()
        .parse::<usize>()
        .expect("length line should be numeric");
    assert_eq!(
        observed_len,
        long_argument.len(),
        "long argument length should be preserved"
    );
    assert!(
        stdout_lines.count() >= 3_000,
        "stdout should include large payload"
    );
    assert!(
        output.stderr.lines().count() >= 2_500,
        "stderr should include large payload"
    );
    assert!(
        output.aggregated_output.contains("stdout-2999")
            && output.aggregated_output.contains("stderr-2499"),
        "aggregated output should include both streams"
    );

    for attempt in 0..30 {
        let timeout_output = manager
            .execute(
                &SandboxCommandRequest {
                    command: vec![sleep_bin.clone(), "1".to_string()],
                    cwd: workspace.path().to_path_buf(),
                    env: HashMap::new(),
                    timeout_ms: Some(25),
                },
                &policy(SandboxAccess::ReadWrite, true, vec![]),
                workspace.path(),
            )
            .unwrap_or_else(|error| panic!("timeout attempt {attempt} should execute: {error:?}"));

        assert!(
            timeout_output.timed_out,
            "attempt {attempt} should time out"
        );
        assert_eq!(
            timeout_output.exit_code, 124,
            "attempt {attempt} should use timeout exit code"
        );
    }
}

#[test]
fn filesystem_boundaries_cover_deep_paths_readonly_permissions_and_symlink_chains() {
    let shell = linux_shell_path();
    let manager = SandboxManager::new();
    let workspace = TempDir::new("fs-boundary-workspace");
    let outside = TempDir::new("fs-boundary-outside");
    let harness = WriteScriptHarness::new(workspace.path());

    let deep_dir = create_deep_directory(workspace.path(), 24);
    let deep_allowed = deep_dir.join("deep-allowed.txt");
    let deep_denied = deep_dir.join("deep-denied.txt");

    let allowed_output = manager
        .execute(
            &SandboxCommandRequest {
                command: harness.command_for_depth(&shell, 3, &deep_allowed, "deep-ok"),
                cwd: workspace.path().to_path_buf(),
                env: HashMap::new(),
                timeout_ms: Some(4_000),
            },
            &policy(
                SandboxAccess::ReadOnly,
                true,
                vec![SandboxPathPermission::read_write(deep_dir.clone())],
            ),
            workspace.path(),
        )
        .expect("deep allowed case should execute");
    assert_eq!(
        allowed_output.exit_code, 0,
        "deep allowed write should succeed"
    );
    assert_eq!(
        fs::read_to_string(&deep_allowed).expect("deep allowed file should exist"),
        "deep-ok"
    );

    let denied_output = manager
        .execute(
            &SandboxCommandRequest {
                command: harness.command_for_depth(&shell, 2, &deep_denied, "deep-no"),
                cwd: workspace.path().to_path_buf(),
                env: HashMap::new(),
                timeout_ms: Some(4_000),
            },
            &policy(
                SandboxAccess::ReadOnly,
                true,
                vec![SandboxPathPermission::read_only(deep_dir.clone())],
            ),
            workspace.path(),
        )
        .expect("deep denied case should execute");
    assert_ne!(denied_output.exit_code, 0, "deep denied write should fail");
    assert!(
        !deep_denied.exists(),
        "deep denied target should remain absent"
    );

    let outside_target = outside.path().join("outside-target.txt");
    fs::write(&outside_target, "seed").expect("outside seed file should be written");
    let link2 = workspace.path().join("link2");
    let link1 = workspace.path().join("link1");
    symlink(&outside_target, &link2).expect("first symlink should be created");
    symlink(&link2, &link1).expect("second symlink should be created");

    let symlink_escape_output = manager
        .execute(
            &SandboxCommandRequest {
                command: harness.command_for_depth(&shell, 3, &link1, "escape-attempt"),
                cwd: workspace.path().to_path_buf(),
                env: HashMap::new(),
                timeout_ms: Some(4_000),
            },
            &policy(
                SandboxAccess::ReadOnly,
                true,
                vec![SandboxPathPermission::read_write(
                    workspace.path().to_path_buf(),
                )],
            ),
            workspace.path(),
        )
        .expect("symlink escape case should execute");
    assert_ne!(
        symlink_escape_output.exit_code, 0,
        "symlink chain should not bypass denied outside write"
    );
    assert_eq!(
        fs::read_to_string(&outside_target).expect("outside target should stay readable"),
        "seed",
        "outside file should remain unchanged after denied escape"
    );

    let readonly_dir = workspace.path().join("readonly-perm-dir");
    fs::create_dir_all(&readonly_dir).expect("readonly permission directory should exist");
    fs::set_permissions(&readonly_dir, fs::Permissions::from_mode(0o555))
        .expect("should set readonly directory permissions");

    let readonly_target = readonly_dir.join("blocked-by-fs.txt");
    let readonly_output = manager
        .execute(
            &SandboxCommandRequest {
                command: harness.command_for_depth(&shell, 1, &readonly_target, "perm-blocked"),
                cwd: workspace.path().to_path_buf(),
                env: HashMap::new(),
                timeout_ms: Some(4_000),
            },
            &policy(SandboxAccess::ReadWrite, true, vec![]),
            workspace.path(),
        )
        .expect("readonly permission case should execute");

    assert_ne!(
        readonly_output.exit_code, 0,
        "filesystem readonly permissions should block writes"
    );
    assert!(
        !readonly_target.exists(),
        "filesystem permission block should keep file absent"
    );

    fs::set_permissions(&readonly_dir, fs::Permissions::from_mode(0o755))
        .expect("should restore directory permissions for cleanup");
}

#[test]
fn network_policy_holds_across_parent_child_and_grandchild_processes() {
    let Some(bash) = linux_bash_path() else {
        return;
    };
    if !bash_dev_tcp_supported(&bash) {
        return;
    }

    let shell = linux_shell_path();
    let manager = SandboxManager::new();
    let workspace = TempDir::new("network-depth-matrix");
    let harness = NetworkScriptHarness::new(workspace.path());

    for depth in [1_usize, 2, 3] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("allow listener should bind");
        let port = listener
            .local_addr()
            .expect("allow listener addr should resolve")
            .port();
        let accepted_rx = spawn_accept_probe(listener, Duration::from_secs(2));

        let output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(&shell, depth, &bash, port),
                    cwd: workspace.path().to_path_buf(),
                    env: HashMap::new(),
                    timeout_ms: Some(3_000),
                },
                &policy(SandboxAccess::ReadWrite, true, vec![]),
                workspace.path(),
            )
            .expect("network-allow depth case should execute");

        let accepted = accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false);
        assert_eq!(
            output.exit_code, 0,
            "depth {depth} should allow network when enabled"
        );
        assert!(accepted, "depth {depth} should reach loopback listener");
    }

    for depth in [1_usize, 2, 3] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("deny listener should bind");
        let port = listener
            .local_addr()
            .expect("deny listener addr should resolve")
            .port();
        let accepted_rx = spawn_accept_probe(listener, Duration::from_secs(2));

        let output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(&shell, depth, &bash, port),
                    cwd: workspace.path().to_path_buf(),
                    env: HashMap::new(),
                    timeout_ms: Some(3_000),
                },
                &policy(SandboxAccess::ReadWrite, false, vec![]),
                workspace.path(),
            )
            .expect("network-deny depth case should execute");

        let accepted = accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false);
        assert_ne!(
            output.exit_code, 0,
            "depth {depth} should deny network when disabled"
        );
        assert!(
            !accepted,
            "depth {depth} should not reach loopback listener when denied"
        );
    }
}

#[test]
fn property_style_randomized_policy_combinations_match_write_expectations() {
    let shell = linux_shell_path();
    let manager = SandboxManager::new();
    let workspace = TempDir::new("property-workspace");
    let outside = TempDir::new("property-outside");
    let harness = WriteScriptHarness::new(workspace.path());
    let workspace_path = workspace.path().to_path_buf();
    let outside_path = outside.path().to_path_buf();

    let mut rng = DeterministicRng::new(0x5eed_5eed_1234_5678);

    for case_index in 0..120_usize {
        let global_access = if rng.next_bool() {
            SandboxAccess::ReadWrite
        } else {
            SandboxAccess::ReadOnly
        };
        let network_access = rng.next_bool();
        let grant_workspace_rw = rng.next_bool();
        let grant_outside_rw = rng.next_bool();
        let target_workspace = rng.next_bool();
        let depth = rng.choose_depth();

        let mut permissions = Vec::new();
        if grant_workspace_rw {
            permissions.push(SandboxPathPermission::read_write(workspace_path.clone()));
        } else if rng.next_bool() {
            permissions.push(SandboxPathPermission::read_only(workspace_path.clone()));
        }
        if grant_outside_rw {
            permissions.push(SandboxPathPermission::read_write(outside_path.clone()));
        } else if rng.next_bool() {
            permissions.push(SandboxPathPermission::read_only(outside_path.clone()));
        }

        let target = if target_workspace {
            workspace_path.join(format!("property-workspace-{case_index}.txt"))
        } else {
            outside_path.join(format!("property-outside-{case_index}.txt"))
        };
        let payload = format!("property-payload-{case_index}-{depth}");

        let output = manager
            .execute(
                &SandboxCommandRequest {
                    command: harness.command_for_depth(&shell, depth, &target, &payload),
                    cwd: workspace_path.clone(),
                    env: HashMap::new(),
                    timeout_ms: Some(5_000),
                },
                &policy(global_access, network_access, permissions),
                workspace.path(),
            )
            .unwrap_or_else(|error| panic!("property case {case_index} should execute: {error:?}"));

        let expect_success = matches!(global_access, SandboxAccess::ReadWrite)
            || (target_workspace && grant_workspace_rw)
            || (!target_workspace && grant_outside_rw);

        if expect_success {
            assert_eq!(
                output.exit_code, 0,
                "property case {case_index} should succeed, stderr: {}",
                output.stderr
            );
            let content = fs::read_to_string(&target)
                .unwrap_or_else(|error| panic!("property case {case_index} file missing: {error}"));
            assert_eq!(
                content, payload,
                "property case {case_index} should persist payload"
            );
        } else {
            assert_ne!(
                output.exit_code, 0,
                "property case {case_index} should fail for denied write"
            );
            assert!(
                !target.exists(),
                "property case {case_index} should not create denied target {}",
                target.display()
            );
        }
    }
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

fn write_script(path: &Path, body: &str) {
    let script = format!("#!/bin/sh\nset -eu\n{}\n", body.trim());
    fs::write(path, script)
        .unwrap_or_else(|error| panic!("failed to write script {}: {error}", path.display()));
}

fn create_deep_directory(base: &Path, depth: usize) -> PathBuf {
    let mut path = base.to_path_buf();
    for segment in 0..depth {
        path.push(format!("deep-segment-{segment:02}-abcdefghijklmnop"));
    }
    fs::create_dir_all(&path).unwrap_or_else(|error| {
        panic!(
            "failed to create deep directory {}: {error}",
            path.display()
        )
    });
    path
}

fn noaccess_policy_with_readable_paths(extra_paths: Vec<PathBuf>) -> SandboxPolicy {
    let mut permissions = runtime_readable_roots()
        .into_iter()
        .map(SandboxPathPermission::read_only)
        .collect::<Vec<_>>();

    permissions.extend(
        extra_paths
            .into_iter()
            .map(SandboxPathPermission::read_only),
    );
    policy(SandboxAccess::NoAccess, true, permissions)
}

fn runtime_readable_roots() -> Vec<PathBuf> {
    let candidates = [
        "/bin",
        "/usr/bin",
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/libexec",
    ];

    let mut roots = Vec::new();
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() {
            roots.push(path);
        }
    }
    roots
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
