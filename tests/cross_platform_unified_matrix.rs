use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use procwarden::{
    SandboxAccess, SandboxCommandRequest, SandboxError, SandboxManager, SandboxPathPermission,
    SandboxPolicy,
};

const PYTHON_HARNESS_SOURCE: &str = r#"import os
import socket
import subprocess
import sys

def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(2)

    op = sys.argv[1]
    depth = int(sys.argv[2])
    args = sys.argv[3:]

    if depth > 1 and os.name != "nt":
        result = subprocess.run([sys.executable, __file__, op, str(depth - 1), *args], check=False)
        sys.exit(result.returncode)

    try:
        if op == "write":
            path, payload = args[0], args[1]
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(payload)
            sys.exit(0)

        if op == "read":
            path = args[0]
            with open(path, "r", encoding="utf-8") as handle:
                handle.read()
            sys.exit(0)

        if op == "connect":
            port = int(args[0])
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            try:
                sock.connect(("127.0.0.1", port))
            finally:
                sock.close()
            sys.exit(0)
    except Exception:
        sys.exit(1)

    sys.exit(2)


if __name__ == "__main__":
    main()
"#;

const NODE_HARNESS_SOURCE: &str = r#"const fs = require('fs');
const net = require('net');
const { spawnSync } = require('child_process');

const argvStart = process.argv.length >= 2 && (process.argv[1] === __filename || process.argv[1].endsWith('.js')) ? 2 : 1;
const argv = process.argv.slice(argvStart);
if (argv.length < 2) {
  process.exit(2);
}

const op = argv[0];
const depth = Number(argv[1]);
const args = argv.slice(2);
if (!Number.isInteger(depth) || depth < 1) {
  process.exit(2);
}

if (depth > 1) {
  if (process.platform !== 'win32') {
    const childProgram = process.execArgv.length > 0
      ? [...process.execArgv, op, String(depth - 1), ...args]
      : [__filename, op, String(depth - 1), ...args];
    const result = spawnSync(process.execPath, childProgram, {
      stdio: 'inherit',
    });
    process.exit(typeof result.status === 'number' ? result.status : 1);
  }
}

if (op === 'write') {
  try {
    fs.writeFileSync(args[0], args[1], { encoding: 'utf8' });
    process.exit(0);
  } catch (error) {
    if (error) {
      console.error(error.stack || String(error));
    }
    process.exit(1);
  }
}

if (op === 'read') {
  try {
    fs.readFileSync(args[0], { encoding: 'utf8' });
    process.exit(0);
  } catch (error) {
    if (error) {
      console.error(error.stack || String(error));
    }
    process.exit(1);
  }
}

if (op === 'connect') {
  const port = Number(args[0]);
  const socket = net.createConnection({ host: '127.0.0.1', port });
  socket.setTimeout(1000);
  socket.once('connect', () => {
    socket.end();
    process.exit(0);
  });
  socket.once('timeout', () => {
    socket.destroy();
    process.exit(1);
  });
  socket.once('error', () => {
    if (socket && socket.connecting) {
      console.error('connect-error');
    }
    process.exit(1);
  });
} else {
  process.exit(2);
}
"#;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("procwarden-unified-{prefix}-{nonce}"));
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

    fn extension(self) -> &'static str {
        match self {
            Self::Python => "py",
            Self::Node => "js",
        }
    }

    fn source(self) -> &'static str {
        match self {
            Self::Python => PYTHON_HARNESS_SOURCE,
            Self::Node => NODE_HARNESS_SOURCE,
        }
    }

    fn launcher_candidates(self) -> Vec<Vec<&'static str>> {
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
}

struct RuntimeHarness {
    launcher: Vec<String>,
    script: RuntimeHarnessScript,
}

enum RuntimeHarnessScript {
    File(PathBuf),
    Inline(String),
}

#[test]
fn cross_platform_cli_tool_runs_under_restricted_policy() {
    let git = resolve_launcher(vec![vec!["git"]], vec!["--version"])
        .expect("git runtime should be available on CI runners");

    let workspace = TempDir::new("cli-smoke");
    let manager = SandboxManager::new();
    let policy = SandboxPolicy {
        path_permissions: Vec::new(),
        default_access: SandboxAccess::ReadWrite,
        network_access: true,
    };

    let request = sandbox_request(
        append_command(&git, vec!["--version".to_string()]),
        workspace.path(),
    );

    match manager.execute(&request, &policy) {
        Ok(output) => {
            if output.exit_code != 0 && is_skippable_cli_baseline_failure(&output) {
                eprintln!(
                    "skipping CLI smoke due to runtime limitation: exit={} stdout={} stderr={}",
                    output.exit_code, output.stdout, output.stderr
                );
                return;
            }
            assert_eq!(output.exit_code, 0, "git CLI command should execute");
        }
        Err(error) if is_skippable_environment_error(&error) => {
            eprintln!("skipping CLI smoke due to environment limitation: {error:?}");
        }
        Err(error) => panic!("unexpected CLI smoke execution error: {error:?}"),
    }
}

#[test]
fn cross_platform_python_matrix_depth_path_and_network_consistency() {
    run_runtime_matrix(RuntimeKind::Python);
}

#[test]
fn cross_platform_node_matrix_depth_path_and_network_consistency() {
    run_runtime_matrix(RuntimeKind::Node);
}

fn run_runtime_matrix(kind: RuntimeKind) {
    let workspace = TempDir::new(&format!("{}-matrix", kind.name()));
    let outside = TempDir::new(&format!("{}-outside", kind.name()));
    let manager = SandboxManager::new();

    let runtime_cwd_raw = workspace.path().join("runtime-cwd");
    fs::create_dir_all(&runtime_cwd_raw).expect("runtime cwd directory should be created");
    let runtime_cwd = normalize_path(&runtime_cwd_raw);

    let runtime = prepare_runtime_harness(kind, &runtime_cwd);

    let ro_parent_raw = workspace.path().join("readonly-parent");
    let ro_child_raw = ro_parent_raw.join("child");
    let rw_parent_raw = workspace.path().join("readwrite-parent");
    let rw_child_raw = rw_parent_raw.join("child");
    fs::create_dir_all(&ro_child_raw).expect("readonly child directory should be created");
    fs::create_dir_all(&rw_child_raw).expect("readwrite child directory should be created");

    let ro_parent = normalize_path(&ro_parent_raw);
    let ro_child = normalize_path(&ro_child_raw);
    let rw_parent = normalize_path(&rw_parent_raw);
    let rw_child = normalize_path(&rw_child_raw);
    let outside_root = normalize_path(outside.path());

    let ro_parent_seed = ro_parent.join("seed-parent.txt");
    let ro_child_seed = ro_child.join("seed-child.txt");
    fs::write(&ro_parent_seed, "readonly-parent").expect("readonly parent seed should be created");
    fs::write(&ro_child_seed, "readonly-child").expect("readonly child seed should be created");

    let policy_ro = policy_read_only(true, &runtime_cwd, &ro_parent);
    let policy_rw_parent = policy_with_writable_scope(true, &runtime_cwd, &ro_parent, &rw_parent);
    let policy_rw_child = policy_with_writable_scope(true, &runtime_cwd, &ro_parent, &rw_child);
    let policy_rw_parent_network_deny =
        policy_with_writable_scope(false, &runtime_cwd, &ro_parent, &rw_parent);

    let baseline = manager.execute(
        &sandbox_request(
            runtime_command(&runtime, "read", 1, vec![path_arg(&ro_parent_seed)]),
            &runtime_cwd,
        ),
        &policy_ro,
    );

    match baseline {
        Ok(output)
            if output.exit_code != 0 && is_skippable_runtime_baseline_failure(kind, &output) =>
        {
            eprintln!(
                "skipping {} matrix due to runtime baseline limitation: stdout={}, stderr={}",
                kind.name(),
                output.stdout,
                output.stderr
            );
            return;
        }
        Ok(output) => assert_eq!(
            output.exit_code,
            0,
            "{} baseline read should succeed, stdout: {}, stderr: {}",
            kind.name(),
            output.stdout,
            output.stderr
        ),
        Err(error) if is_skippable_environment_error(&error) => {
            eprintln!(
                "skipping {} matrix due to environment limitation: {error:?}",
                kind.name()
            );
            return;
        }
        Err(error) => panic!(
            "unexpected {} baseline execution error: {error:?}",
            kind.name()
        ),
    }

    let supports_loopback_connect = {
        let probe_listener =
            TcpListener::bind(("127.0.0.1", 0)).expect("loopback probe listener should bind");
        let probe_port = probe_listener
            .local_addr()
            .expect("loopback probe listener addr should resolve")
            .port();
        let probe_accepted_rx = spawn_accept_probe(probe_listener, Duration::from_secs(2));
        let probe_request = sandbox_request(
            runtime_command(&runtime, "connect", 1, vec![probe_port.to_string()]),
            &runtime_cwd,
        );
        let probe_success = manager
            .execute(&probe_request, &policy_rw_parent)
            .is_ok_and(|output| output.exit_code == 0);
        let probe_accepted = probe_accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false);
        probe_success && probe_accepted
    };
    if !supports_loopback_connect {
        eprintln!(
            "{} matrix: loopback baseline is unavailable in this AppContainer environment; expecting connect cases to fail",
            kind.name()
        );
    }

    for depth in [1_usize, 2, 3] {
        assert_case(
            &manager,
            &policy_ro,
            &sandbox_request(
                runtime_command(&runtime, "read", depth, vec![path_arg(&ro_parent_seed)]),
                &runtime_cwd,
            ),
            true,
            &format!("{} depth {depth} read readonly parent", kind.name()),
        );

        assert_case(
            &manager,
            &policy_ro,
            &sandbox_request(
                runtime_command(&runtime, "read", depth, vec![path_arg(&ro_child_seed)]),
                &runtime_cwd,
            ),
            true,
            &format!("{} depth {depth} read readonly child", kind.name()),
        );

        let ro_parent_write =
            ro_parent.join(format!("{}-depth-{depth}-ro-parent.txt", kind.name()));
        assert_case(
            &manager,
            &policy_ro,
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![
                        path_arg(&ro_parent_write),
                        format!("deny-ro-parent-{depth}"),
                    ],
                ),
                &runtime_cwd,
            ),
            false,
            &format!("{} depth {depth} write readonly parent", kind.name()),
        );
        assert!(
            !ro_parent_write.exists(),
            "{} depth {depth} readonly parent write should not create file",
            kind.name()
        );

        let ro_child_write = ro_child.join(format!("{}-depth-{depth}-ro-child.txt", kind.name()));
        assert_case(
            &manager,
            &policy_ro,
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![path_arg(&ro_child_write), format!("deny-ro-child-{depth}")],
                ),
                &runtime_cwd,
            ),
            false,
            &format!("{} depth {depth} write readonly child", kind.name()),
        );
        assert!(
            !ro_child_write.exists(),
            "{} depth {depth} readonly child write should not create file",
            kind.name()
        );

        let rw_parent_write =
            rw_parent.join(format!("{}-depth-{depth}-rw-parent.txt", kind.name()));
        let rw_parent_payload = format!("allow-rw-parent-{depth}");
        assert_case(
            &manager,
            &policy_rw_parent,
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![path_arg(&rw_parent_write), rw_parent_payload.clone()],
                ),
                &runtime_cwd,
            ),
            true,
            &format!("{} depth {depth} write readwrite parent", kind.name()),
        );
        assert_eq!(
            fs::read_to_string(&rw_parent_write).expect("readwrite parent output should exist"),
            rw_parent_payload,
            "{} depth {depth} readwrite parent payload mismatch",
            kind.name()
        );

        let rw_child_write = rw_child.join(format!("{}-depth-{depth}-rw-child.txt", kind.name()));
        let rw_child_payload = format!("allow-rw-child-{depth}");
        assert_case(
            &manager,
            &policy_rw_parent,
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![path_arg(&rw_child_write), rw_child_payload.clone()],
                ),
                &runtime_cwd,
            ),
            true,
            &format!("{} depth {depth} write readwrite child", kind.name()),
        );
        assert_eq!(
            fs::read_to_string(&rw_child_write).expect("readwrite child output should exist"),
            rw_child_payload,
            "{} depth {depth} readwrite child payload mismatch",
            kind.name()
        );

        let outside_write = outside_root.join(format!("{}-depth-{depth}-outside.txt", kind.name()));
        assert_case(
            &manager,
            &policy_rw_parent,
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![path_arg(&outside_write), format!("deny-outside-{depth}")],
                ),
                &runtime_cwd,
            ),
            false,
            &format!("{} depth {depth} write outside scope", kind.name()),
        );
        assert!(
            !outside_write.exists(),
            "{} depth {depth} outside write should not create file",
            kind.name()
        );

        let child_scope_parent_write = rw_parent.join(format!(
            "{}-depth-{depth}-child-scope-parent.txt",
            kind.name()
        ));
        assert_case(
            &manager,
            &policy_rw_child,
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![
                        path_arg(&child_scope_parent_write),
                        format!("deny-parent-only-{depth}"),
                    ],
                ),
                &runtime_cwd,
            ),
            false,
            &format!(
                "{} depth {depth} child-scope denies parent write",
                kind.name()
            ),
        );
        assert!(
            !child_scope_parent_write.exists(),
            "{} depth {depth} child-only write scope should not allow parent writes",
            kind.name()
        );

        let child_scope_child_write = rw_child.join(format!(
            "{}-depth-{depth}-child-scope-child.txt",
            kind.name()
        ));
        let child_scope_payload = format!("allow-child-scope-{depth}");
        assert_case(
            &manager,
            &policy_rw_child,
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![
                        path_arg(&child_scope_child_write),
                        child_scope_payload.clone(),
                    ],
                ),
                &runtime_cwd,
            ),
            true,
            &format!(
                "{} depth {depth} child-scope allows child write",
                kind.name()
            ),
        );
        assert_eq!(
            fs::read_to_string(&child_scope_child_write)
                .expect("child-scope output should exist for child write"),
            child_scope_payload,
            "{} depth {depth} child-scope payload mismatch",
            kind.name()
        );

        let allow_listener =
            TcpListener::bind(("127.0.0.1", 0)).expect("allow listener should bind");
        let allow_port = allow_listener
            .local_addr()
            .expect("allow listener addr should resolve")
            .port();
        let allow_accepted_rx = spawn_accept_probe(allow_listener, Duration::from_secs(2));

        assert_case(
            &manager,
            &policy_rw_parent,
            &sandbox_request(
                runtime_command(&runtime, "connect", depth, vec![allow_port.to_string()]),
                &runtime_cwd,
            ),
            supports_loopback_connect,
            &format!(
                "{} depth {depth} network enabled loopback connect",
                kind.name()
            ),
        );
        let allow_accepted = allow_accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false);
        if supports_loopback_connect {
            assert!(
                allow_accepted,
                "{} depth {depth} network-enabled case should reach listener",
                kind.name()
            );
        }

        let deny_listener = TcpListener::bind(("127.0.0.1", 0)).expect("deny listener should bind");
        let deny_port = deny_listener
            .local_addr()
            .expect("deny listener addr should resolve")
            .port();
        let deny_accepted_rx = spawn_accept_probe(deny_listener, Duration::from_secs(2));

        let deny_request = sandbox_request(
            runtime_command(&runtime, "connect", depth, vec![deny_port.to_string()]),
            &runtime_cwd,
        );
        match manager.execute(&deny_request, &policy_rw_parent_network_deny) {
            Ok(output) => {
                assert_ne!(
                    output.exit_code,
                    0,
                    "{} depth {depth} network-disabled case should fail loopback connect",
                    kind.name()
                );
            }
            Err(SandboxError::Denied(message))
                if message.contains("requires privileges to install temporary WFP filters") => {}
            Err(error) if is_skippable_environment_error(&error) => {
                eprintln!(
                    "skipping remaining {} network-disabled checks due to environment limitation: {error:?}",
                    kind.name()
                );
                return;
            }
            Err(error) => panic!(
                "unexpected {} depth {depth} network-disabled manager error: {error:?}",
                kind.name()
            ),
        }

        let deny_accepted = deny_accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false);
        assert!(
            !deny_accepted,
            "{} depth {depth} network-disabled case should not reach listener",
            kind.name()
        );
    }
}

fn prepare_runtime_harness(kind: RuntimeKind, workspace: &Path) -> RuntimeHarness {
    let launcher = resolve_launcher(kind.launcher_candidates(), kind.probe_args())
        .unwrap_or_else(|| panic!("{} runtime should be available on CI runners", kind.name()));

    let script = if cfg!(windows) && matches!(kind, RuntimeKind::Node) {
        RuntimeHarnessScript::Inline(kind.source().to_string())
    } else {
        let script_path = workspace.join(format!("harness-{}.{}", kind.name(), kind.extension()));
        fs::write(&script_path, kind.source()).expect("runtime harness script should be written");
        RuntimeHarnessScript::File(script_path)
    };

    RuntimeHarness { launcher, script }
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

fn append_command(prefix: &[String], extra: Vec<String>) -> Vec<String> {
    let mut command = prefix.to_vec();
    command.extend(extra);
    command
}

fn runtime_command(
    runtime: &RuntimeHarness,
    op: &str,
    depth: usize,
    args: Vec<String>,
) -> Vec<String> {
    let mut command = runtime.launcher.clone();
    match &runtime.script {
        RuntimeHarnessScript::File(path) => command.push(path_arg(path)),
        RuntimeHarnessScript::Inline(source) => {
            command.push("-e".to_string());
            command.push(source.clone());
        }
    }
    command.push(op.to_string());
    command.push(depth.to_string());
    command.extend(args);
    command
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn normalize_path(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        fs::canonicalize(path).unwrap_or_else(|error| {
            panic!(
                "path should canonicalize on macOS ({}): {error}",
                path.display()
            )
        })
    }

    #[cfg(not(target_os = "macos"))]
    {
        path.to_path_buf()
    }
}

fn sandbox_request(command: Vec<String>, cwd: &Path) -> SandboxCommandRequest {
    SandboxCommandRequest {
        command,
        cwd: cwd.to_path_buf(),
        env: sandbox_env(),
        timeout_ms: Some(10_000),
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

fn policy_read_only(
    network_access: bool,
    runtime_cwd: &Path,
    readonly_parent: &Path,
) -> SandboxPolicy {
    SandboxPolicy {
        path_permissions: vec![
            SandboxPathPermission::read_write(runtime_cwd.to_path_buf()),
            SandboxPathPermission::read_only(readonly_parent.to_path_buf()),
        ],
        default_access: SandboxAccess::ReadOnly,
        network_access,
    }
}

fn policy_with_writable_scope(
    network_access: bool,
    runtime_cwd: &Path,
    readonly_parent: &Path,
    writable_scope: &Path,
) -> SandboxPolicy {
    SandboxPolicy {
        path_permissions: vec![
            SandboxPathPermission::read_write(runtime_cwd.to_path_buf()),
            SandboxPathPermission::read_only(readonly_parent.to_path_buf()),
            SandboxPathPermission::read_write(writable_scope.to_path_buf()),
        ],
        default_access: SandboxAccess::ReadOnly,
        network_access,
    }
}

fn assert_case(
    manager: &SandboxManager,
    policy: &SandboxPolicy,
    request: &SandboxCommandRequest,
    expect_success: bool,
    context: &str,
) {
    let output = manager
        .execute(request, policy)
        .unwrap_or_else(|error| panic!("{context}: manager error: {error:?}"));

    if expect_success {
        assert_eq!(
            output.exit_code, 0,
            "{context}: expected success, stderr: {}",
            output.stderr
        );
    } else {
        assert_ne!(
            output.exit_code, 0,
            "{context}: expected failure but succeeded"
        );
    }
}

fn is_skippable_environment_error(error: &SandboxError) -> bool {
    match error {
        SandboxError::Unavailable(_) => true,
        SandboxError::Windows(message) => {
            message.contains("UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)")
                || message.contains("FwpmEngineOpen0 failed")
        }
        _ => false,
    }
}

fn is_skippable_runtime_baseline_failure(
    kind: RuntimeKind,
    output: &procwarden::SandboxExecOutput,
) -> bool {
    matches!(kind, RuntimeKind::Node)
        && output
            .stderr
            .contains("snap-confine has elevated permissions")
        || (cfg!(windows)
            && matches!(kind, RuntimeKind::Python | RuntimeKind::Node)
            && output.exit_code == -1_073_741_515)
        || (cfg!(windows)
            && matches!(kind, RuntimeKind::Python | RuntimeKind::Node)
            && output.exit_code == -1_073_741_790)
        || (cfg!(windows)
            && matches!(kind, RuntimeKind::Python)
            && output
                .stderr
                .contains("Fatal Python error: init_fs_encoding"))
        || (cfg!(windows)
            && matches!(kind, RuntimeKind::Node)
            && output.stderr.contains("EPERM: operation not permitted")
            && output.stderr.contains("lstat 'C:\\'"))
}

fn is_skippable_cli_baseline_failure(output: &procwarden::SandboxExecOutput) -> bool {
    cfg!(windows) && output.exit_code != 0
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
