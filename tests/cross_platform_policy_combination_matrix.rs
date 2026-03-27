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
        let path = std::env::temp_dir().join(format!("procwarden-policy-{prefix}-{nonce}"));
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
fn cross_platform_python_policy_combination_matrix() {
    run_policy_combination_matrix(RuntimeKind::Python);
}

#[test]
fn cross_platform_node_policy_combination_matrix() {
    run_policy_combination_matrix(RuntimeKind::Node);
}

fn run_policy_combination_matrix(kind: RuntimeKind) {
    let workspace = TempDir::new(&format!("{}-workspace", kind.name()));
    let outside = TempDir::new(&format!("{}-outside", kind.name()));
    let manager = SandboxManager::new();

    let runtime_cwd_raw = workspace.path().join("runtime-cwd");
    fs::create_dir_all(&runtime_cwd_raw).expect("runtime cwd should be created");
    let runtime_cwd = normalize_path(&runtime_cwd_raw);
    let runtime = prepare_runtime_harness(kind, &runtime_cwd);

    let ro_scope_raw = workspace.path().join("ro-scope");
    let rw_scope_raw = workspace.path().join("rw-scope");
    let deny_scope_raw = workspace.path().join("deny-scope");
    fs::create_dir_all(&ro_scope_raw).expect("ro scope should be created");
    fs::create_dir_all(&rw_scope_raw).expect("rw scope should be created");
    fs::create_dir_all(&deny_scope_raw).expect("deny scope should be created");
    let ro_scope = normalize_path(&ro_scope_raw);
    let rw_scope = normalize_path(&rw_scope_raw);
    let deny_scope = normalize_path(&deny_scope_raw);
    let outside_scope = normalize_path(outside.path());

    let ro_seed = ro_scope.join("seed-ro.txt");
    fs::write(&ro_seed, "readonly-seed").expect("ro seed should be created");
    let deny_seed = deny_scope.join("seed-deny.txt");
    fs::write(&deny_seed, "deny-seed").expect("deny seed should be created");

    let baseline_policy = SandboxPolicy {
        path_permissions: vec![
            SandboxPathPermission::read_write(runtime_cwd.clone()),
            SandboxPathPermission::read_only(ro_scope.clone()),
        ],
        default_access: SandboxAccess::ReadOnly,
        network_access: true,
    };

    let baseline = manager.execute(
        &sandbox_request(
            runtime_command(&runtime, "read", 1, vec![path_arg(&ro_seed)]),
            &runtime_cwd,
        ),
        &baseline_policy,
    );
    match baseline {
        Ok(output)
            if output.exit_code != 0 && is_skippable_runtime_baseline_failure(kind, &output) =>
        {
            eprintln!(
                "skipping {} policy matrix due to runtime baseline limitation: stdout={}, stderr={}",
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
                "skipping {} policy matrix due to environment limitation: {error:?}",
                kind.name()
            );
            return;
        }
        Err(error) => panic!(
            "unexpected {} baseline execution error: {error:?}",
            kind.name()
        ),
    }

    let readwrite_probe_policy = SandboxPolicy {
        path_permissions: Vec::new(),
        default_access: SandboxAccess::ReadWrite,
        network_access: true,
    };

    let supports_global_readwrite_write = {
        let probe_target = outside_scope.join(format!("{}-readwrite-probe.txt", kind.name()));
        manager
            .execute(
                &sandbox_request(
                    runtime_command(
                        &runtime,
                        "write",
                        1,
                        vec![path_arg(&probe_target), "probe".to_string()],
                    ),
                    &runtime_cwd,
                ),
                &readwrite_probe_policy,
            )
            .is_ok_and(|output| output.exit_code == 0)
    };

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
            .execute(&probe_request, &readwrite_probe_policy)
            .is_ok_and(|output| output.exit_code == 0);
        let probe_accepted = probe_accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false);
        probe_success && probe_accepted
    };

    if !supports_global_readwrite_write {
        eprintln!(
            "{} policy matrix: global ReadWrite writes are unavailable in this AppContainer environment; expecting those write cases to fail",
            kind.name()
        );
    }
    if !supports_loopback_connect {
        eprintln!(
            "{} policy matrix: loopback baseline is unavailable in this AppContainer environment; expecting connect cases to fail",
            kind.name()
        );
    }

    for depth in [1_usize, 2, 3] {
        let readonly_policy = SandboxPolicy {
            path_permissions: vec![
                SandboxPathPermission::read_write(runtime_cwd.clone()),
                SandboxPathPermission::read_only(ro_scope.clone()),
            ],
            default_access: SandboxAccess::ReadOnly,
            network_access: true,
        };
        assert_case(
            &manager,
            &readonly_policy,
            &sandbox_request(
                runtime_command(&runtime, "read", depth, vec![path_arg(&ro_seed)]),
                &runtime_cwd,
            ),
            true,
            &format!(
                "{} depth {depth} readonly policy allows read-only read",
                kind.name()
            ),
        );

        let readonly_write =
            ro_scope.join(format!("{}-depth-{depth}-readonly-write.txt", kind.name()));
        assert_case(
            &manager,
            &readonly_policy,
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![path_arg(&readonly_write), format!("deny-readonly-{depth}")],
                ),
                &runtime_cwd,
            ),
            false,
            &format!(
                "{} depth {depth} readonly global blocks read-only write",
                kind.name()
            ),
        );

        let readonly_no_ro_allow = SandboxPolicy {
            path_permissions: vec![SandboxPathPermission::read_write(runtime_cwd.clone())],
            default_access: SandboxAccess::ReadOnly,
            network_access: true,
        };
        let readonly_outside_write = outside_scope.join(format!(
            "{}-depth-{depth}-readonly-outside-write.txt",
            kind.name()
        ));
        assert_case(
            &manager,
            &readonly_no_ro_allow,
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![
                        path_arg(&readonly_outside_write),
                        format!("deny-readonly-outside-{depth}"),
                    ],
                ),
                &runtime_cwd,
            ),
            false,
            &format!(
                "{} depth {depth} readonly policy blocks outside write",
                kind.name()
            ),
        );
        assert!(
            !readonly_outside_write.exists(),
            "{} depth {depth} readonly outside write must not create file",
            kind.name()
        );

        let readonly_with_carveout = SandboxPolicy {
            path_permissions: vec![
                SandboxPathPermission::read_write(runtime_cwd.clone()),
                SandboxPathPermission::read_only(ro_scope.clone()),
                SandboxPathPermission::read_write(rw_scope.clone()),
            ],
            default_access: SandboxAccess::ReadOnly,
            network_access: true,
        };
        let readonly_carve_write = rw_scope.join(format!(
            "{}-depth-{depth}-readonly-carveout.txt",
            kind.name()
        ));
        assert_case(
            &manager,
            &readonly_with_carveout,
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![
                        path_arg(&readonly_carve_write),
                        format!("allow-readonly-carve-{depth}"),
                    ],
                ),
                &runtime_cwd,
            ),
            true,
            &format!(
                "{} depth {depth} readonly global allows rw carveout",
                kind.name()
            ),
        );

        let readonly_with_deny = SandboxPolicy {
            path_permissions: vec![
                SandboxPathPermission::read_write(runtime_cwd.clone()),
                SandboxPathPermission::read_only(ro_scope.clone()),
                SandboxPathPermission::deny(deny_scope.clone()),
            ],
            default_access: SandboxAccess::ReadOnly,
            network_access: true,
        };
        let readonly_deny_read = manager.execute(
            &sandbox_request(
                runtime_command(&runtime, "read", depth, vec![path_arg(&deny_seed)]),
                &runtime_cwd,
            ),
            &readonly_with_deny,
        );

        let readonly_deny_supported = match readonly_deny_read {
            Ok(output) => {
                assert_ne!(
                    output.exit_code,
                    0,
                    "{} depth {depth} readonly default must deny reads in denied override",
                    kind.name()
                );
                true
            }
            Err(SandboxError::InvalidRequest(message))
                if message.contains("NoAccess path overrides") =>
            {
                false
            }
            Err(error) if is_skippable_environment_error(&error) => {
                eprintln!(
                    "skipping remaining {} matrix checks due to environment limitation: {error:?}",
                    kind.name()
                );
                return;
            }
            Err(error) => panic!(
                "unexpected {} depth {depth} readonly+deny manager error: {error:?}",
                kind.name()
            ),
        };

        if readonly_deny_supported {
            assert_case(
                &manager,
                &readonly_with_deny,
                &sandbox_request(
                    runtime_command(&runtime, "read", depth, vec![path_arg(&ro_seed)]),
                    &runtime_cwd,
                ),
                true,
                &format!(
                    "{} depth {depth} readonly+deny keeps non-denied read paths accessible",
                    kind.name()
                ),
            );
        }

        let readwrite_with_overrides = SandboxPolicy {
            path_permissions: vec![
                SandboxPathPermission::read_write(runtime_cwd.clone()),
                SandboxPathPermission::read_only(ro_scope.clone()),
                SandboxPathPermission::deny(deny_scope.clone()),
            ],
            default_access: SandboxAccess::ReadWrite,
            network_access: true,
        };

        let readwrite_override_ro_write = ro_scope.join(format!(
            "{}-depth-{depth}-readwrite-override-ro.txt",
            kind.name()
        ));
        let readwrite_override_ro = manager.execute(
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![
                        path_arg(&readwrite_override_ro_write),
                        format!("deny-rw-override-ro-{depth}"),
                    ],
                ),
                &runtime_cwd,
            ),
            &readwrite_with_overrides,
        );

        let overrides_supported = match readwrite_override_ro {
            Ok(output) => {
                assert_ne!(
                    output.exit_code,
                    0,
                    "{} depth {depth} readwrite default must not write into read-only override",
                    kind.name()
                );
                true
            }
            Err(SandboxError::InvalidRequest(message))
                if message.contains("default_access=ReadWrite with ReadOnly/NoAccess") =>
            {
                false
            }
            Err(error) if is_skippable_environment_error(&error) => {
                eprintln!(
                    "skipping remaining {} matrix checks due to environment limitation: {error:?}",
                    kind.name()
                );
                return;
            }
            Err(error) => panic!(
                "unexpected {} depth {depth} readwrite override manager error: {error:?}",
                kind.name()
            ),
        };
        assert!(
            !readwrite_override_ro_write.exists(),
            "{} depth {depth} readwrite override ro write must not create file",
            kind.name()
        );

        if overrides_supported {
            assert_case(
                &manager,
                &readwrite_with_overrides,
                &sandbox_request(
                    runtime_command(&runtime, "read", depth, vec![path_arg(&deny_seed)]),
                    &runtime_cwd,
                ),
                false,
                &format!(
                    "{} depth {depth} readwrite default must deny reads in denied override",
                    kind.name()
                ),
            );

            let readwrite_override_outside = outside_scope.join(format!(
                "{}-depth-{depth}-readwrite-override-outside.txt",
                kind.name()
            ));
            assert_case(
                &manager,
                &readwrite_with_overrides,
                &sandbox_request(
                    runtime_command(
                        &runtime,
                        "write",
                        depth,
                        vec![
                            path_arg(&readwrite_override_outside),
                            format!("allow-rw-override-outside-{depth}"),
                        ],
                    ),
                    &runtime_cwd,
                ),
                supports_global_readwrite_write,
                &format!(
                    "{} depth {depth} readwrite default still allows writes outside overrides",
                    kind.name()
                ),
            );
        }

        let readwrite_policy = SandboxPolicy {
            path_permissions: Vec::new(),
            default_access: SandboxAccess::ReadWrite,
            network_access: true,
        };
        let readwrite_outside = outside_scope.join(format!(
            "{}-depth-{depth}-readwrite-global.txt",
            kind.name()
        ));
        assert_case(
            &manager,
            &readwrite_policy,
            &sandbox_request(
                runtime_command(
                    &runtime,
                    "write",
                    depth,
                    vec![
                        path_arg(&readwrite_outside),
                        format!("allow-readwrite-global-{depth}"),
                    ],
                ),
                &runtime_cwd,
            ),
            supports_global_readwrite_write,
            &format!(
                "{} depth {depth} readwrite global allows outside write",
                kind.name()
            ),
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
            &readwrite_policy,
            &sandbox_request(
                runtime_command(&runtime, "connect", depth, vec![allow_port.to_string()]),
                &runtime_cwd,
            ),
            supports_loopback_connect,
            &format!(
                "{} depth {depth} readwrite policy allows loopback connect",
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

        let network_deny_policy = SandboxPolicy {
            path_permissions: Vec::new(),
            default_access: SandboxAccess::ReadWrite,
            network_access: false,
        };
        match manager.execute(
            &sandbox_request(
                runtime_command(&runtime, "connect", depth, vec![deny_port.to_string()]),
                &runtime_cwd,
            ),
            &network_deny_policy,
        ) {
            Ok(output) => {
                assert_ne!(
                    output.exit_code,
                    0,
                    "{} depth {depth} network-disabled policy should fail loopback connect",
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
        let script_path = workspace.join(format!(
            "policy-harness-{}.{}",
            kind.name(),
            kind.extension()
        ));
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
