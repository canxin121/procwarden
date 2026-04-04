#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use procwarden::{
    SandboxCommandRequest, SandboxDefaultAccess, SandboxError, SandboxExecOutput, SandboxManager,
    SandboxNetworkMode, SandboxPathPermission, SandboxPolicy,
};

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("procwarden-tests-{prefix}-{nonce}"));
        fs::create_dir_all(&path).expect("temp directory should be created");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub struct Fixture {
    _workspace: TempDir,
    _outside: TempDir,
    pub runtime_cwd: PathBuf,
    pub deny_dir: PathBuf,
    pub ro_dir: PathBuf,
    pub rw_dir: PathBuf,
    pub outside_dir: PathBuf,
    pub deny_seed: PathBuf,
    pub ro_seed: PathBuf,
    pub outside_seed: PathBuf,
}

impl Fixture {
    pub fn new(prefix: &str) -> Self {
        let workspace = TempDir::new(&format!("{prefix}-workspace"));
        let outside = TempDir::new(&format!("{prefix}-outside"));

        let runtime_cwd_raw = workspace.path().join("runtime-cwd");
        let deny_dir_raw = workspace.path().join("denied");
        let ro_dir_raw = workspace.path().join("readonly");
        let rw_dir_raw = workspace.path().join("readwrite");
        let outside_dir_raw = outside.path().join("outside");

        for dir in [
            &runtime_cwd_raw,
            &deny_dir_raw,
            &ro_dir_raw,
            &rw_dir_raw,
            &outside_dir_raw,
        ] {
            fs::create_dir_all(dir).expect("fixture directory should be created");
        }

        let deny_seed_raw = deny_dir_raw.join("seed-deny.txt");
        let ro_seed_raw = ro_dir_raw.join("seed-ro.txt");
        let outside_seed_raw = outside_dir_raw.join("seed-outside.txt");
        fs::write(&deny_seed_raw, "deny-seed").expect("deny seed should be created");
        fs::write(&ro_seed_raw, "readonly-seed").expect("readonly seed should be created");
        fs::write(&outside_seed_raw, "outside-seed").expect("outside seed should be created");

        let runtime_cwd = normalize_path(&runtime_cwd_raw);
        let deny_dir = normalize_path(&deny_dir_raw);
        let ro_dir = normalize_path(&ro_dir_raw);
        let rw_dir = normalize_path(&rw_dir_raw);
        let outside_dir = normalize_path(&outside_dir_raw);
        let deny_seed = normalize_path(&deny_seed_raw);
        let ro_seed = normalize_path(&ro_seed_raw);
        let outside_seed = normalize_path(&outside_seed_raw);

        Self {
            _workspace: workspace,
            _outside: outside,
            runtime_cwd,
            deny_dir,
            ro_dir,
            rw_dir,
            outside_dir,
            deny_seed,
            ro_seed,
            outside_seed,
        }
    }
}

pub fn policy(
    default_access: SandboxDefaultAccess,
    network_mode: SandboxNetworkMode,
    path_permissions: Vec<SandboxPathPermission>,
) -> SandboxPolicy {
    SandboxPolicy {
        path_permissions,
        default_access,
        network_mode,
    }
}

pub fn sandbox_request(command: Vec<String>, cwd: &Path, timeout_ms: u64) -> SandboxCommandRequest {
    SandboxCommandRequest {
        command,
        cwd: cwd.to_path_buf(),
        env: sandbox_env(),
        timeout_ms: Some(timeout_ms),
    }
}

pub fn sandbox_env() -> HashMap<String, String> {
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

pub fn read_command(target: &Path) -> Vec<String> {
    #[cfg(windows)]
    {
        let escaped_target = escape_powershell_single_quoted(target);
        vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            format!(
                "try {{ [System.IO.File]::ReadAllText('{escaped_target}') | Out-Null; exit 0 }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
            ),
        ]
    }

    #[cfg(not(windows))]
    {
        vec!["/bin/cat".to_string(), path_arg(target)]
    }
}

pub fn write_command(target: &Path, payload: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        let escaped_target = escape_powershell_single_quoted(target);
        let escaped_payload = payload.replace('\'', "''");
        vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            format!(
                "try {{ [System.IO.File]::WriteAllText('{escaped_target}', '{escaped_payload}'); exit 0 }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
            ),
        ]
    }

    #[cfg(not(windows))]
    {
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf '%s' \"$2\" > \"$1\"".to_string(),
            "sh".to_string(),
            path_arg(target),
            payload.to_string(),
        ]
    }
}

pub fn connect_command(host: &str, port: u16, timeout_ms: u64) -> Vec<String> {
    #[cfg(windows)]
    {
        let escaped_host = host.replace('\'', "''");
        vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            format!(
                "try {{ $client = New-Object System.Net.Sockets.TcpClient; $async = $client.BeginConnect('{escaped_host}', {port}, $null, $null); if (-not $async.AsyncWaitHandle.WaitOne({timeout_ms}, $false)) {{ $client.Close(); [Console]::Error.WriteLine('timeout'); exit 1 }}; $client.EndConnect($async) | Out-Null; $client.Close(); exit 0 }} catch {{ [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }}"
            ),
        ]
    }

    #[cfg(not(windows))]
    {
        let script = r#"import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(float(sys.argv[3]) / 1000.0)
try:
    sock.connect((sys.argv[1], int(sys.argv[2])))
    sys.exit(0)
except Exception:
    sys.exit(1)
finally:
    sock.close()
"#;
        vec![
            "python3".to_string(),
            "-c".to_string(),
            script.to_string(),
            host.to_string(),
            port.to_string(),
            timeout_ms.to_string(),
        ]
    }
}

pub fn listen_command(host: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        let escaped_host = host.replace('\'', "''");
        vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            format!(
                "try {{ $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('{escaped_host}'), 0); $listener.Start(); $listener.Stop(); exit 0 }} catch {{ [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }}"
            ),
        ]
    }

    #[cfg(not(windows))]
    {
        let script = r#"import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    sock.bind((sys.argv[1], 0))
    sock.listen(1)
    sys.exit(0)
except Exception:
    sys.exit(1)
finally:
    sock.close()
"#;
        vec![
            "python3".to_string(),
            "-c".to_string(),
            script.to_string(),
            host.to_string(),
        ]
    }
}

pub fn execute_case(
    manager: &SandboxManager,
    request: &SandboxCommandRequest,
    policy: &SandboxPolicy,
    context: &str,
) -> SandboxExecOutput {
    manager
        .execute(request, policy)
        .unwrap_or_else(|error| panic!("{context}: manager execution failed: {error:?}"))
}

pub fn assert_success(output: &SandboxExecOutput, context: &str) {
    if output.exit_code != 0 {
        let sandbox_excerpt = macos_recent_sandbox_log_excerpt();
        assert_eq!(
            output.exit_code, 0,
            "{context}: expected success, stdout: {}, stderr: {}, sandbox_log: {}",
            output.stdout, output.stderr, sandbox_excerpt
        );
    }
}

pub fn assert_failure(output: &SandboxExecOutput, context: &str) {
    assert_ne!(
        output.exit_code, 0,
        "{context}: expected failure but command succeeded"
    );
}

pub fn should_skip_windows_wfp_unavailable(
    result: &Result<SandboxExecOutput, SandboxError>,
) -> bool {
    #[cfg(windows)]
    {
        matches!(
            result,
            Err(SandboxError::Windows(message))
                if message.contains("FwpmEngineOpen0 failed: 50")
        )
    }

    #[cfg(not(windows))]
    {
        let _ = result;
        false
    }
}

pub fn path_arg(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

pub fn normalize_path(path: &Path) -> PathBuf {
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

fn escape_powershell_single_quoted(path: &Path) -> String {
    path_arg(path).replace('\'', "''")
}

fn macos_recent_sandbox_log_excerpt() -> String {
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("log")
            .args([
                "show",
                "--style",
                "compact",
                "--last",
                "2m",
                "--predicate",
                r#"subsystem == "com.apple.sandbox" OR eventMessage CONTAINS[c] "deny""#,
            ])
            .output();

        match output {
            Ok(output) if output.status.success() => {
                let text = String::from_utf8_lossy(&output.stdout);
                let lines = text
                    .lines()
                    .rev()
                    .take(12)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>();
                if lines.is_empty() {
                    "<no macOS sandbox log entries>".to_string()
                } else {
                    lines.join(" | ")
                }
            }
            Ok(output) => format!(
                "<log show failed: status={:?}, stderr={}>",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => format!("<log show unavailable: {error}>"),
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        String::new()
    }
}

pub fn spawn_accept_probe(listener: TcpListener, timeout: Duration) -> mpsc::Receiver<bool> {
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

pub fn spawn_http_probe(listener: TcpListener, timeout: Duration) -> mpsc::Receiver<bool> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = listener.set_nonblocking(true);
        let start = Instant::now();
        let mut accepted = false;
        while start.elapsed() < timeout {
            match listener.accept() {
                Ok((mut stream, _addr)) => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                    let _ = stream.flush();
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
