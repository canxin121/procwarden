#![cfg(target_os = "macos")]

use std::collections::HashMap;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use procwarden::{
    SandboxAccess, SandboxCommandRequest, SandboxError, SandboxManager, SandboxPolicy,
};

fn temp_workspace(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be monotonic")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("procwarden-it-{prefix}-{nonce}"));
    std::fs::create_dir_all(&dir).expect("temp workspace should be created");
    dir
}

fn python3_path() -> Option<String> {
    [
        "/usr/bin/python3",
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
    ]
    .iter()
    .find(|path| Path::new(path).is_file())
    .map(|path| (*path).to_string())
}

fn loopback_connect_request(cwd: &Path, python3: &str, port: u16) -> SandboxCommandRequest {
    SandboxCommandRequest {
        command: vec![
            python3.to_string(),
            "-c".to_string(),
            "import socket,sys; s=socket.socket(); s.settimeout(1.0); s.connect(('127.0.0.1', int(sys.argv[1]))); s.close()"
                .to_string(),
            port.to_string(),
        ],
        cwd: cwd.to_path_buf(),
        env: HashMap::new(),
        timeout_ms: Some(10_000),
    }
}

fn loopback_policy(network_access: bool) -> SandboxPolicy {
    SandboxPolicy {
        path_permissions: Vec::new(),
        global_access: SandboxAccess::ReadWrite,
        network_access,
    }
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

#[test]
fn macos_network_disabled_blocks_loopback_when_enabled_baseline_works() {
    let Some(python3) = python3_path() else {
        return;
    };

    let workspace = temp_workspace("macos-network-loopback");
    let manager = SandboxManager::new();

    let allow_listener = TcpListener::bind(("127.0.0.1", 0)).expect("allow listener should bind");
    let allow_port = allow_listener
        .local_addr()
        .expect("allow listener addr should resolve")
        .port();
    let allow_accepted_rx = spawn_accept_probe(allow_listener, Duration::from_secs(2));

    let allow_output = match manager.execute(
        &loopback_connect_request(&workspace, &python3, allow_port),
        &loopback_policy(true),
    ) {
        Ok(value) => value,
        Err(SandboxError::Unavailable(_)) => {
            let _ = std::fs::remove_dir_all(&workspace);
            return;
        }
        Err(other) => panic!("unexpected network-allow execution error: {other:?}"),
    };

    let allow_accepted = allow_accepted_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or(false);
    if allow_output.exit_code != 0 || !allow_accepted {
        eprintln!(
            "skipping deny assertion: enabled baseline cannot reach loopback in this environment"
        );
        let _ = std::fs::remove_dir_all(&workspace);
        return;
    }

    let deny_listener = TcpListener::bind(("127.0.0.1", 0)).expect("deny listener should bind");
    let deny_port = deny_listener
        .local_addr()
        .expect("deny listener addr should resolve")
        .port();
    let deny_accepted_rx = spawn_accept_probe(deny_listener, Duration::from_secs(2));

    let deny_result = manager.execute(
        &loopback_connect_request(&workspace, &python3, deny_port),
        &loopback_policy(false),
    );
    let deny_accepted = deny_accepted_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or(false);

    match deny_result {
        Ok(output) => {
            assert_ne!(
                output.exit_code, 0,
                "network-disabled policy should reject loopback TCP connect"
            );
        }
        Err(SandboxError::Denied(_)) | Err(SandboxError::Unavailable(_)) => {}
        Err(other) => panic!("unexpected network-deny execution result: {other:?}"),
    }

    assert!(
        !deny_accepted,
        "listener should not receive a connection when network is disabled"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
