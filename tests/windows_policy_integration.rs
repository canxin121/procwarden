#![cfg(windows)]

use std::collections::HashMap;
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use procwarden::{
    SandboxAccess, SandboxCommandRequest, SandboxManager, SandboxPathPermission, SandboxPolicy,
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

fn base_request(cwd: &Path) -> SandboxCommandRequest {
    SandboxCommandRequest {
        command: vec!["cmd".to_string(), "/C".to_string(), "exit 0".to_string()],
        cwd: cwd.to_path_buf(),
        env: HashMap::new(),
        timeout_ms: Some(10_000),
    }
}

fn powershell_set_content_request(cwd: &Path, target: &Path, value: &str) -> SandboxCommandRequest {
    let escaped_target = target.to_string_lossy().replace('\'', "''");
    let escaped_value = value.replace('\'', "''");
    SandboxCommandRequest {
        command: vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            format!(
                "try {{ [System.IO.File]::WriteAllText('{escaped_target}', '{escaped_value}'); exit 0 }} catch {{ exit 1 }}"
            ),
        ],
        cwd: cwd.to_path_buf(),
        env: HashMap::new(),
        timeout_ms: Some(10_000),
    }
}

fn loopback_connect_request(cwd: &Path, port: u16) -> SandboxCommandRequest {
    SandboxCommandRequest {
        command: vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            format!(
                "$client = New-Object System.Net.Sockets.TcpClient; try {{ $client.Connect('127.0.0.1', {port}); exit 0 }} catch {{ exit 1 }} finally {{ if ($client) {{ $client.Dispose() }} }}"
            ),
        ],
        cwd: cwd.to_path_buf(),
        env: HashMap::new(),
        timeout_ms: Some(10_000),
    }
}

fn loopback_policy(network_access: bool) -> SandboxPolicy {
    SandboxPolicy {
        path_permissions: Vec::new(),
        default_access: SandboxAccess::ReadWrite,
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
fn windows_executes_with_explicit_allowlists() {
    let workspace = temp_workspace("appcontainer-strong");
    let manager = SandboxManager::new();
    let request = base_request(&workspace);

    let policy = SandboxPolicy {
        path_permissions: vec![
            SandboxPathPermission::read_only(workspace.clone()),
            SandboxPathPermission::read_write(workspace.clone()),
        ],
        default_access: SandboxAccess::NoAccess,
        network_access: true,
    };

    let output = match manager.execute(&request, &policy) {
        Ok(value) => value,
        Err(procwarden::SandboxError::Windows(message))
            if message.contains("UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)") =>
        {
            let _ = std::fs::remove_dir_all(&workspace);
            return;
        }
        Err(other) => panic!("unexpected execution error: {other:?}"),
    };

    assert_eq!(output.exit_code, 0);
    assert!(!output.timed_out);
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn windows_read_only_paths_reject_writes_while_read_write_paths_allow_them() {
    let workspace = temp_workspace("ro-rw-write");
    let readonly_dir = workspace.join("readonly");
    let readwrite_dir = workspace.join("readwrite");
    std::fs::create_dir_all(&readonly_dir).expect("readonly directory should be created");
    std::fs::create_dir_all(&readwrite_dir).expect("readwrite directory should be created");

    let manager = SandboxManager::new();
    let policy = SandboxPolicy {
        path_permissions: vec![
            SandboxPathPermission::read_only(workspace.clone()),
            SandboxPathPermission::read_only(readonly_dir.clone()),
            SandboxPathPermission::read_write(readwrite_dir.clone()),
        ],
        default_access: SandboxAccess::NoAccess,
        network_access: true,
    };

    let readonly_target = readonly_dir.join("blocked.txt");
    let readonly_request = powershell_set_content_request(&workspace, &readonly_target, "blocked");

    let readonly_output = match manager.execute(&readonly_request, &policy) {
        Ok(value) => value,
        Err(procwarden::SandboxError::Windows(message))
            if message.contains("UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)") =>
        {
            let _ = std::fs::remove_dir_all(&workspace);
            return;
        }
        Err(other) => panic!("unexpected readonly execution error: {other:?}"),
    };

    assert_ne!(
        readonly_output.exit_code, 0,
        "write into read-only path should fail"
    );
    assert!(
        !readonly_target.exists(),
        "read-only target should not be created"
    );

    let readwrite_target = readwrite_dir.join("allowed.txt");
    let readwrite_request =
        powershell_set_content_request(&workspace, &readwrite_target, "allowed");
    let readwrite_output = match manager.execute(&readwrite_request, &policy) {
        Ok(value) => value,
        Err(other) => panic!("unexpected readwrite execution error: {other:?}"),
    };

    assert_eq!(
        readwrite_output.exit_code, 0,
        "read-write path should allow write; stdout: {}; stderr: {}",
        readwrite_output.stdout, readwrite_output.stderr
    );
    assert!(
        readwrite_target.exists(),
        "read-write target should be created"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn windows_nonexistent_allow_path_is_blocked() {
    let workspace = temp_workspace("namespace-block");
    let manager = SandboxManager::new();
    let request = base_request(&workspace);

    let policy = SandboxPolicy {
        path_permissions: vec![SandboxPathPermission::read_write(
            workspace.join("definitely-missing-allow-path"),
        )],
        default_access: SandboxAccess::NoAccess,
        network_access: false,
    };

    let result = manager.execute(&request, &policy);
    assert!(result.is_err(), "nonexistent allow path should be blocked");

    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn windows_readwrite_default_respects_readonly_overlay_for_writes() {
    let workspace = temp_workspace("rw-default-readonly-overlay");
    let readonly_dir = workspace.join("readonly-overlay");
    let readwrite_dir = workspace.join("readwrite-overlay");
    std::fs::create_dir_all(&readonly_dir).expect("readonly overlay directory should be created");
    std::fs::create_dir_all(&readwrite_dir).expect("readwrite overlay directory should be created");

    let manager = SandboxManager::new();
    let policy = SandboxPolicy {
        path_permissions: vec![
            SandboxPathPermission::read_only(readonly_dir.clone()),
            SandboxPathPermission::read_write(readwrite_dir.clone()),
        ],
        default_access: SandboxAccess::ReadWrite,
        network_access: true,
    };

    let readonly_target = readonly_dir.join("blocked-rw-default.txt");
    let readonly_output = match manager.execute(
        &powershell_set_content_request(&workspace, &readonly_target, "blocked"),
        &policy,
    ) {
        Ok(value) => value,
        Err(procwarden::SandboxError::Windows(message))
            if message.contains("UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)") =>
        {
            let _ = std::fs::remove_dir_all(&workspace);
            return;
        }
        Err(other) => panic!("unexpected readonly-overlay execution error: {other:?}"),
    };

    assert_ne!(
        readonly_output.exit_code, 0,
        "read-only overlay must deny writes under default_access=ReadWrite"
    );
    assert!(
        !readonly_target.exists(),
        "readonly overlay target should not be created"
    );

    let readwrite_target = readwrite_dir.join("allowed-rw-default.txt");
    let readwrite_output = manager
        .execute(
            &powershell_set_content_request(&workspace, &readwrite_target, "allowed"),
            &policy,
        )
        .expect("readwrite overlay should allow write under default_access=ReadWrite");

    assert_eq!(
        readwrite_output.exit_code, 0,
        "readwrite overlay write should succeed; stdout: {}; stderr: {}",
        readwrite_output.stdout, readwrite_output.stderr
    );
    assert!(
        readwrite_target.exists(),
        "readwrite overlay target should be created"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn windows_network_disabled_blocks_loopback_when_enabled_baseline_works() {
    let workspace = temp_workspace("network-loopback");
    let manager = SandboxManager::new();

    let allow_listener = TcpListener::bind(("127.0.0.1", 0)).expect("allow listener should bind");
    let allow_port = allow_listener
        .local_addr()
        .expect("allow listener addr should resolve")
        .port();
    let allow_accepted_rx = spawn_accept_probe(allow_listener, Duration::from_secs(2));

    let allow_output = match manager.execute(
        &loopback_connect_request(&workspace, allow_port),
        &loopback_policy(true),
    ) {
        Ok(value) => value,
        Err(procwarden::SandboxError::Windows(message))
            if message.contains("UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)") =>
        {
            let _ = std::fs::remove_dir_all(&workspace);
            return;
        }
        Err(procwarden::SandboxError::InvalidRequest(message))
            if message.contains("unable to resolve executable") =>
        {
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
        &loopback_connect_request(&workspace, deny_port),
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
        Err(procwarden::SandboxError::Denied(message))
            if message.contains("requires privileges to install temporary WFP filters") => {}
        Err(other) => panic!("unexpected network-deny execution result: {other:?}"),
    }

    assert!(
        !deny_accepted,
        "listener should not receive a connection when network is disabled"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
