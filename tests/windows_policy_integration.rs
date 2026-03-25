#![cfg(windows)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
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

fn command_request(cwd: &Path, script: String) -> SandboxCommandRequest {
    SandboxCommandRequest {
        command: vec!["cmd".to_string(), "/C".to_string(), script],
        cwd: cwd.to_path_buf(),
        env: HashMap::new(),
        timeout_ms: Some(10_000),
    }
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
        global_access: SandboxAccess::NoAccess,
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
        global_access: SandboxAccess::NoAccess,
        network_access: true,
    };

    let readonly_target = readonly_dir.join("blocked.txt");
    let readonly_request = command_request(
        &workspace,
        format!("echo blocked>\"{}\"", readonly_target.to_string_lossy()),
    );

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
    let readwrite_request = command_request(
        &workspace,
        format!("echo allowed>\"{}\"", readwrite_target.to_string_lossy()),
    );
    let readwrite_output = manager
        .execute(&readwrite_request, &policy)
        .expect("read-write path write should execute");

    assert_eq!(
        readwrite_output.exit_code, 0,
        "read-write path should allow write"
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
        global_access: SandboxAccess::NoAccess,
        network_access: false,
    };

    let result = manager.execute(&request, &policy);
    assert!(result.is_err(), "nonexistent allow path should be blocked");

    let _ = std::fs::remove_dir_all(&workspace);
}
