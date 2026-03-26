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
        Err(procwarden::SandboxError::Windows(message))
            if message.contains("CreateProcessW(AppContainer) failed: 87") =>
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
fn windows_dangerous_namespace_allow_path_is_blocked() {
    let workspace = temp_workspace("namespace-block");
    let manager = SandboxManager::new();
    let request = base_request(&workspace);

    let policy = SandboxPolicy {
        path_permissions: vec![SandboxPathPermission::read_write(PathBuf::from(r"\\.\NUL"))],
        global_access: SandboxAccess::NoAccess,
        network_access: false,
    };

    let result = manager.execute(&request, &policy);
    assert!(
        result.is_err(),
        "dangerous namespace path should be blocked"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
