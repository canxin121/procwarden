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
    let dir = std::env::temp_dir().join(format!("procwarden-manual-{prefix}-{nonce}"));
    std::fs::create_dir_all(&dir).expect("temp workspace should be created");
    dir
}

fn base_request(cwd: &Path) -> SandboxCommandRequest {
    SandboxCommandRequest {
        command: vec!["cmd".to_string(), "/C".to_string(), "exit 0".to_string()],
        cwd: cwd.to_path_buf(),
        env: HashMap::new(),
        timeout_ms: Some(15_000),
    }
}

#[test]
#[ignore = "requires interactive UAC consent"]
fn windows_auto_elevation_succeeds_when_user_confirms_uac() {
    let workspace = temp_workspace("uac-flow");
    let manager = SandboxManager::new();
    let request = base_request(&workspace);

    let policy = SandboxPolicy {
        path_permissions: vec![
            SandboxPathPermission::read_only(workspace.clone()),
            SandboxPathPermission::read_write(workspace.clone()),
        ],
        default_access: SandboxAccess::NoAccess,
        network_access: false,
    };

    println!(
        "manual check: if current process is not elevated, Windows should now show a UAC prompt"
    );

    let result = manager.execute(&request, &policy);
    assert!(
        result.is_ok(),
        "expected auto-elevation flow to succeed after UAC consent, got: {result:?}"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
