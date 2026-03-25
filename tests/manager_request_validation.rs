use std::collections::HashMap;
use std::path::PathBuf;

use procwarden::{SandboxCommandRequest, SandboxError, SandboxManager, SandboxPolicy};

fn workspace() -> PathBuf {
    std::env::current_dir().expect("current directory should be available")
}

#[test]
fn rejects_empty_command_vector() {
    let cwd = workspace();
    let request = SandboxCommandRequest {
        command: Vec::new(),
        cwd: cwd.clone(),
        env: HashMap::new(),
        timeout_ms: Some(100),
    };

    let manager = SandboxManager::new();
    let error = manager
        .execute(&request, &SandboxPolicy::default())
        .expect_err("empty command should be rejected");

    assert!(matches!(error, SandboxError::InvalidRequest(_)));
}

#[test]
fn rejects_blank_executable_token() {
    let cwd = workspace();
    let request = SandboxCommandRequest {
        command: vec!["   ".to_string()],
        cwd: cwd.clone(),
        env: HashMap::new(),
        timeout_ms: Some(100),
    };

    let manager = SandboxManager::new();
    let error = manager
        .execute(&request, &SandboxPolicy::default())
        .expect_err("blank executable should be rejected");

    assert!(matches!(error, SandboxError::InvalidRequest(_)));
}

#[test]
fn rejects_nonexistent_cwd_before_platform_dispatch() {
    let cwd = workspace().join("definitely-missing-cwd-for-procwarden-tests");
    let request = SandboxCommandRequest {
        command: vec!["echo".to_string(), "ok".to_string()],
        cwd: cwd.clone(),
        env: HashMap::new(),
        timeout_ms: Some(100),
    };

    let manager = SandboxManager::new();
    let error = manager
        .execute(&request, &SandboxPolicy::default())
        .expect_err("missing cwd should be rejected");

    assert!(matches!(error, SandboxError::InvalidRequest(_)));
}
