use std::collections::HashMap;
use std::path::PathBuf;

use procwarden::{
    SandboxCommandRequest, SandboxError, SandboxManager, SandboxPathPermission, SandboxPolicy,
};

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

#[test]
fn rejects_nonexistent_allow_path_before_platform_dispatch() {
    let cwd = workspace();
    let missing_allow_path = cwd.join("definitely-missing-allow-path-for-procwarden-tests");
    let request = SandboxCommandRequest {
        command: vec!["definitely-not-executed".to_string()],
        cwd,
        env: HashMap::new(),
        timeout_ms: Some(100),
    };
    let policy = SandboxPolicy {
        path_permissions: vec![SandboxPathPermission::read_write(
            missing_allow_path.clone(),
        )],
        ..SandboxPolicy::default()
    };

    let manager = SandboxManager::new();
    let error = manager
        .execute(&request, &policy)
        .expect_err("missing allow path should be rejected");

    let message = match error {
        SandboxError::InvalidRequest(message) => message,
        other => panic!("expected InvalidRequest, got {other:?}"),
    };
    assert!(message.contains("allow path does not exist"));
    assert!(message.contains("definitely-missing-allow-path-for-procwarden-tests"));
}

#[test]
fn rejects_empty_allow_path_before_platform_dispatch() {
    let request = SandboxCommandRequest {
        command: vec!["definitely-not-executed".to_string()],
        cwd: workspace(),
        env: HashMap::new(),
        timeout_ms: Some(100),
    };
    let policy = SandboxPolicy {
        path_permissions: vec![SandboxPathPermission::read_only("")],
        ..SandboxPolicy::default()
    };

    let manager = SandboxManager::new();
    let error = manager
        .execute(&request, &policy)
        .expect_err("empty allow path should be rejected");

    let message = match error {
        SandboxError::InvalidRequest(message) => message,
        other => panic!("expected InvalidRequest, got {other:?}"),
    };
    assert!(message.contains("allow path must not be empty"));
}
