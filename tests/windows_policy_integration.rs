#![cfg(windows)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use procwarden::{
    ChildProcessCoverage, DegradeReasonCode, FailStrategy, SandboxCommandRequest, SandboxError,
    SandboxManager, SandboxPolicy, WindowsEnforcementLevel,
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

fn base_request(cwd: &PathBuf) -> SandboxCommandRequest {
    SandboxCommandRequest {
        command: vec!["cmd".to_string(), "/C".to_string(), "exit 0".to_string()],
        cwd: cwd.clone(),
        env: HashMap::new(),
        timeout_ms: Some(10_000),
    }
}

#[test]
fn windows_fail_closed_rejects_read_allowlist_on_compat_backend() {
    let workspace = temp_workspace("fail-closed");
    let manager = SandboxManager::new();
    let request = base_request(&workspace);

    let policy = SandboxPolicy::new_custom_policy()
        .with_additional_readable_roots([workspace.clone()])
        .with_windows_enforcement(WindowsEnforcementLevel::CompatAclTokenJob)
        .with_fail_strategy(FailStrategy::FailClosed);

    let result = manager.execute(&request, &policy, &workspace);
    match result {
        Err(SandboxError::Unavailable(message)) => {
            assert!(message.contains("cannot enforce read allowlists"));
        }
        other => panic!("expected unavailable error, got: {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn windows_fail_open_reports_degraded_read_enforcement_and_child_coverage() {
    let workspace = temp_workspace("fail-open");
    let manager = SandboxManager::new();
    let request = base_request(&workspace);

    let policy = SandboxPolicy::new_custom_policy()
        .with_additional_readable_roots([workspace.clone()])
        .with_additional_writable_roots([workspace.clone()])
        .with_windows_enforcement(WindowsEnforcementLevel::CompatAclTokenJob)
        .with_fail_strategy(FailStrategy::FailOpenWithReport)
        .with_world_writable_audit(false);

    let output = match manager.execute(&request, &policy, &workspace) {
        Ok(value) => value,
        Err(SandboxError::Windows(message))
            if message.contains("UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)") =>
        {
            let _ = std::fs::remove_dir_all(&workspace);
            return;
        }
        Err(other) => panic!("unexpected execution error: {other:?}"),
    };

    assert!(!output.enforcement.read_allowlist_enforced);
    assert!(
        output
            .enforcement
            .degraded_reason_codes
            .contains(&DegradeReasonCode::CompatReadAllowlistBestEffort)
    );
    assert!(
        output
            .enforcement
            .degraded_reason_codes
            .contains(&DegradeReasonCode::FailOpenDegraded)
    );
    assert_eq!(
        output.enforcement.child_process_coverage,
        ChildProcessCoverage::RestrictedAndJob
    );

    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn windows_dangerous_namespace_allow_path_is_blocked() {
    let workspace = temp_workspace("namespace-block");
    let manager = SandboxManager::new();
    let request = base_request(&workspace);

    let policy = SandboxPolicy::new_custom_policy()
        .with_additional_writable_roots([PathBuf::from(r"\\.\NUL")])
        .with_windows_enforcement(WindowsEnforcementLevel::CompatAclTokenJob)
        .with_fail_strategy(FailStrategy::FailOpenWithReport)
        .with_reparse_point_rejection(false);

    let result = manager.execute(&request, &policy, &workspace);
    assert!(
        result.is_err(),
        "dangerous namespace path should be blocked"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
