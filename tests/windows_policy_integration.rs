#![cfg(windows)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use procwarden::{
    DegradeReasonCode, EnforcementStrength, SandboxCommandRequest, SandboxManager, SandboxPolicy,
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
fn windows_reports_strong_enforcement_for_allowlists() {
    let workspace = temp_workspace("appcontainer-strong");
    let manager = SandboxManager::new();
    let request = base_request(&workspace);

    let policy = SandboxPolicy::new_custom_policy()
        .with_additional_readable_roots([workspace.clone()])
        .with_additional_writable_roots([workspace.clone()])
        .with_world_writable_audit(false);

    let output = match manager.execute(&request, &policy, &workspace) {
        Ok(value) => value,
        Err(procwarden::SandboxError::Windows(message))
            if message.contains("UpdateProcThreadAttribute(CHILD_PROCESS_POLICY)") =>
        {
            let _ = std::fs::remove_dir_all(&workspace);
            return;
        }
        Err(other) => panic!("unexpected execution error: {other:?}"),
    };

    assert_eq!(output.enforcement.backend, "windows-appcontainer");
    assert!(output.enforcement.read_allowlist_enforced);
    assert!(output.enforcement.write_allowlist_enforced);
    assert_eq!(
        output.enforcement.effective_read_enforcement,
        EnforcementStrength::Strong
    );
    assert_eq!(
        output.enforcement.effective_write_enforcement,
        EnforcementStrength::Strong
    );
    assert!(output.enforcement.network_restricted);
    match output.enforcement.effective_network_enforcement {
        EnforcementStrength::Strong => {}
        EnforcementStrength::BestEffort => {
            assert!(
                output
                    .enforcement
                    .degraded_reason_codes
                    .contains(&DegradeReasonCode::WindowsLoopbackExemptionDetected)
                    || output
                        .enforcement
                        .degraded_reason_codes
                        .contains(&DegradeReasonCode::WindowsLoopbackExemptionCheckFailed),
            );
        }
        EnforcementStrength::None => panic!("network enforcement should not be none"),
    }
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn windows_dangerous_namespace_allow_path_is_blocked() {
    let workspace = temp_workspace("namespace-block");
    let manager = SandboxManager::new();
    let request = base_request(&workspace);

    let policy = SandboxPolicy::new_custom_policy()
        .with_additional_writable_roots([PathBuf::from(r"\\.\NUL")])
        .with_reparse_point_rejection(false);

    let result = manager.execute(&request, &policy, &workspace);
    assert!(
        result.is_err(),
        "dangerous namespace path should be blocked"
    );

    let _ = std::fs::remove_dir_all(&workspace);
}
