use crate::{
    SandboxAccess, SandboxCommandRequest, SandboxError, SandboxPathPermission, SandboxPolicy,
};
use std::collections::HashMap;

use super::{MACOS_SANDBOX_EXEC_ENV, build_sbpl_profile, execute};

#[test]
fn profile_contains_network_deny_when_disabled() {
    let profile = build_sbpl_profile(&SandboxPolicy {
        network_access: false,
        ..SandboxPolicy::default()
    });

    assert!(profile.contains("(deny network*)"));
}

#[test]
fn profile_readonly_allows_rw_paths_before_global_write_deny() {
    let policy = SandboxPolicy {
        path_permissions: vec![SandboxPathPermission::read_write("/tmp/w")],
        global_access: SandboxAccess::ReadOnly,
        network_access: true,
    };
    let profile = build_sbpl_profile(&policy);

    let allow_pos = profile
        .find("(allow file-write* (subpath \"/tmp/w\"))")
        .expect("rw carve-out should be present");
    let deny_pos = profile
        .find("(deny file-write*)")
        .expect("global write deny should be present");

    assert!(
        allow_pos < deny_pos,
        "allow carve-out must appear before fallback deny"
    );
}

#[test]
fn profile_noaccess_adds_read_write_fallback_denies() {
    let policy = SandboxPolicy {
        path_permissions: vec![
            SandboxPathPermission::read_only("/tmp/ro"),
            SandboxPathPermission::read_write("/tmp/rw"),
            SandboxPathPermission::deny("/tmp/no"),
        ],
        global_access: SandboxAccess::NoAccess,
        network_access: true,
    };
    let profile = build_sbpl_profile(&policy);

    assert!(profile.contains("(allow file-read* (subpath \"/tmp/ro\"))"));
    assert!(profile.contains("(allow file-write* (subpath \"/tmp/rw\"))"));
    assert!(profile.contains("(deny file-read*)"));
    assert!(profile.contains("(deny file-write*)"));
    assert!(profile.contains("(deny file-read* (subpath \"/tmp/no\"))"));
}

#[test]
fn execute_fails_closed_when_sandbox_executable_is_missing() {
    let _guard = EnvVarGuard::set(
        MACOS_SANDBOX_EXEC_ENV,
        "/definitely/not/installed/sandbox-exec",
    );
    let cwd = std::env::temp_dir();
    let request = SandboxCommandRequest {
        command: vec!["true".to_string()],
        cwd: cwd.clone(),
        env: HashMap::new(),
        timeout_ms: Some(100),
    };

    let result = execute(&request, &SandboxPolicy::default());
    let message = match result {
        Err(SandboxError::Unavailable(message)) => message,
        other => panic!("expected unavailable error, got {other:?}"),
    };
    assert!(message.contains(MACOS_SANDBOX_EXEC_ENV));
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            unsafe {
                std::env::set_var(self.key, previous);
            }
        } else {
            unsafe {
                std::env::remove_var(self.key);
            }
        }
    }
}
