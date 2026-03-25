use std::collections::HashMap;
use std::path::PathBuf;

use super::{SandboxCommandRequest, sanitize_env_vars, starts_with_ascii_case_insensitive};

#[test]
fn strips_loader_and_shell_injection_env_when_sandboxed() {
    let mut env = HashMap::new();
    env.insert("PATH".to_string(), "/usr/bin".to_string());
    env.insert("LD_PRELOAD".to_string(), "evil.so".to_string());
    env.insert(
        "DYLD_INSERT_LIBRARIES".to_string(),
        "evil.dylib".to_string(),
    );
    env.insert("BASH_ENV".to_string(), "/tmp/rc".to_string());

    let sanitized = sanitize_env_vars(&env);

    assert!(sanitized.contains_key("PATH"));
    assert!(!sanitized.contains_key("LD_PRELOAD"));
    assert!(!sanitized.contains_key("DYLD_INSERT_LIBRARIES"));
    assert!(!sanitized.contains_key("BASH_ENV"));
}

#[test]
fn strips_blocked_prefixes_case_insensitively() {
    let mut env = HashMap::new();
    env.insert(
        "dyld_insert_libraries".to_string(),
        "evil.dylib".to_string(),
    );
    env.insert("Ld_PreLoAd".to_string(), "evil.so".to_string());
    env.insert("BaSh_FuNc_x".to_string(), "() { :; }".to_string());
    env.insert("SAFE_VAR".to_string(), "1".to_string());

    let sanitized = sanitize_env_vars(&env);

    assert!(!sanitized.contains_key("dyld_insert_libraries"));
    assert!(!sanitized.contains_key("Ld_PreLoAd"));
    assert!(!sanitized.contains_key("BaSh_FuNc_x"));
    assert_eq!(sanitized.get("SAFE_VAR"), Some(&"1".to_string()));
}

#[test]
fn request_sanitization_preserves_non_env_fields() {
    let mut env = HashMap::new();
    env.insert("PATH".to_string(), "/usr/bin".to_string());
    env.insert("LD_PRELOAD".to_string(), "evil.so".to_string());
    let request = SandboxCommandRequest {
        command: vec!["echo".to_string(), "hello".to_string()],
        cwd: PathBuf::from("/tmp"),
        env,
        timeout_ms: Some(1234),
    };

    let sanitized = request.sanitized_for_execution();
    assert_eq!(sanitized.command, request.command);
    assert_eq!(sanitized.cwd, request.cwd);
    assert_eq!(sanitized.timeout_ms, request.timeout_ms);
    assert_eq!(sanitized.env.get("PATH"), Some(&"/usr/bin".to_string()));
    assert!(!sanitized.env.contains_key("LD_PRELOAD"));
}

#[test]
fn blocks_exact_loader_keys_case_insensitively() {
    let mut env = HashMap::new();
    env.insert("ld_library_path".to_string(), "/tmp/lib".to_string());
    env.insert("Ld_AuDiT".to_string(), "evil.so".to_string());

    let sanitized = sanitize_env_vars(&env);

    assert!(!sanitized.contains_key("ld_library_path"));
    assert!(!sanitized.contains_key("Ld_AuDiT"));
}

#[test]
fn prefix_check_rejects_shorter_candidate_without_panicking() {
    assert!(!starts_with_ascii_case_insensitive("LD", "LD_PRE"));
    assert!(starts_with_ascii_case_insensitive("DyLd_Value", "DYLD_"));
}

#[test]
fn data_driven_blocked_keys_and_prefixes_are_removed() {
    let blocked_keys = [
        "LD_PRELOAD",
        "ld_library_path",
        "Ld_AuDiT",
        "DYLD_INSERT_LIBRARIES",
        "dyld_anything",
        "BASH_FUNC_payload",
        "bash_func_payload",
        "ENV",
        "bash_env",
    ];

    for blocked in blocked_keys {
        let mut env = HashMap::new();
        env.insert(blocked.to_string(), "evil".to_string());
        env.insert("SAFE_KEY".to_string(), "ok".to_string());

        let sanitized = sanitize_env_vars(&env);
        assert!(
            !sanitized.contains_key(blocked),
            "blocked key should be removed: {blocked}"
        );
        assert_eq!(sanitized.get("SAFE_KEY"), Some(&"ok".to_string()));
    }
}
