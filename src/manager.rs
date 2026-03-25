use std::collections::HashMap;
use std::path::PathBuf;

use super::{SandboxError, SandboxExecOutput, SandboxPolicy, cap_fs, platform};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCommandRequest {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub env: HashMap<String, String>,
    pub timeout_ms: Option<u64>,
}

impl SandboxCommandRequest {
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.command.is_empty() {
            return Err(SandboxError::InvalidRequest(
                "command must contain at least one token".to_string(),
            ));
        }
        if self.command[0].trim().is_empty() {
            return Err(SandboxError::InvalidRequest(
                "command executable must not be empty".to_string(),
            ));
        }
        if !cap_fs::path_exists(&self.cwd) {
            return Err(SandboxError::InvalidRequest(format!(
                "sandbox cwd does not exist: {}",
                self.cwd.display()
            )));
        }
        if !cap_fs::is_dir(&self.cwd) {
            return Err(SandboxError::InvalidRequest(format!(
                "sandbox cwd is not a directory: {}",
                self.cwd.display()
            )));
        }
        Ok(())
    }

    pub(crate) fn sanitized_for_execution(&self) -> Self {
        Self {
            command: self.command.clone(),
            cwd: self.cwd.clone(),
            env: sanitize_env_vars(&self.env),
            timeout_ms: self.timeout_ms,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SandboxManager;

impl SandboxManager {
    pub fn new() -> Self {
        Self
    }

    pub fn execute(
        &self,
        request: &SandboxCommandRequest,
        policy: &SandboxPolicy,
    ) -> Result<SandboxExecOutput, SandboxError> {
        request.validate()?;
        let sanitized = request.sanitized_for_execution();
        platform::execute(&sanitized, policy)
    }
}

fn sanitize_env_vars(env: &HashMap<String, String>) -> HashMap<String, String> {
    const BLOCKED_EXACT: [&str; 5] = [
        "BASH_ENV",
        "ENV",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
    ];
    const BLOCKED_PREFIXES: [&str; 3] = ["DYLD_", "LD_", "BASH_FUNC_"];

    env.iter()
        .filter(|(key, _)| {
            !BLOCKED_EXACT
                .iter()
                .any(|name| key.eq_ignore_ascii_case(name))
                && !BLOCKED_PREFIXES
                    .iter()
                    .any(|prefix| starts_with_ascii_case_insensitive(key, prefix))
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn starts_with_ascii_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use std::collections::HashMap;

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
}
