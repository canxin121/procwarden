use std::collections::HashMap;
use std::path::PathBuf;

use super::{SandboxAccess, SandboxError, SandboxExecOutput, SandboxPolicy, cap_fs, platform};

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
        validate_policy_allow_paths(policy)?;
        let sanitized = request.sanitized_for_execution();
        platform::execute(&sanitized, policy)
    }
}

fn validate_policy_allow_paths(policy: &SandboxPolicy) -> Result<(), SandboxError> {
    for permission in &policy.path_permissions {
        if !matches!(
            permission.access,
            SandboxAccess::ReadOnly | SandboxAccess::ReadWrite
        ) {
            continue;
        }

        if permission.path.as_os_str().is_empty() {
            return Err(SandboxError::InvalidRequest(
                "allow path must not be empty".to_string(),
            ));
        }

        if !cap_fs::path_exists(&permission.path) {
            return Err(SandboxError::InvalidRequest(format!(
                "allow path does not exist: {}",
                permission.path.display()
            )));
        }
    }

    Ok(())
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
