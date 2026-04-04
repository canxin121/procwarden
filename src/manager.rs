use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use super::{
    SandboxError, SandboxExecOutput, SandboxPathAccess, SandboxPathPermission, SandboxPolicy,
    cap_fs, platform,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxCommandRequest {
    pub command: Vec<String>,
    pub cwd: PathBuf,
    pub env: HashMap<String, String>,
    pub timeout_ms: Option<u64>,
}

impl SandboxCommandRequest {
    pub fn validate(&self) -> Result<(), SandboxError> {
        self.validate_command()?;
        sanitize_existing_dir(&self.cwd, "sandbox cwd").map(|_| ())
    }

    fn validate_command(&self) -> Result<(), SandboxError> {
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
        Ok(())
    }

    pub(crate) fn sanitized_for_execution(&self) -> Result<Self, SandboxError> {
        self.validate_command()?;

        Ok(Self {
            command: self.command.clone(),
            cwd: sanitize_existing_dir(&self.cwd, "sandbox cwd")?,
            env: sanitize_env_vars(&self.env),
            timeout_ms: self.timeout_ms,
        })
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
        let sanitized_request = request.sanitized_for_execution()?;
        let sanitized_policy = sanitize_policy_for_execution(policy)?;
        platform::execute(&sanitized_request, &sanitized_policy)
    }
}

fn sanitize_policy_for_execution(policy: &SandboxPolicy) -> Result<SandboxPolicy, SandboxError> {
    let mut exact_paths: BTreeMap<PathBuf, u8> = BTreeMap::new();

    for permission in &policy.path_permissions {
        let canonical_path = sanitize_policy_path(permission)?;
        let priority = explicit_priority(policy.default_access, permission.access);
        exact_paths
            .entry(canonical_path)
            .and_modify(|current| *current = (*current).max(priority))
            .or_insert(priority);
    }

    let mut path_permissions = exact_paths
        .into_iter()
        .filter_map(|(path, priority)| {
            access_for_priority(policy.default_access, priority)
                .map(|access| SandboxPathPermission { path, access })
        })
        .collect::<Vec<_>>();

    path_permissions.sort_by(|left, right| {
        path_depth(&left.path)
            .cmp(&path_depth(&right.path))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| path_access_key(left.access).cmp(&path_access_key(right.access)))
    });
    reject_reopened_descendants_under_deny(&path_permissions)?;
    path_permissions = prune_same_access_descendants(path_permissions);

    Ok(SandboxPolicy {
        path_permissions,
        default_access: policy.default_access,
        network_mode: policy.network_mode,
    })
}

fn sanitize_policy_path(permission: &SandboxPathPermission) -> Result<PathBuf, SandboxError> {
    let label = path_access_label(permission.access);

    sanitize_existing_path(&permission.path, &format!("{label} path"), true)
}

fn sanitize_existing_dir(path: &std::path::Path, label: &str) -> Result<PathBuf, SandboxError> {
    let canonical = sanitize_existing_path(path, label, false)?;
    if !cap_fs::is_dir(&canonical) {
        return Err(SandboxError::InvalidRequest(format!(
            "{label} is not a directory: {}",
            path.display()
        )));
    }
    Ok(canonical)
}

fn sanitize_existing_path(
    path: &std::path::Path,
    label: &str,
    reject_empty: bool,
) -> Result<PathBuf, SandboxError> {
    if reject_empty && path.as_os_str().is_empty() {
        return Err(SandboxError::InvalidRequest(format!(
            "{label} must not be empty"
        )));
    }

    if !cap_fs::path_exists(path) {
        return Err(SandboxError::InvalidRequest(format!(
            "{label} does not exist: {}",
            path.display()
        )));
    }

    cap_fs::canonicalize_path(path).map_err(|error| {
        SandboxError::InvalidRequest(format!(
            "{label} cannot be canonicalized: {}: {error}",
            path.display()
        ))
    })
}

fn path_access_key(access: SandboxPathAccess) -> u8 {
    match access {
        SandboxPathAccess::Deny => 0,
        SandboxPathAccess::ReadOnly => 1,
        SandboxPathAccess::ReadWrite => 2,
    }
}

fn explicit_priority(default_access: super::SandboxDefaultAccess, access: SandboxPathAccess) -> u8 {
    match (default_access, access) {
        (_, SandboxPathAccess::Deny) => 2,
        (super::SandboxDefaultAccess::ReadOnly, SandboxPathAccess::ReadOnly)
        | (super::SandboxDefaultAccess::ReadWrite, SandboxPathAccess::ReadWrite) => 0,
        (super::SandboxDefaultAccess::ReadOnly, SandboxPathAccess::ReadWrite)
        | (super::SandboxDefaultAccess::ReadWrite, SandboxPathAccess::ReadOnly) => 1,
    }
}

fn access_for_priority(
    default_access: super::SandboxDefaultAccess,
    priority: u8,
) -> Option<SandboxPathAccess> {
    match (default_access, priority) {
        (_, 0) => None,
        (super::SandboxDefaultAccess::ReadOnly, 1) => Some(SandboxPathAccess::ReadWrite),
        (super::SandboxDefaultAccess::ReadWrite, 1) => Some(SandboxPathAccess::ReadOnly),
        (_, 2) => Some(SandboxPathAccess::Deny),
        _ => None,
    }
}

fn prune_same_access_descendants(
    permissions: Vec<SandboxPathPermission>,
) -> Vec<SandboxPathPermission> {
    let mut normalized: Vec<SandboxPathPermission> = Vec::new();

    'candidate: for permission in permissions {
        for existing in &normalized {
            if existing.access == permission.access
                && is_same_or_descendant(&permission.path, &existing.path)
            {
                continue 'candidate;
            }
        }

        normalized.push(permission);
    }

    normalized
}

fn reject_reopened_descendants_under_deny(
    permissions: &[SandboxPathPermission],
) -> Result<(), SandboxError> {
    for permission in permissions {
        if permission.access == SandboxPathAccess::Deny {
            continue;
        }

        if let Some(ancestor) = permissions.iter().find(|existing| {
            existing.access == SandboxPathAccess::Deny
                && existing.path != permission.path
                && is_same_or_descendant(&permission.path, &existing.path)
        }) {
            return Err(SandboxError::InvalidRequest(format!(
                "{} path cannot reopen access under deny ancestor {}: {}",
                path_access_label(permission.access),
                ancestor.path.display(),
                permission.path.display()
            )));
        }
    }

    Ok(())
}

fn path_access_label(access: SandboxPathAccess) -> &'static str {
    match access {
        SandboxPathAccess::Deny => "deny",
        SandboxPathAccess::ReadOnly => "read_only",
        SandboxPathAccess::ReadWrite => "read_write",
    }
}

fn is_same_or_descendant(path: &std::path::Path, ancestor: &std::path::Path) -> bool {
    let path_components = path.components().collect::<Vec<_>>();
    let ancestor_components = ancestor.components().collect::<Vec<_>>();

    if ancestor_components.len() > path_components.len() {
        return false;
    }

    ancestor_components
        .iter()
        .zip(path_components.iter())
        .all(|(left, right)| path_component_eq(left.as_os_str(), right.as_os_str()))
}

fn path_component_eq(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    #[cfg(target_os = "windows")]
    {
        left.to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy())
    }

    #[cfg(not(target_os = "windows"))]
    {
        left == right
    }
}

fn path_depth(path: &std::path::Path) -> usize {
    path.components().count()
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
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::{SandboxDefaultAccess, SandboxNetworkMode, SandboxPathPermission, SandboxPolicy};

    use super::{SandboxError, cap_fs, sanitize_policy_for_execution};

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be monotonic")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "procwarden-manager-tests-{prefix}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("test temp directory should be created");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn policy_paths_are_canonicalized_and_deduped_before_dispatch() {
        let temp = TestTempDir::new("canonicalize-policy-paths");
        let real_path = temp.path().join("real");
        fs::create_dir_all(&real_path).expect("real path should be created");

        let alias_path = temp.path().join("real").join("..").join("real");

        let sanitized = sanitize_policy_for_execution(&SandboxPolicy {
            default_access: SandboxDefaultAccess::ReadOnly,
            network_mode: SandboxNetworkMode::Disabled,
            path_permissions: vec![
                SandboxPathPermission::read_write(alias_path),
                SandboxPathPermission::read_write(real_path.clone()),
            ],
        })
        .expect("policy should sanitize successfully");

        assert_eq!(
            sanitized.path_permissions,
            vec![SandboxPathPermission::read_write(
                cap_fs::canonicalize_path(&real_path).expect("real path should canonicalize")
            )]
        );
    }

    #[test]
    fn missing_policy_paths_fail_frontloaded_validation() {
        let temp = TestTempDir::new("missing-policy-path");
        let missing_path = temp.path().join("missing");

        let error = sanitize_policy_for_execution(&SandboxPolicy {
            default_access: SandboxDefaultAccess::ReadWrite,
            network_mode: SandboxNetworkMode::Disabled,
            path_permissions: vec![SandboxPathPermission::read_only(missing_path.clone())],
        })
        .expect_err("missing path should fail validation");

        match error {
            SandboxError::InvalidRequest(message) => {
                assert!(
                    message.contains("read_only path does not exist"),
                    "unexpected error message: {message}"
                );
                assert!(
                    message.contains(missing_path.to_string_lossy().as_ref()),
                    "error should include the missing path: {message}"
                );
            }
            other => panic!("expected InvalidRequest for missing path, got {other:?}"),
        }
    }

    #[test]
    fn default_readonly_redundant_entries_are_removed_before_dispatch() {
        let temp = TestTempDir::new("readonly-redundant-paths");
        let root = temp.path().join("root");
        let child = root.join("child");
        fs::create_dir_all(&child).expect("test directories should be created");

        let sanitized = sanitize_policy_for_execution(&SandboxPolicy {
            default_access: SandboxDefaultAccess::ReadOnly,
            network_mode: SandboxNetworkMode::Disabled,
            path_permissions: vec![
                SandboxPathPermission::read_only(root.clone()),
                SandboxPathPermission::read_write(root.clone()),
                SandboxPathPermission::read_write(child),
            ],
        })
        .expect("policy should sanitize successfully");

        assert_eq!(
            sanitized.path_permissions,
            vec![SandboxPathPermission::read_write(
                cap_fs::canonicalize_path(&root).expect("root should canonicalize")
            )]
        );
    }

    #[test]
    fn default_readwrite_redundant_entries_are_removed_before_dispatch() {
        let temp = TestTempDir::new("readwrite-redundant-paths");
        let root = temp.path().join("root");
        let child = root.join("child");
        fs::create_dir_all(&child).expect("test directories should be created");

        let sanitized = sanitize_policy_for_execution(&SandboxPolicy {
            default_access: SandboxDefaultAccess::ReadWrite,
            network_mode: SandboxNetworkMode::Disabled,
            path_permissions: vec![
                SandboxPathPermission::read_write(root.clone()),
                SandboxPathPermission::read_only(root.clone()),
                SandboxPathPermission::read_only(child),
            ],
        })
        .expect("policy should sanitize successfully");

        assert_eq!(
            sanitized.path_permissions,
            vec![SandboxPathPermission::read_only(
                cap_fs::canonicalize_path(&root).expect("root should canonicalize")
            )]
        );
    }

    #[test]
    fn conflicting_same_path_entries_collapse_to_effective_overlay_before_dispatch() {
        let temp = TestTempDir::new("conflicting-same-path");
        let path = temp.path().join("target");
        fs::create_dir_all(&path).expect("target path should be created");

        let sanitized = sanitize_policy_for_execution(&SandboxPolicy {
            default_access: SandboxDefaultAccess::ReadWrite,
            network_mode: SandboxNetworkMode::Disabled,
            path_permissions: vec![
                SandboxPathPermission::read_only(path.clone()),
                SandboxPathPermission::read_write(path.clone()),
            ],
        })
        .expect("policy should sanitize successfully");

        assert_eq!(
            sanitized.path_permissions,
            vec![SandboxPathPermission::read_only(
                cap_fs::canonicalize_path(&path).expect("path should canonicalize")
            )]
        );
    }

    #[test]
    fn deny_wins_same_path_conflicts_before_dispatch() {
        let temp = TestTempDir::new("conflicting-same-path-deny");
        let path = temp.path().join("target");
        fs::create_dir_all(&path).expect("target path should be created");

        let sanitized = sanitize_policy_for_execution(&SandboxPolicy {
            default_access: SandboxDefaultAccess::ReadOnly,
            network_mode: SandboxNetworkMode::Disabled,
            path_permissions: vec![
                SandboxPathPermission::read_write(path.clone()),
                SandboxPathPermission::deny(path.clone()),
            ],
        })
        .expect("policy should sanitize successfully");

        assert_eq!(
            sanitized.path_permissions,
            vec![SandboxPathPermission::deny(
                cap_fs::canonicalize_path(&path).expect("path should canonicalize")
            )]
        );
    }

    #[test]
    fn deny_descendants_are_retained_as_more_restrictive_overlays() {
        let temp = TestTempDir::new("deny-descendant");
        let root = temp.path().join("root");
        let child = root.join("child");
        fs::create_dir_all(&child).expect("test directories should be created");

        let sanitized = sanitize_policy_for_execution(&SandboxPolicy {
            default_access: SandboxDefaultAccess::ReadWrite,
            network_mode: SandboxNetworkMode::Disabled,
            path_permissions: vec![
                SandboxPathPermission::read_only(root.clone()),
                SandboxPathPermission::deny(child.clone()),
            ],
        })
        .expect("policy should sanitize successfully");

        assert_eq!(
            sanitized.path_permissions,
            vec![
                SandboxPathPermission::read_only(
                    cap_fs::canonicalize_path(&root).expect("root should canonicalize")
                ),
                SandboxPathPermission::deny(
                    cap_fs::canonicalize_path(&child).expect("child should canonicalize")
                ),
            ]
        );
    }

    #[test]
    fn reopening_inside_deny_fails_closed_before_dispatch() {
        let temp = TestTempDir::new("deny-reopen");
        let root = temp.path().join("root");
        let child = root.join("child");
        fs::create_dir_all(&child).expect("test directories should be created");

        let error = sanitize_policy_for_execution(&SandboxPolicy {
            default_access: SandboxDefaultAccess::ReadOnly,
            network_mode: SandboxNetworkMode::Disabled,
            path_permissions: vec![
                SandboxPathPermission::deny(root.clone()),
                SandboxPathPermission::read_write(child.clone()),
            ],
        })
        .expect_err("reopening inside deny should fail");

        match error {
            SandboxError::InvalidRequest(message) => {
                assert!(
                    message.contains("read_write path cannot reopen access under deny ancestor"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected InvalidRequest for reopen-under-deny, got {other:?}"),
        }
    }
}
