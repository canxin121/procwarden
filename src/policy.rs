use std::path::{Path, PathBuf};

use super::cap_fs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxAccess {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPathPermission {
    pub path: PathBuf,
    pub access: SandboxAccess,
}

impl SandboxPathPermission {
    pub fn deny(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: SandboxAccess::NoAccess,
        }
    }

    pub fn read_only(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: SandboxAccess::ReadOnly,
        }
    }

    pub fn read_write(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: SandboxAccess::ReadWrite,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    path_permissions: Vec<SandboxPathPermission>,
    global_access: SandboxAccess,
    network_access: bool,
    enforce_world_writable_audit: bool,
    reject_reparse_points: bool,
    allow_unc_paths: bool,
    include_workspace_root_in_writable_roots: bool,
    include_tmpdir_env_var_in_writable_roots: bool,
    include_slash_tmp_in_writable_roots: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WritableRoot {
    pub root: PathBuf,
    pub read_only_subpaths: Vec<PathBuf>,
}

impl SandboxPolicy {
    #[allow(non_upper_case_globals)]
    pub const ReadOnly: Self = Self {
        path_permissions: Vec::new(),
        global_access: SandboxAccess::ReadOnly,
        network_access: false,
        enforce_world_writable_audit: true,
        reject_reparse_points: true,
        allow_unc_paths: false,
        include_workspace_root_in_writable_roots: false,
        include_tmpdir_env_var_in_writable_roots: false,
        include_slash_tmp_in_writable_roots: false,
    };

    #[allow(non_upper_case_globals)]
    pub const WorkspaceWrite: Self = Self {
        path_permissions: Vec::new(),
        global_access: SandboxAccess::ReadOnly,
        network_access: false,
        enforce_world_writable_audit: true,
        reject_reparse_points: true,
        allow_unc_paths: false,
        include_workspace_root_in_writable_roots: true,
        include_tmpdir_env_var_in_writable_roots: true,
        include_slash_tmp_in_writable_roots: true,
    };

    pub fn new_unsandboxed_policy() -> Self {
        Self {
            path_permissions: Vec::new(),
            global_access: SandboxAccess::ReadWrite,
            network_access: true,
            enforce_world_writable_audit: false,
            reject_reparse_points: false,
            allow_unc_paths: true,
            include_workspace_root_in_writable_roots: false,
            include_tmpdir_env_var_in_writable_roots: false,
            include_slash_tmp_in_writable_roots: false,
        }
    }

    pub fn new_read_only_policy() -> Self {
        Self::ReadOnly
    }

    pub fn new_full_read_policy() -> Self {
        Self::new_read_only_policy()
    }

    pub fn new_workspace_write_policy() -> Self {
        Self::WorkspaceWrite
    }

    pub fn new_full_read_write_policy() -> Self {
        Self {
            path_permissions: Vec::new(),
            global_access: SandboxAccess::ReadWrite,
            network_access: false,
            enforce_world_writable_audit: false,
            reject_reparse_points: false,
            allow_unc_paths: true,
            include_workspace_root_in_writable_roots: false,
            include_tmpdir_env_var_in_writable_roots: false,
            include_slash_tmp_in_writable_roots: false,
        }
    }

    pub fn new_custom_policy() -> Self {
        Self {
            path_permissions: Vec::new(),
            global_access: SandboxAccess::NoAccess,
            network_access: false,
            enforce_world_writable_audit: true,
            reject_reparse_points: true,
            allow_unc_paths: false,
            include_workspace_root_in_writable_roots: false,
            include_tmpdir_env_var_in_writable_roots: false,
            include_slash_tmp_in_writable_roots: false,
        }
    }

    pub fn path_permissions(&self) -> &[SandboxPathPermission] {
        &self.path_permissions
    }

    pub fn has_full_disk_write_access(&self) -> bool {
        matches!(self.global_access, SandboxAccess::ReadWrite)
    }

    pub fn has_full_disk_read_access(&self) -> bool {
        !matches!(self.global_access, SandboxAccess::NoAccess)
    }

    pub fn is_danger_full_access(&self) -> bool {
        self.has_full_disk_write_access() && self.network_access
    }

    pub fn should_bypass_env_sanitization(&self) -> bool {
        self.is_danger_full_access()
    }

    pub fn requires_read_allowlist_enforcement(&self) -> bool {
        matches!(self.global_access, SandboxAccess::NoAccess)
    }

    pub fn requested_read_enforcement(&self) -> bool {
        self.requires_read_allowlist_enforcement()
    }

    pub fn requested_write_enforcement(&self) -> bool {
        !self.has_full_disk_write_access()
    }

    pub fn global_access(&self) -> SandboxAccess {
        self.global_access
    }

    pub fn has_full_network_access(&self) -> bool {
        self.network_access
    }

    pub fn enforce_world_writable_audit(&self) -> bool {
        self.enforce_world_writable_audit
    }

    pub fn reject_reparse_points(&self) -> bool {
        self.reject_reparse_points
    }

    pub fn allow_unc_paths(&self) -> bool {
        self.allow_unc_paths
    }

    pub fn with_permissions(
        mut self,
        permissions: impl IntoIterator<Item = SandboxPathPermission>,
    ) -> Self {
        self.path_permissions.extend(permissions);
        self
    }

    pub fn with_additional_writable_roots(
        mut self,
        roots: impl IntoIterator<Item = PathBuf>,
    ) -> Self {
        self.path_permissions
            .extend(roots.into_iter().map(SandboxPathPermission::read_write));
        self
    }

    pub fn with_additional_readable_roots(
        mut self,
        roots: impl IntoIterator<Item = PathBuf>,
    ) -> Self {
        self.path_permissions
            .extend(roots.into_iter().map(SandboxPathPermission::read_only));
        self
    }

    pub fn with_global_access(mut self, access: SandboxAccess) -> Self {
        self.global_access = access;
        self
    }

    pub fn with_full_disk_read_access(mut self, enabled: bool) -> Self {
        self.global_access = if enabled {
            if matches!(self.global_access, SandboxAccess::ReadWrite) {
                SandboxAccess::ReadWrite
            } else {
                SandboxAccess::ReadOnly
            }
        } else {
            SandboxAccess::NoAccess
        };
        self
    }

    pub fn with_full_disk_write_access(mut self, enabled: bool) -> Self {
        self.global_access = if enabled {
            SandboxAccess::ReadWrite
        } else if self.has_full_disk_read_access() {
            SandboxAccess::ReadOnly
        } else {
            SandboxAccess::NoAccess
        };
        self
    }

    pub fn with_network_access(mut self, enabled: bool) -> Self {
        self.network_access = enabled;
        self
    }

    pub fn with_world_writable_audit(mut self, enabled: bool) -> Self {
        self.enforce_world_writable_audit = enabled;
        self
    }

    pub fn with_reparse_point_rejection(mut self, enabled: bool) -> Self {
        self.reject_reparse_points = enabled;
        self
    }

    pub fn with_allow_unc_paths(mut self, enabled: bool) -> Self {
        self.allow_unc_paths = enabled;
        self
    }

    pub fn with_workspace_writable_roots(mut self, enabled: bool) -> Self {
        self.include_workspace_root_in_writable_roots = enabled;
        self
    }

    pub fn with_tmpdir_env_writable_roots(mut self, enabled: bool) -> Self {
        self.include_tmpdir_env_var_in_writable_roots = enabled;
        self
    }

    pub fn with_slash_tmp_writable_roots(mut self, enabled: bool) -> Self {
        self.include_slash_tmp_in_writable_roots = enabled;
        self
    }

    pub fn readable_roots_with_workspace(&self, _workspace_root: &Path) -> Vec<PathBuf> {
        if self.has_full_disk_read_access() {
            return Vec::new();
        }

        let roots = self
            .path_permissions
            .iter()
            .filter(|permission| !matches!(permission.access, SandboxAccess::NoAccess))
            .map(|permission| permission.path.clone())
            .collect::<Vec<_>>();

        cap_fs::PathPolicy::exact().normalize_paths(roots)
    }

    pub fn writable_roots_with_workspace(&self, workspace_root: &Path) -> Vec<WritableRoot> {
        if self.has_full_disk_write_access() {
            return Vec::new();
        }

        let mut roots = self
            .path_permissions
            .iter()
            .filter(|permission| matches!(permission.access, SandboxAccess::ReadWrite))
            .map(|permission| permission.path.clone())
            .collect::<Vec<_>>();

        if self.include_workspace_root_in_writable_roots {
            roots.push(workspace_root.to_path_buf());
        }

        if self.include_slash_tmp_in_writable_roots && cfg!(unix) {
            let slash_tmp = PathBuf::from("/tmp");
            if cap_fs::is_dir(&slash_tmp) {
                roots.push(slash_tmp);
            }
        }

        if self.include_tmpdir_env_var_in_writable_roots
            && let Some(tmpdir) = std::env::var_os("TMPDIR")
            && !tmpdir.is_empty()
        {
            roots.push(PathBuf::from(tmpdir));
        }

        if self.include_tmpdir_env_var_in_writable_roots && cfg!(windows) {
            for key in ["TEMP", "TMP"] {
                if let Some(value) = std::env::var_os(key)
                    && !value.is_empty()
                {
                    roots.push(PathBuf::from(value));
                }
            }
        }

        let canonical_roots = cap_fs::PathPolicy::exact().normalize_paths(roots);
        canonical_roots
            .into_iter()
            .map(|canonical_root| {
                let mut read_only_subpaths = Vec::new();
                let git_path = canonical_root.join(".git");
                if cap_fs::is_dir(&git_path) {
                    read_only_subpaths.push(git_path);
                }
                WritableRoot {
                    root: canonical_root,
                    read_only_subpaths,
                }
            })
            .collect()
    }

    pub fn is_path_readable(&self, path: &Path, workspace_root: &Path) -> bool {
        if self.has_full_disk_read_access() {
            return true;
        }

        self.readable_roots_with_workspace(workspace_root)
            .iter()
            .any(|root| path.starts_with(root))
    }

    pub fn is_path_writable(&self, path: &Path, workspace_root: &Path) -> bool {
        if self.has_full_disk_write_access() {
            return true;
        }

        for root in self.writable_roots_with_workspace(workspace_root) {
            if !path.starts_with(&root.root) {
                continue;
            }
            let inside_read_only_subpath = root
                .read_only_subpaths
                .iter()
                .any(|read_only_subpath| path.starts_with(read_only_subpath));
            if !inside_read_only_subpath {
                return true;
            }
        }
        false
    }
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self::new_workspace_write_policy()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{SandboxAccess, SandboxPathPermission, SandboxPolicy};

    #[test]
    fn workspace_write_contains_workspace_root() {
        let workspace = if cfg!(windows) {
            PathBuf::from(r"C:\workspace\repo")
        } else {
            PathBuf::from("/workspace/repo")
        };

        let roots =
            SandboxPolicy::new_workspace_write_policy().writable_roots_with_workspace(&workspace);
        assert!(roots.iter().any(|root| root.root == workspace));
    }

    #[test]
    fn read_only_has_no_writable_roots() {
        let workspace = if cfg!(windows) {
            PathBuf::from(r"C:\workspace\repo")
        } else {
            PathBuf::from("/workspace/repo")
        };

        let roots = SandboxPolicy::new_read_only_policy().writable_roots_with_workspace(&workspace);
        assert!(roots.is_empty());
    }

    #[test]
    fn custom_policy_supports_scoped_read_and_write_paths() {
        let workspace = if cfg!(windows) {
            PathBuf::from(r"C:\workspace\repo")
        } else {
            PathBuf::from("/workspace/repo")
        };
        let readable = workspace.join("docs");
        let writable = workspace.join("tmp");

        let policy = SandboxPolicy::new_custom_policy()
            .with_additional_readable_roots([readable.clone()])
            .with_additional_writable_roots([writable.clone()]);

        assert!(!policy.has_full_disk_read_access());
        assert!(!policy.has_full_disk_write_access());
        assert!(policy.is_path_readable(&readable.join("a.txt"), &workspace));
        assert!(policy.is_path_writable(&writable.join("b.txt"), &workspace));
        assert!(!policy.is_path_writable(&readable.join("a.txt"), &workspace));
    }

    #[test]
    fn unsandboxed_is_full_access_and_networked() {
        let policy = SandboxPolicy::new_unsandboxed_policy();
        assert!(policy.has_full_disk_read_access());
        assert!(policy.has_full_disk_write_access());
        assert!(policy.has_full_network_access());
        assert!(policy.is_danger_full_access());
    }

    #[test]
    fn deny_permission_is_neither_readable_nor_writable() {
        let workspace = if cfg!(windows) {
            PathBuf::from(r"C:\workspace\repo")
        } else {
            PathBuf::from("/workspace/repo")
        };
        let denied = workspace.join("secret");
        let policy = SandboxPolicy::new_custom_policy()
            .with_permissions([SandboxPathPermission::deny(denied.clone())]);

        assert!(!policy.is_path_readable(&denied.join("a.txt"), &workspace));
        assert!(!policy.is_path_writable(&denied.join("a.txt"), &workspace));
    }

    #[test]
    fn global_access_enum_controls_full_access() {
        let policy = SandboxPolicy::new_custom_policy().with_global_access(SandboxAccess::ReadOnly);
        assert!(policy.has_full_disk_read_access());
        assert!(!policy.has_full_disk_write_access());
    }
}
