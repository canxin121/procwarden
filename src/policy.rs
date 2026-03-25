use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum SandboxAccess {
    #[default]
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    pub path_permissions: Vec<SandboxPathPermission>,
    pub global_access: SandboxAccess,
    pub network_access: bool,
    pub enforce_world_writable_audit: bool,
}

impl SandboxPolicy {
    pub fn read_only_paths(&self) -> Vec<PathBuf> {
        self.collect_paths(|access| matches!(access, SandboxAccess::ReadOnly))
    }

    pub fn read_write_paths(&self) -> Vec<PathBuf> {
        self.collect_paths(|access| matches!(access, SandboxAccess::ReadWrite))
    }

    pub fn readable_paths(&self) -> Vec<PathBuf> {
        self.collect_paths(|access| {
            matches!(access, SandboxAccess::ReadOnly | SandboxAccess::ReadWrite)
        })
    }

    pub fn writable_paths(&self) -> Vec<PathBuf> {
        self.read_write_paths()
    }

    pub fn denied_paths(&self) -> Vec<PathBuf> {
        self.collect_paths(|access| matches!(access, SandboxAccess::NoAccess))
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn full_disk_read_access(&self) -> bool {
        !matches!(self.global_access, SandboxAccess::NoAccess)
    }

    #[cfg(any(target_os = "linux", target_os = "windows", test))]
    pub(crate) fn full_disk_write_access(&self) -> bool {
        matches!(self.global_access, SandboxAccess::ReadWrite)
    }

    fn collect_paths(&self, mut include: impl FnMut(SandboxAccess) -> bool) -> Vec<PathBuf> {
        self.path_permissions
            .iter()
            .filter(|permission| include(permission.access))
            .map(|permission| permission.path.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{SandboxAccess, SandboxPathPermission, SandboxPolicy};

    fn sample_policy() -> SandboxPolicy {
        SandboxPolicy {
            path_permissions: vec![
                SandboxPathPermission::read_only("/tmp/ro"),
                SandboxPathPermission::read_write("/tmp/rw"),
                SandboxPathPermission::deny("/tmp/no"),
            ],
            global_access: SandboxAccess::NoAccess,
            network_access: false,
            enforce_world_writable_audit: false,
        }
    }

    #[test]
    fn collects_policy_paths_by_access_level() {
        let policy = sample_policy();

        assert_eq!(policy.read_only_paths().len(), 1);
        assert_eq!(policy.read_write_paths().len(), 1);
        assert_eq!(policy.writable_paths().len(), 1);
        assert_eq!(policy.denied_paths().len(), 1);
        assert_eq!(policy.readable_paths().len(), 2);
    }

    #[test]
    fn keeps_permission_order_within_extractors() {
        let policy = SandboxPolicy {
            path_permissions: vec![
                SandboxPathPermission::read_only("/tmp/a"),
                SandboxPathPermission::read_write("/tmp/b"),
                SandboxPathPermission::read_only("/tmp/c"),
            ],
            ..SandboxPolicy::default()
        };

        let readable = policy.readable_paths();
        let readable = readable
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert_eq!(readable, vec!["/tmp/a", "/tmp/b", "/tmp/c"]);
    }

    #[test]
    fn reports_global_disk_access_flags() {
        let mut policy = SandboxPolicy {
            global_access: SandboxAccess::NoAccess,
            ..SandboxPolicy::default()
        };
        assert!(!policy.full_disk_read_access());
        assert!(!policy.full_disk_write_access());

        policy.global_access = SandboxAccess::ReadOnly;
        assert!(policy.full_disk_read_access());
        assert!(!policy.full_disk_write_access());

        policy.global_access = SandboxAccess::ReadWrite;
        assert!(policy.full_disk_read_access());
        assert!(policy.full_disk_write_access());
    }
}
