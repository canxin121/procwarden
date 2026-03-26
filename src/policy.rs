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
    pub default_access: SandboxAccess,
    pub network_access: bool,
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

    #[cfg(target_os = "linux")]
    pub(crate) fn default_read_access(&self) -> bool {
        !matches!(self.default_access, SandboxAccess::NoAccess)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn default_write_access(&self) -> bool {
        matches!(self.default_access, SandboxAccess::ReadWrite)
    }

    fn collect_paths(&self, mut include: impl FnMut(SandboxAccess) -> bool) -> Vec<PathBuf> {
        self.path_permissions
            .iter()
            .filter(|permission| include(permission.access))
            .map(|permission| permission.path.clone())
            .collect()
    }
}
