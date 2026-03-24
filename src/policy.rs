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
    pub reject_reparse_points: bool,
    pub allow_unc_paths: bool,
}
