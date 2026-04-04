use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum SandboxDefaultAccess {
    #[default]
    ReadOnly,
    ReadWrite,
}

/// IP-network policy for the sandboxed process.
///
/// The variants intentionally stay coarse so each backend can map them to a
/// real enforcement strategy without pretending to support rules it cannot
/// actually guarantee. Host-specific caveats still exist on some platforms;
/// see the README support matrix before depending on a mode in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum SandboxNetworkMode {
    /// Deny IP networking.
    #[default]
    Disabled,
    /// Request an outbound-oriented IP policy.
    ///
    /// Linux and macOS enforce this as outbound-only networking and also deny
    /// listener setup. Windows maps it through AppContainer and firewall
    /// controls; on the current backend the main verified contract is
    /// private-network outbound access, while loopback and listener behavior
    /// remain host- and executable-dependent there.
    OutboundOnly,
    /// Request that procwarden not add its own network direction restriction.
    ///
    /// This does not imply a blanket loopback guarantee on every backend.
    /// Windows still relies on AppContainer and firewall controls, so consult
    /// the README support matrix before depending on specific loopback or
    /// listener behavior there.
    Bidirectional,
}

impl SandboxNetworkMode {
    pub fn allows_ip_network(self) -> bool {
        !matches!(self, SandboxNetworkMode::Disabled)
    }

    pub fn allows_inbound_ip(self) -> bool {
        matches!(self, SandboxNetworkMode::Bidirectional)
    }

    pub fn allows_outbound_ip(self) -> bool {
        matches!(
            self,
            SandboxNetworkMode::OutboundOnly | SandboxNetworkMode::Bidirectional
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SandboxPathAccess {
    Deny,
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPathPermission {
    pub path: PathBuf,
    pub access: SandboxPathAccess,
}

impl SandboxPathPermission {
    pub fn deny(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: SandboxPathAccess::Deny,
        }
    }

    pub fn read_only(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: SandboxPathAccess::ReadOnly,
        }
    }

    pub fn read_write(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            access: SandboxPathAccess::ReadWrite,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    pub path_permissions: Vec<SandboxPathPermission>,
    pub default_access: SandboxDefaultAccess,
    pub network_mode: SandboxNetworkMode,
}

impl SandboxPolicy {
    pub fn read_only_paths(&self) -> Vec<PathBuf> {
        self.collect_paths(|access| matches!(access, SandboxPathAccess::ReadOnly))
    }

    pub fn denied_paths(&self) -> Vec<PathBuf> {
        self.collect_paths(|access| matches!(access, SandboxPathAccess::Deny))
    }

    pub fn read_write_paths(&self) -> Vec<PathBuf> {
        self.collect_paths(|access| matches!(access, SandboxPathAccess::ReadWrite))
    }

    pub fn readable_paths(&self) -> Vec<PathBuf> {
        self.collect_paths(|access| {
            matches!(
                access,
                SandboxPathAccess::ReadOnly | SandboxPathAccess::ReadWrite
            )
        })
    }

    pub fn writable_paths(&self) -> Vec<PathBuf> {
        self.read_write_paths()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn default_write_access(&self) -> bool {
        matches!(self.default_access, SandboxDefaultAccess::ReadWrite)
    }

    fn collect_paths(&self, mut include: impl FnMut(SandboxPathAccess) -> bool) -> Vec<PathBuf> {
        self.path_permissions
            .iter()
            .filter(|permission| include(permission.access))
            .map(|permission| permission.path.clone())
            .collect()
    }
}
