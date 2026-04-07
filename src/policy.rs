use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum SandboxDefaultAccess {
    #[default]
    ReadOnly,
    ReadWrite,
}

/// Socket-network policy for the sandboxed process.
///
/// The public model only exposes knobs that can be enforced honestly. On
/// Linux, the current implementation applies these controls at socket-family
/// creation time and for the key connection-management syscalls. On macOS and
/// Windows, only the coarse helper shapes are currently supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxNetworkPolicy {
    pub allow_unix: bool,
    pub allow_ipv4: bool,
    pub allow_ipv6: bool,
    pub allow_connect: bool,
    pub allow_bind: bool,
    pub allow_listen: bool,
    pub allow_accept: bool,
}

impl Default for SandboxNetworkPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SandboxCoarseNetworkPolicy {
    Disabled,
    OutboundOnly,
    Bidirectional,
}

#[cfg(target_os = "windows")]
impl SandboxCoarseNetworkPolicy {
    pub(crate) fn allows_ip_network(self) -> bool {
        !matches!(self, SandboxCoarseNetworkPolicy::Disabled)
    }

    pub(crate) fn allows_loopback_exemption(self) -> bool {
        matches!(
            self,
            SandboxCoarseNetworkPolicy::OutboundOnly | SandboxCoarseNetworkPolicy::Bidirectional
        )
    }
}

impl SandboxNetworkPolicy {
    pub const fn disabled() -> Self {
        Self {
            allow_unix: true,
            allow_ipv4: false,
            allow_ipv6: false,
            allow_connect: false,
            allow_bind: false,
            allow_listen: false,
            allow_accept: false,
        }
    }

    pub const fn outbound_only() -> Self {
        Self {
            allow_unix: true,
            allow_ipv4: true,
            allow_ipv6: true,
            allow_connect: true,
            allow_bind: false,
            allow_listen: false,
            allow_accept: false,
        }
    }

    pub const fn bidirectional() -> Self {
        Self {
            allow_unix: true,
            allow_ipv4: true,
            allow_ipv6: true,
            allow_connect: true,
            allow_bind: true,
            allow_listen: true,
            allow_accept: true,
        }
    }

    pub const fn allows_ip_network(self) -> bool {
        self.allow_ipv4 || self.allow_ipv6
    }

    pub const fn allows_inbound_ip(self) -> bool {
        self.allows_ip_network() && self.allow_bind && self.allow_listen && self.allow_accept
    }

    pub const fn allows_outbound_ip(self) -> bool {
        self.allows_ip_network() && self.allow_connect
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub(crate) fn coarse_policy(self) -> Option<SandboxCoarseNetworkPolicy> {
        if self == Self::disabled() {
            Some(SandboxCoarseNetworkPolicy::Disabled)
        } else if self == Self::outbound_only() {
            Some(SandboxCoarseNetworkPolicy::OutboundOnly)
        } else if self == Self::bidirectional() {
            Some(SandboxCoarseNetworkPolicy::Bidirectional)
        } else {
            None
        }
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
    pub network_policy: SandboxNetworkPolicy,
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
