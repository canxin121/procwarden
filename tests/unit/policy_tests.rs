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
