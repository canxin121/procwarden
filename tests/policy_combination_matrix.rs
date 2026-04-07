#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use procwarden::{
    SandboxDefaultAccess, SandboxError, SandboxManager, SandboxNetworkPolicy, SandboxPathPermission,
};

use common::{Fixture, assert_success, policy, sandbox_request};

#[derive(Clone, Copy)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
enum Expectation {
    Runnable,
    HostCapabilityDependent,
}

struct CombinationCase {
    name: &'static str,
    default_access: SandboxDefaultAccess,
    include_read_only: bool,
    include_read_write: bool,
    include_deny: bool,
}

#[test]
fn policy_shape_matrix_acceptance_contract() {
    let fixture = Fixture::new("policy-shape-matrix");
    let manager = SandboxManager::new();

    let cases = vec![
        CombinationCase {
            name: "read_write_default_no_overlays",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: false,
            include_read_write: false,
            include_deny: false,
        },
        CombinationCase {
            name: "read_write_default_read_write_overlay",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: false,
            include_read_write: true,
            include_deny: false,
        },
        CombinationCase {
            name: "read_write_default_read_only_overlay",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: true,
            include_read_write: false,
            include_deny: false,
        },
        CombinationCase {
            name: "read_write_default_read_only_and_read_write_overlay",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: true,
            include_read_write: true,
            include_deny: false,
        },
        CombinationCase {
            name: "read_write_default_deny_overlay",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: false,
            include_read_write: false,
            include_deny: true,
        },
        CombinationCase {
            name: "read_write_default_read_only_and_deny_overlay",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: true,
            include_read_write: false,
            include_deny: true,
        },
        CombinationCase {
            name: "read_write_default_read_write_and_deny_overlay",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: false,
            include_read_write: true,
            include_deny: true,
        },
        CombinationCase {
            name: "read_write_default_read_only_read_write_and_deny_overlay",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: true,
            include_read_write: true,
            include_deny: true,
        },
        CombinationCase {
            name: "read_only_default_no_overlays",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: false,
            include_read_write: false,
            include_deny: false,
        },
        CombinationCase {
            name: "read_only_default_read_only_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: true,
            include_read_write: false,
            include_deny: false,
        },
        CombinationCase {
            name: "read_only_default_read_write_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: false,
            include_read_write: true,
            include_deny: false,
        },
        CombinationCase {
            name: "read_only_default_read_only_and_read_write_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: true,
            include_read_write: true,
            include_deny: false,
        },
        CombinationCase {
            name: "read_only_default_deny_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: false,
            include_read_write: false,
            include_deny: true,
        },
        CombinationCase {
            name: "read_only_default_read_only_and_deny_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: true,
            include_read_write: false,
            include_deny: true,
        },
        CombinationCase {
            name: "read_only_default_read_write_and_deny_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: false,
            include_read_write: true,
            include_deny: true,
        },
        CombinationCase {
            name: "read_only_default_read_only_read_write_and_deny_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: true,
            include_read_write: true,
            include_deny: true,
        },
    ];

    for case in cases {
        let mut path_permissions = Vec::new();
        if case.include_read_only {
            path_permissions.push(SandboxPathPermission::read_only(fixture.ro_dir.clone()));
        }
        if case.include_read_write {
            path_permissions.push(SandboxPathPermission::read_write(fixture.rw_dir.clone()));
        }
        if case.include_deny {
            path_permissions.push(SandboxPathPermission::deny(fixture.deny_dir.clone()));
        }

        let test_policy = policy(
            case.default_access,
            SandboxNetworkPolicy::disabled(),
            path_permissions,
        );
        let result = manager.execute(
            &sandbox_request(
                vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "exit 0".to_string(),
                ],
                &fixture.runtime_cwd,
                2_500,
            ),
            &test_policy,
        );

        let expected = expected_for_current_platform(&case);
        match (expected, result) {
            (Expectation::Runnable, Ok(output)) => {
                assert_success(&output, case.name);
            }
            (Expectation::Runnable, Err(SandboxError::Unavailable(message)))
                if message.contains("mount-namespace support") =>
            {
                panic!(
                    "{}: expected runnable policy, got host capability gap: {}",
                    case.name, message
                )
            }
            (Expectation::Runnable, other) => {
                panic!("{}: expected runnable policy, got {:?}", case.name, other)
            }
            (Expectation::HostCapabilityDependent, Ok(output)) => {
                assert_success(&output, case.name);
            }
            (Expectation::HostCapabilityDependent, Err(SandboxError::Unavailable(message)))
                if message.contains("mount-namespace support") => {}
            (Expectation::HostCapabilityDependent, other) => {
                panic!(
                    "{}: expected success or mount-namespace Unavailable, got {:?}",
                    case.name, other
                )
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_read_write_default_with_read_only_overlay_is_enforced_when_overlays_are_available() {
    let fixture = Fixture::new("matrix-linux-readwrite-readonly");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxDefaultAccess::ReadWrite,
        SandboxNetworkPolicy::disabled(),
        vec![SandboxPathPermission::read_only(fixture.ro_dir.clone())],
    );

    let write_outside_target = fixture.outside_dir.join("allowed-linux-readwrite.txt");
    let write_outside = match manager.execute(
        &sandbox_request(
            common::write_command(&write_outside_target, "allowed"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
    ) {
        Ok(output) => output,
        Err(SandboxError::Unavailable(message)) if message.contains("mount-namespace support") => {
            return;
        }
        Err(error) => {
            panic!("linux readwrite+readonly write outside path failed: {error:?}")
        }
    };
    assert_success(
        &write_outside,
        "linux readwrite+readonly write outside path",
    );

    let read_ro = common::execute_case(
        &manager,
        &sandbox_request(
            common::read_command(&fixture.ro_seed),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "linux readwrite+readonly read readonly path",
    );
    assert_success(&read_ro, "linux readwrite+readonly read readonly path");

    let write_ro_target = fixture.ro_dir.join("blocked-linux-readwrite-readonly.txt");
    let write_ro = common::execute_case(
        &manager,
        &sandbox_request(
            common::write_command(&write_ro_target, "blocked"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "linux readwrite+readonly write readonly path",
    );
    common::assert_failure(&write_ro, "linux readwrite+readonly write readonly path");
}

#[cfg(target_os = "linux")]
#[test]
fn linux_overlay_backed_readonly_paths_require_existing_targets() {
    let fixture = Fixture::new("matrix-linux-existing-overlay-targets");
    let manager = SandboxManager::new();

    let missing_readonly_target = fixture.ro_dir.join("future-readonly.txt");
    assert!(
        !missing_readonly_target.exists(),
        "test requires a missing readonly overlay target"
    );

    let read_write_missing_readonly_policy = policy(
        SandboxDefaultAccess::ReadWrite,
        SandboxNetworkPolicy::disabled(),
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_only(missing_readonly_target),
        ],
    );
    let read_write_missing_readonly_result = manager.execute(
        &sandbox_request(
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 0".to_string(),
            ],
            &fixture.runtime_cwd,
            2_500,
        ),
        &read_write_missing_readonly_policy,
    );
    match read_write_missing_readonly_result {
        Err(SandboxError::InvalidRequest(message)) => {
            assert!(
                message.contains("read_only path does not exist"),
                "unexpected read_write missing-readonly error: {message}"
            );
        }
        other => panic!(
            "read_write default with missing read_only overlay target should fail closed, got {other:?}"
        ),
    }
}

fn expected_for_current_platform(case: &CombinationCase) -> Expectation {
    #[cfg(target_os = "linux")]
    {
        linux_expectation(case)
    }

    #[cfg(target_os = "macos")]
    {
        macos_expectation(case)
    }
}

#[cfg(target_os = "linux")]
fn linux_expectation(case: &CombinationCase) -> Expectation {
    match case.default_access {
        SandboxDefaultAccess::ReadWrite if case.include_read_only || case.include_deny => {
            Expectation::HostCapabilityDependent
        }
        SandboxDefaultAccess::ReadOnly if case.include_deny => Expectation::HostCapabilityDependent,
        _ => Expectation::Runnable,
    }
}

#[cfg(target_os = "macos")]
fn macos_expectation(_case: &CombinationCase) -> Expectation {
    Expectation::Runnable
}
