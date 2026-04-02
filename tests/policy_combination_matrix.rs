#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use procwarden::{SandboxDefaultAccess, SandboxError, SandboxManager, SandboxPathPermission};

use common::{
    Fixture, assert_failure, assert_success, execute_case, policy, read_command, sandbox_request,
    write_command,
};

#[derive(Clone, Copy)]
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
    linux_expectation: Expectation,
    macos_expectation: Expectation,
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
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_write_default_read_write_overlay",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: false,
            include_read_write: true,
            include_deny: false,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_write_default_read_only_overlay",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: true,
            include_read_write: false,
            include_deny: false,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_write_default_deny_overlay",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: false,
            include_read_write: false,
            include_deny: true,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_write_default_read_only_and_deny_overlay",
            default_access: SandboxDefaultAccess::ReadWrite,
            include_read_only: true,
            include_read_write: false,
            include_deny: true,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_no_overlays",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: false,
            include_read_write: false,
            include_deny: false,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_read_only_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: true,
            include_read_write: false,
            include_deny: false,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_read_write_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: false,
            include_read_write: true,
            include_deny: false,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_deny_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: false,
            include_read_write: false,
            include_deny: true,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_read_only_and_read_write_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: true,
            include_read_write: true,
            include_deny: false,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_read_write_and_deny_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: false,
            include_read_write: true,
            include_deny: true,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_read_only_read_write_and_deny_overlay",
            default_access: SandboxDefaultAccess::ReadOnly,
            include_read_only: true,
            include_read_write: true,
            include_deny: true,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
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

        let test_policy = policy(case.default_access, false, path_permissions);
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
fn linux_read_only_default_with_deny_is_enforced_when_overlays_are_available() {
    let fixture = Fixture::new("matrix-linux-readonly-deny");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxDefaultAccess::ReadOnly,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::deny(fixture.deny_dir.clone()),
        ],
    );

    let read_ro_request =
        sandbox_request(read_command(&fixture.ro_seed), &fixture.runtime_cwd, 2_500);
    let read_ro = match manager.execute(&read_ro_request, &test_policy) {
        Ok(output) => output,
        Err(SandboxError::Unavailable(message)) if message.contains("mount-namespace support") => {
            return;
        }
        Err(error) => {
            panic!("linux readonly+deny read readonly seed: manager execution failed: {error:?}")
        }
    };
    assert_success(&read_ro, "linux readonly+deny read readonly seed");

    let write_rw_target = fixture.rw_dir.join("allowed-linux-readonly-deny.txt");
    let write_rw_request = sandbox_request(
        write_command(&write_rw_target, "allowed"),
        &fixture.runtime_cwd,
        2_500,
    );
    let write_rw = execute_case(
        &manager,
        &write_rw_request,
        &test_policy,
        "linux readonly+deny write readwrite path",
    );
    assert_success(&write_rw, "linux readonly+deny write readwrite path");

    let read_deny = execute_case(
        &manager,
        &sandbox_request(
            read_command(&fixture.deny_seed),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "linux readonly+deny read deny path",
    );
    assert_failure(&read_deny, "linux readonly+deny read deny path");
}

#[cfg(target_os = "linux")]
#[test]
fn linux_overlay_backed_subtractive_paths_require_existing_targets() {
    let fixture = Fixture::new("matrix-linux-existing-overlay-targets");
    let manager = SandboxManager::new();

    let missing_readonly_target = fixture.ro_dir.join("future-readonly.txt");
    assert!(
        !missing_readonly_target.exists(),
        "test requires a missing readonly overlay target"
    );

    let read_write_missing_readonly_policy = policy(
        SandboxDefaultAccess::ReadWrite,
        false,
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

    let missing_readwrite_deny_target = fixture.deny_dir.join("future-deny-readwrite.txt");
    assert!(
        !missing_readwrite_deny_target.exists(),
        "test requires a missing read_write deny overlay target"
    );

    let read_write_missing_deny_policy = policy(
        SandboxDefaultAccess::ReadWrite,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::deny(missing_readwrite_deny_target),
        ],
    );
    let read_write_missing_deny_result = manager.execute(
        &sandbox_request(
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 0".to_string(),
            ],
            &fixture.runtime_cwd,
            2_500,
        ),
        &read_write_missing_deny_policy,
    );
    match read_write_missing_deny_result {
        Err(SandboxError::InvalidRequest(message)) => {
            assert!(
                message.contains("deny path does not exist"),
                "unexpected read_write missing-deny error: {message}"
            );
        }
        other => panic!(
            "read_write default with missing deny overlay target should fail closed, got {other:?}"
        ),
    }

    let missing_readonly_deny_target = fixture.deny_dir.join("future-deny-readonly.txt");
    assert!(
        !missing_readonly_deny_target.exists(),
        "test requires a missing read_only deny overlay target"
    );

    let read_only_missing_deny_policy = policy(
        SandboxDefaultAccess::ReadOnly,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::deny(missing_readonly_deny_target),
        ],
    );
    let read_only_missing_deny_result = manager.execute(
        &sandbox_request(
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 0".to_string(),
            ],
            &fixture.runtime_cwd,
            2_500,
        ),
        &read_only_missing_deny_policy,
    );
    match read_only_missing_deny_result {
        Err(SandboxError::InvalidRequest(message)) => {
            assert!(
                message.contains("deny path does not exist"),
                "unexpected read_only missing-deny error: {message}"
            );
        }
        other => panic!(
            "read_only default with missing deny overlay target should fail closed, got {other:?}"
        ),
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_read_only_default_can_combine_read_write_and_deny() {
    let fixture = Fixture::new("matrix-macos-readonly-deny");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxDefaultAccess::ReadOnly,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::deny(fixture.deny_dir.clone()),
        ],
    );

    let write_rw_target = fixture.rw_dir.join("allowed-matrix-macos.txt");
    let write_rw = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_rw_target, "allowed"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "macos readonly+deny write readwrite path",
    );
    assert_success(&write_rw, "macos readonly+deny write readwrite path");

    let read_deny = execute_case(
        &manager,
        &sandbox_request(
            read_command(&fixture.deny_seed),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "macos readonly+deny read deny path",
    );
    assert_failure(&read_deny, "macos readonly+deny read deny path");
}

fn expected_for_current_platform(case: &CombinationCase) -> Expectation {
    let _ = case.linux_expectation;
    let _ = case.macos_expectation;

    #[cfg(target_os = "linux")]
    {
        case.linux_expectation
    }

    #[cfg(target_os = "macos")]
    {
        case.macos_expectation
    }
}
