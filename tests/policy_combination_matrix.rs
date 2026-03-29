#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use procwarden::{SandboxAccess, SandboxError, SandboxManager, SandboxPathPermission};

use common::{
    assert_failure, assert_success, execute_case, policy, read_command, sandbox_request,
    write_command, Fixture,
};

#[derive(Clone, Copy)]
enum Expectation {
    Accepted,
    InvalidRequest,
}

struct CombinationCase {
    name: &'static str,
    default_access: SandboxAccess,
    include_read_only: bool,
    include_read_write: bool,
    include_deny: bool,
    overlap_read_write_with_deny: bool,
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
            default_access: SandboxAccess::ReadWrite,
            include_read_only: false,
            include_read_write: false,
            include_deny: false,
            overlap_read_write_with_deny: false,
            linux_expectation: Expectation::Accepted,
            macos_expectation: Expectation::Accepted,
        },
        CombinationCase {
            name: "read_write_default_read_only_overlay",
            default_access: SandboxAccess::ReadWrite,
            include_read_only: true,
            include_read_write: false,
            include_deny: false,
            overlap_read_write_with_deny: false,
            linux_expectation: Expectation::Accepted,
            macos_expectation: Expectation::Accepted,
        },
        CombinationCase {
            name: "read_write_default_deny_overlay",
            default_access: SandboxAccess::ReadWrite,
            include_read_only: false,
            include_read_write: false,
            include_deny: true,
            overlap_read_write_with_deny: false,
            linux_expectation: Expectation::Accepted,
            macos_expectation: Expectation::Accepted,
        },
        CombinationCase {
            name: "read_only_default_read_write_overlay",
            default_access: SandboxAccess::ReadOnly,
            include_read_only: true,
            include_read_write: true,
            include_deny: false,
            overlap_read_write_with_deny: false,
            linux_expectation: Expectation::Accepted,
            macos_expectation: Expectation::Accepted,
        },
        CombinationCase {
            name: "read_only_default_with_deny_overlay",
            default_access: SandboxAccess::ReadOnly,
            include_read_only: true,
            include_read_write: true,
            include_deny: true,
            overlap_read_write_with_deny: false,
            linux_expectation: Expectation::InvalidRequest,
            macos_expectation: Expectation::Accepted,
        },
        CombinationCase {
            name: "no_access_default_allow_carveouts",
            default_access: SandboxAccess::NoAccess,
            include_read_only: true,
            include_read_write: true,
            include_deny: false,
            overlap_read_write_with_deny: false,
            linux_expectation: Expectation::Accepted,
            macos_expectation: Expectation::Accepted,
        },
        CombinationCase {
            name: "no_access_default_allow_and_non_overlap_deny",
            default_access: SandboxAccess::NoAccess,
            include_read_only: true,
            include_read_write: true,
            include_deny: true,
            overlap_read_write_with_deny: false,
            linux_expectation: Expectation::Accepted,
            macos_expectation: Expectation::Accepted,
        },
        CombinationCase {
            name: "no_access_default_overlap_allow_and_deny",
            default_access: SandboxAccess::NoAccess,
            include_read_only: true,
            include_read_write: true,
            include_deny: true,
            overlap_read_write_with_deny: true,
            linux_expectation: Expectation::InvalidRequest,
            macos_expectation: Expectation::Accepted,
        },
    ];

    for case in cases {
        let mut path_permissions = vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )];
        if case.include_read_only {
            path_permissions.push(SandboxPathPermission::read_only(fixture.ro_dir.clone()));
        }
        if case.include_read_write {
            path_permissions.push(SandboxPathPermission::read_write(fixture.rw_dir.clone()));
        }
        if case.include_deny {
            let deny_path = if case.overlap_read_write_with_deny {
                fixture.rw_dir.clone()
            } else {
                fixture.deny_dir.clone()
            };
            path_permissions.push(SandboxPathPermission::deny(deny_path));
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
            (Expectation::InvalidRequest, Err(SandboxError::InvalidRequest(_))) => {}
            (Expectation::InvalidRequest, other) => {
                panic!("{}: expected InvalidRequest, got {:?}", case.name, other)
            }
            (Expectation::Accepted, Err(SandboxError::InvalidRequest(message))) => panic!(
                "{}: expected accepted shape, got InvalidRequest: {}",
                case.name, message
            ),
            (Expectation::Accepted, _) => {}
        }
    }
}

#[test]
fn no_access_default_supports_read_only_and_read_write_carveouts() {
    let fixture = Fixture::new("matrix-no-access-carveouts");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxAccess::NoAccess,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
        ],
    );

    let read_ro = execute_case(
        &manager,
        &sandbox_request(read_command(&fixture.ro_seed), &fixture.runtime_cwd, 2_500),
        &test_policy,
        "no_access_default read readonly seed",
    );
    assert_success(&read_ro, "no_access_default read readonly seed");

    let write_ro_target = fixture.ro_dir.join("blocked-matrix-no-access.txt");
    let write_ro = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_ro_target, "blocked"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "no_access_default write readonly path",
    );
    assert_failure(&write_ro, "no_access_default write readonly path");

    let write_rw_target = fixture.rw_dir.join("allowed-matrix-no-access.txt");
    let write_rw = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_rw_target, "allowed"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "no_access_default write readwrite path",
    );
    assert_success(&write_rw, "no_access_default write readwrite path");
}

#[cfg(target_os = "linux")]
#[test]
fn linux_read_only_default_with_deny_is_fail_closed_invalid_request() {
    let fixture = Fixture::new("matrix-linux-readonly-deny");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxAccess::ReadOnly,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::deny(fixture.deny_dir.clone()),
        ],
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

    assert!(
        matches!(result, Err(SandboxError::InvalidRequest(_))),
        "linux should reject ReadOnly+deny combination fail-closed"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_read_only_default_can_combine_read_write_and_deny() {
    let fixture = Fixture::new("matrix-macos-readonly-deny");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxAccess::ReadOnly,
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
    #[cfg(target_os = "linux")]
    {
        case.linux_expectation
    }

    #[cfg(target_os = "macos")]
    {
        case.macos_expectation
    }
}
