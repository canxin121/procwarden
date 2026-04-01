#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use procwarden::{SandboxAccess, SandboxError, SandboxManager, SandboxPathPermission};

use common::{
    Fixture, assert_failure, assert_success, execute_case, no_access_policy_with_runtime_roots,
    policy, read_command, sandbox_request, write_command,
};

#[derive(Clone, Copy)]
enum Expectation {
    Runnable,
    HostCapabilityDependent,
    AcceptedShapeOnly,
}

struct CombinationCase {
    name: &'static str,
    default_access: SandboxAccess,
    include_read_only: bool,
    include_read_write: bool,
    include_deny: bool,
    overlap_read_write_with_deny: bool,
    use_runtime_roots: bool,
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
            use_runtime_roots: false,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_write_default_read_write_overlay",
            default_access: SandboxAccess::ReadWrite,
            include_read_only: false,
            include_read_write: true,
            include_deny: false,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_write_default_read_only_overlay",
            default_access: SandboxAccess::ReadWrite,
            include_read_only: true,
            include_read_write: false,
            include_deny: false,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_write_default_deny_overlay",
            default_access: SandboxAccess::ReadWrite,
            include_read_only: false,
            include_read_write: false,
            include_deny: true,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_write_default_read_only_and_deny_overlay",
            default_access: SandboxAccess::ReadWrite,
            include_read_only: true,
            include_read_write: false,
            include_deny: true,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_no_overlays",
            default_access: SandboxAccess::ReadOnly,
            include_read_only: false,
            include_read_write: false,
            include_deny: false,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_read_only_overlay",
            default_access: SandboxAccess::ReadOnly,
            include_read_only: true,
            include_read_write: false,
            include_deny: false,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_read_write_overlay",
            default_access: SandboxAccess::ReadOnly,
            include_read_only: false,
            include_read_write: true,
            include_deny: false,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_deny_overlay",
            default_access: SandboxAccess::ReadOnly,
            include_read_only: false,
            include_read_write: false,
            include_deny: true,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_read_only_and_read_write_overlay",
            default_access: SandboxAccess::ReadOnly,
            include_read_only: true,
            include_read_write: true,
            include_deny: false,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_read_write_and_deny_overlay",
            default_access: SandboxAccess::ReadOnly,
            include_read_only: false,
            include_read_write: true,
            include_deny: true,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "read_only_default_read_only_read_write_and_deny_overlay",
            default_access: SandboxAccess::ReadOnly,
            include_read_only: true,
            include_read_write: true,
            include_deny: true,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::HostCapabilityDependent,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "no_access_default_no_carveouts",
            default_access: SandboxAccess::NoAccess,
            include_read_only: false,
            include_read_write: false,
            include_deny: false,
            overlap_read_write_with_deny: false,
            use_runtime_roots: false,
            linux_expectation: Expectation::AcceptedShapeOnly,
            macos_expectation: Expectation::AcceptedShapeOnly,
        },
        CombinationCase {
            name: "no_access_default_read_only_allowlist",
            default_access: SandboxAccess::NoAccess,
            include_read_only: true,
            include_read_write: false,
            include_deny: false,
            overlap_read_write_with_deny: false,
            use_runtime_roots: true,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "no_access_default_read_write_allowlist",
            default_access: SandboxAccess::NoAccess,
            include_read_only: false,
            include_read_write: true,
            include_deny: false,
            overlap_read_write_with_deny: false,
            use_runtime_roots: true,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "no_access_default_allow_carveouts",
            default_access: SandboxAccess::NoAccess,
            include_read_only: true,
            include_read_write: true,
            include_deny: false,
            overlap_read_write_with_deny: false,
            use_runtime_roots: true,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "no_access_default_allow_and_non_overlap_deny",
            default_access: SandboxAccess::NoAccess,
            include_read_only: true,
            include_read_write: true,
            include_deny: true,
            overlap_read_write_with_deny: false,
            use_runtime_roots: true,
            linux_expectation: Expectation::Runnable,
            macos_expectation: Expectation::Runnable,
        },
        CombinationCase {
            name: "no_access_default_overlap_allow_and_deny",
            default_access: SandboxAccess::NoAccess,
            include_read_only: true,
            include_read_write: true,
            include_deny: true,
            overlap_read_write_with_deny: true,
            use_runtime_roots: true,
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
            let deny_path = if case.overlap_read_write_with_deny {
                fixture.rw_dir.clone()
            } else {
                fixture.deny_dir.clone()
            };
            path_permissions.push(SandboxPathPermission::deny(deny_path));
        }

        let test_policy = if case.use_runtime_roots {
            no_access_policy_with_runtime_roots(false, path_permissions)
        } else {
            policy(case.default_access, false, path_permissions)
        };
        let probe_cwd = request_cwd_for_case(&case, &fixture);
        let result = manager.execute(
            &sandbox_request(
                vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "exit 0".to_string(),
                ],
                probe_cwd,
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
            (Expectation::AcceptedShapeOnly, Err(SandboxError::InvalidRequest(message))) => panic!(
                "{}: expected accepted shape, got InvalidRequest: {}",
                case.name, message
            ),
            (Expectation::AcceptedShapeOnly, _) => {}
        }
    }
}

#[test]
fn no_access_default_supports_read_only_and_read_write_carveouts() {
    let fixture = Fixture::new("matrix-no-access-carveouts");
    let manager = SandboxManager::new();

    let test_policy = no_access_policy_with_runtime_roots(
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

#[test]
fn no_access_default_non_overlapping_deny_remains_runnable_and_fails_closed_for_denied_path() {
    let fixture = Fixture::new("matrix-no-access-non-overlap-deny");
    let manager = SandboxManager::new();

    let test_policy = no_access_policy_with_runtime_roots(
        false,
        vec![
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::deny(fixture.deny_dir.clone()),
        ],
    );

    let read_ro = execute_case(
        &manager,
        &sandbox_request(read_command(&fixture.ro_seed), &fixture.ro_dir, 2_500),
        &test_policy,
        "no_access_default non-overlap deny read readonly seed",
    );
    assert_success(
        &read_ro,
        "no_access_default non-overlap deny read readonly seed",
    );

    let write_rw_target = fixture.rw_dir.join("allowed-matrix-no-access-deny.txt");
    let write_rw = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_rw_target, "allowed"),
            &fixture.rw_dir,
            2_500,
        ),
        &test_policy,
        "no_access_default non-overlap deny write readwrite path",
    );
    assert_success(
        &write_rw,
        "no_access_default non-overlap deny write readwrite path",
    );

    let read_deny = execute_case(
        &manager,
        &sandbox_request(read_command(&fixture.deny_seed), &fixture.ro_dir, 2_500),
        &test_policy,
        "no_access_default non-overlap deny read deny path",
    );
    assert_failure(
        &read_deny,
        "no_access_default non-overlap deny read deny path",
    );

    let write_deny_target = fixture.deny_dir.join("blocked-matrix-no-access-deny.txt");
    let write_deny = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_deny_target, "blocked"),
            &fixture.ro_dir,
            2_500,
        ),
        &test_policy,
        "no_access_default non-overlap deny write deny path",
    );
    assert_failure(
        &write_deny,
        "no_access_default non-overlap deny write deny path",
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_read_only_default_with_deny_is_enforced_when_overlays_are_available() {
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
fn linux_no_access_overlap_allow_and_deny_is_enforced_when_overlays_are_available() {
    use std::fs;

    let fixture = Fixture::new("matrix-linux-noaccess-overlap");
    let manager = SandboxManager::new();

    let blocked_dir = fixture.rw_dir.join("blocked-subtree");
    fs::create_dir_all(&blocked_dir).expect("blocked subtree should be created");
    let blocked_seed = blocked_dir.join("blocked-seed.txt");
    fs::write(&blocked_seed, "blocked-seed").expect("blocked seed should be created");

    let test_policy = no_access_policy_with_runtime_roots(
        false,
        vec![
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::deny(blocked_dir.clone()),
        ],
    );

    let read_ro_request = sandbox_request(read_command(&fixture.ro_seed), &fixture.ro_dir, 2_500);
    let read_ro = match manager.execute(&read_ro_request, &test_policy) {
        Ok(output) => output,
        Err(SandboxError::Unavailable(message)) if message.contains("mount-namespace support") => {
            return;
        }
        Err(error) => {
            panic!(
                "linux no_access overlap read readonly seed: manager execution failed: {error:?}"
            )
        }
    };
    assert_success(&read_ro, "linux no_access overlap read readonly seed");

    let write_rw_target = fixture.rw_dir.join("allowed-linux-noaccess-overlap.txt");
    let write_rw_request = sandbox_request(
        write_command(&write_rw_target, "allowed"),
        &fixture.ro_dir,
        2_500,
    );
    let write_rw = execute_case(
        &manager,
        &write_rw_request,
        &test_policy,
        "linux no_access overlap write allowed path",
    );
    assert_success(&write_rw, "linux no_access overlap write allowed path");

    let read_blocked = execute_case(
        &manager,
        &sandbox_request(read_command(&blocked_seed), &fixture.ro_dir, 2_500),
        &test_policy,
        "linux no_access overlap read blocked subtree",
    );
    assert_failure(
        &read_blocked,
        "linux no_access overlap read blocked subtree",
    );

    let blocked_write_target = blocked_dir.join("blocked-write.txt");
    let write_blocked = execute_case(
        &manager,
        &sandbox_request(
            write_command(&blocked_write_target, "blocked"),
            &fixture.ro_dir,
            2_500,
        ),
        &test_policy,
        "linux no_access overlap write blocked subtree",
    );
    assert_failure(
        &write_blocked,
        "linux no_access overlap write blocked subtree",
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_overlay_backed_subtractive_paths_require_existing_targets() {
    let fixture = Fixture::new("matrix-linux-existing-overlay-targets");
    let manager = SandboxManager::new();

    let missing_overlap_target = fixture.rw_dir.join("future-blocked.txt");
    assert!(
        !missing_overlap_target.exists(),
        "test requires a missing overlay target"
    );

    let read_write_policy = policy(
        SandboxAccess::ReadWrite,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::deny(missing_overlap_target.clone()),
        ],
    );
    let read_write_result = manager.execute(
        &sandbox_request(
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 0".to_string(),
            ],
            &fixture.runtime_cwd,
            2_500,
        ),
        &read_write_policy,
    );
    match read_write_result {
        Err(SandboxError::InvalidRequest(message)) => {
            assert!(
                message.contains(
                    "linux backend requires existing deny overlay targets for default_access=ReadWrite"
                ),
                "unexpected read_write missing-overlay error: {message}"
            );
        }
        other => panic!(
            "read_write default with missing deny overlay target should fail closed, got {other:?}"
        ),
    }

    let no_access_overlap_policy = no_access_policy_with_runtime_roots(
        false,
        vec![
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::deny(missing_overlap_target.clone()),
        ],
    );
    let no_access_overlap_result = manager.execute(
        &sandbox_request(
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 0".to_string(),
            ],
            &fixture.rw_dir,
            2_500,
        ),
        &no_access_overlap_policy,
    );
    match no_access_overlap_result {
        Err(SandboxError::InvalidRequest(message)) => {
            assert!(
                message.contains(
                    "linux backend requires existing deny overlay targets for default_access=NoAccess with overlapping deny overlays"
                ),
                "unexpected no_access overlap missing-overlay error: {message}"
            );
        }
        other => {
            panic!("no_access overlap with missing deny target should fail closed, got {other:?}")
        }
    }

    let missing_non_overlap_deny = fixture.outside_dir.join("future-deny.txt");
    assert!(
        !missing_non_overlap_deny.exists(),
        "test requires a missing non-overlapping deny target"
    );

    let no_access_non_overlap_policy = no_access_policy_with_runtime_roots(
        false,
        vec![
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::deny(missing_non_overlap_deny),
        ],
    );
    let non_overlap_result = manager.execute(
        &sandbox_request(
            vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 0".to_string(),
            ],
            &fixture.rw_dir,
            2_500,
        ),
        &no_access_non_overlap_policy,
    );
    let non_overlap_output = non_overlap_result.unwrap_or_else(|error| {
        panic!("no_access non-overlap missing deny should stay accepted: {error:?}")
    });
    assert_success(
        &non_overlap_output,
        "linux no_access non-overlap missing deny should stay accepted",
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

#[cfg(target_os = "macos")]
#[test]
fn macos_no_access_overlap_allow_and_deny_is_enforced() {
    use std::fs;

    let fixture = Fixture::new("matrix-macos-noaccess-overlap");
    let manager = SandboxManager::new();

    let blocked_dir = fixture.rw_dir.join("blocked-subtree");
    fs::create_dir_all(&blocked_dir).expect("blocked subtree should be created");
    let blocked_seed = blocked_dir.join("blocked-seed.txt");
    fs::write(&blocked_seed, "blocked-seed").expect("blocked seed should be created");

    let test_policy = no_access_policy_with_runtime_roots(
        false,
        vec![
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::deny(blocked_dir.clone()),
        ],
    );

    let read_ro = execute_case(
        &manager,
        &sandbox_request(read_command(&fixture.ro_seed), &fixture.ro_dir, 2_500),
        &test_policy,
        "macos no_access overlap read readonly seed",
    );
    assert_success(&read_ro, "macos no_access overlap read readonly seed");

    let write_rw_target = fixture
        .rw_dir
        .join("allowed-matrix-macos-noaccess-overlap.txt");
    let write_rw = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_rw_target, "allowed"),
            &fixture.rw_dir,
            2_500,
        ),
        &test_policy,
        "macos no_access overlap write allowed path",
    );
    assert_success(&write_rw, "macos no_access overlap write allowed path");

    let read_blocked = execute_case(
        &manager,
        &sandbox_request(read_command(&blocked_seed), &fixture.ro_dir, 2_500),
        &test_policy,
        "macos no_access overlap read blocked subtree",
    );
    assert_failure(
        &read_blocked,
        "macos no_access overlap read blocked subtree",
    );

    let blocked_write_target = blocked_dir.join("blocked-write.txt");
    let write_blocked = execute_case(
        &manager,
        &sandbox_request(
            write_command(&blocked_write_target, "blocked"),
            &fixture.ro_dir,
            2_500,
        ),
        &test_policy,
        "macos no_access overlap write blocked subtree",
    );
    assert_failure(
        &write_blocked,
        "macos no_access overlap write blocked subtree",
    );
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

fn request_cwd_for_case<'a>(case: &CombinationCase, fixture: &'a Fixture) -> &'a std::path::Path {
    if !matches!(case.default_access, SandboxAccess::NoAccess) {
        return &fixture.runtime_cwd;
    }

    if case.use_runtime_roots {
        if case.include_read_write && !case.overlap_read_write_with_deny {
            return &fixture.rw_dir;
        }
        if case.include_read_only {
            return &fixture.ro_dir;
        }
    }

    &fixture.runtime_cwd
}
