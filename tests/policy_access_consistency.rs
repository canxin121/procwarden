mod common;

use std::fs;

use procwarden::{SandboxAccess, SandboxManager, SandboxPathPermission};

use common::{
    Fixture, assert_denied_or_failed, assert_failure, assert_success, execute_case, policy,
    read_command, sandbox_request, write_command,
};

#[test]
fn default_no_access_enforces_readonly_readwrite_and_outside_denial() {
    let fixture = Fixture::new("policy-noaccess");
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
        "default_no_access read readonly seed",
    );
    assert_success(&read_ro, "default_no_access read readonly seed");

    let ro_write_target = fixture.ro_dir.join("blocked-noaccess.txt");
    let write_ro = execute_case(
        &manager,
        &sandbox_request(
            write_command(&ro_write_target, "blocked"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_no_access write readonly path",
    );
    assert_failure(&write_ro, "default_no_access write readonly path");
    assert!(
        !ro_write_target.exists(),
        "default_no_access write readonly path should not create file"
    );

    let rw_write_target = fixture.rw_dir.join("allowed-noaccess.txt");
    let write_rw = execute_case(
        &manager,
        &sandbox_request(
            write_command(&rw_write_target, "allowed-noaccess"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_no_access write readwrite path",
    );
    assert_success(&write_rw, "default_no_access write readwrite path");
    assert_eq!(
        fs::read_to_string(&rw_write_target).expect("readwrite target should exist"),
        "allowed-noaccess"
    );

    let read_outside = execute_case(
        &manager,
        &sandbox_request(
            read_command(&fixture.outside_seed),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_no_access read outside path",
    );
    assert_failure(&read_outside, "default_no_access read outside path");

    let outside_write_target = fixture.outside_dir.join("blocked-noaccess.txt");
    let write_outside = execute_case(
        &manager,
        &sandbox_request(
            write_command(&outside_write_target, "blocked-outside"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_no_access write outside path",
    );
    assert_failure(&write_outside, "default_no_access write outside path");
    assert!(
        !outside_write_target.exists(),
        "default_no_access write outside path should not create file"
    );
}

#[test]
fn default_read_only_enforces_readwrite_carveout_and_deny_override() {
    let fixture = Fixture::new("policy-readonly");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxAccess::ReadOnly,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::deny(fixture.deny_dir.clone()),
        ],
    );

    let read_ro = execute_case(
        &manager,
        &sandbox_request(read_command(&fixture.ro_seed), &fixture.runtime_cwd, 2_500),
        &test_policy,
        "default_read_only read readonly seed",
    );
    assert_success(&read_ro, "default_read_only read readonly seed");

    let read_outside = execute_case(
        &manager,
        &sandbox_request(
            read_command(&fixture.outside_seed),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_only read outside path",
    );
    assert_success(&read_outside, "default_read_only read outside path");

    let write_ro_target = fixture.ro_dir.join("blocked-readonly.txt");
    let write_ro = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_ro_target, "blocked-readonly"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_only write readonly path",
    );
    assert_failure(&write_ro, "default_read_only write readonly path");
    assert!(
        !write_ro_target.exists(),
        "default_read_only write readonly path should not create file"
    );

    let write_rw_target = fixture.rw_dir.join("allowed-readonly-carveout.txt");
    let write_rw = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_rw_target, "allowed-readonly-carveout"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_only write readwrite carveout",
    );
    assert_success(&write_rw, "default_read_only write readwrite carveout");
    assert_eq!(
        fs::read_to_string(&write_rw_target).expect("readwrite carveout target should exist"),
        "allowed-readonly-carveout"
    );

    assert_denied_or_failed(
        &manager,
        &sandbox_request(
            read_command(&fixture.deny_seed),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_only read deny path",
    );

    let outside_write_target = fixture.outside_dir.join("blocked-readonly.txt");
    let write_outside = execute_case(
        &manager,
        &sandbox_request(
            write_command(&outside_write_target, "blocked-readonly-outside"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_only write outside path",
    );
    assert_failure(&write_outside, "default_read_only write outside path");
    assert!(
        !outside_write_target.exists(),
        "default_read_only write outside path should not create file"
    );
}

#[test]
fn default_read_write_enforces_readonly_and_deny_overrides() {
    let fixture = Fixture::new("policy-readwrite");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxAccess::ReadWrite,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
            SandboxPathPermission::deny(fixture.deny_dir.clone()),
        ],
    );

    let write_outside_target = fixture.outside_dir.join("allowed-readwrite-global.txt");
    let write_outside = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_outside_target, "allowed-readwrite-global"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_write write outside path",
    );
    assert_success(&write_outside, "default_read_write write outside path");
    assert_eq!(
        fs::read_to_string(&write_outside_target).expect("outside write target should exist"),
        "allowed-readwrite-global"
    );

    let write_ro_target = fixture.ro_dir.join("blocked-readwrite-override.txt");
    let write_ro = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_ro_target, "blocked-readwrite-override"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_write write readonly override",
    );
    assert_failure(&write_ro, "default_read_write write readonly override");
    assert!(
        !write_ro_target.exists(),
        "default_read_write readonly override should not create file"
    );

    assert_denied_or_failed(
        &manager,
        &sandbox_request(
            read_command(&fixture.deny_seed),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_write read deny override",
    );

    let write_deny_target = fixture.deny_dir.join("blocked-readwrite-deny.txt");
    assert_denied_or_failed(
        &manager,
        &sandbox_request(
            write_command(&write_deny_target, "blocked-readwrite-deny"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_write write deny override",
    );
    assert!(
        !write_deny_target.exists(),
        "default_read_write deny override should not create file"
    );

    let read_ro = execute_case(
        &manager,
        &sandbox_request(read_command(&fixture.ro_seed), &fixture.runtime_cwd, 2_500),
        &test_policy,
        "default_read_write read readonly path",
    );
    assert_success(&read_ro, "default_read_write read readonly path");
}
