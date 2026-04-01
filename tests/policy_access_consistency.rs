mod common;

use std::fs;

use procwarden::{SandboxAccess, SandboxError, SandboxManager, SandboxPathPermission};

use common::{
    Fixture, assert_denied_or_failed, assert_failure, assert_success, execute_case,
    no_access_policy_with_runtime_roots, policy, read_command, sandbox_request,
    should_skip_windows_wfp_unavailable, write_command,
};

#[cfg(not(target_os = "macos"))]
#[test]
fn default_no_access_enforces_readonly_readwrite_and_outside_denial() {
    let fixture = Fixture::new("policy-noaccess");
    let manager = SandboxManager::new();

    let test_policy = no_access_policy_with_runtime_roots(
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
        ],
    );

    let read_ro_request =
        sandbox_request(read_command(&fixture.ro_seed), &fixture.runtime_cwd, 2_500);
    let read_ro_result = manager.execute(&read_ro_request, &test_policy);
    if should_skip_windows_wfp_unavailable(&read_ro_result) {
        eprintln!(
            "skip policy_access_consistency default_no_access test because Windows WFP is unsupported in this environment"
        );
        return;
    }
    let read_ro = read_ro_result.unwrap_or_else(|error| {
        panic!("default_no_access read readonly seed: manager execution failed: {error:?}")
    });
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

#[cfg(target_os = "macos")]
#[test]
fn default_no_access_allowlist_shape_is_accepted_but_bootstrap_is_target_dependent() {
    let fixture = Fixture::new("policy-noaccess");
    let manager = SandboxManager::new();

    let test_policy = no_access_policy_with_runtime_roots(
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
        ],
    );

    let read_ro_request =
        sandbox_request(read_command(&fixture.ro_seed), &fixture.runtime_cwd, 2_500);
    let read_ro_result = manager.execute(&read_ro_request, &test_policy);
    match read_ro_result {
        Ok(_) => {}
        Err(error) => {
            panic!(
                "default_no_access macos shape acceptance probe: manager execution failed: {error:?}"
            )
        }
    }
}

#[cfg(target_os = "linux")]
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

    let read_ro_request =
        sandbox_request(read_command(&fixture.ro_seed), &fixture.runtime_cwd, 2_500);
    let read_ro = match manager.execute(&read_ro_request, &test_policy) {
        Ok(output) => output,
        Err(SandboxError::Unavailable(message)) if message.contains("mount-namespace support") => {
            return;
        }
        Err(error) => {
            panic!("default_read_only read readonly seed: manager execution failed: {error:?}")
        }
    };
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
    let write_rw_request = sandbox_request(
        write_command(&write_rw_target, "allowed-readonly-carveout"),
        &fixture.runtime_cwd,
        2_500,
    );
    let write_rw = execute_case(
        &manager,
        &write_rw_request,
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

#[cfg(target_os = "macos")]
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
    let write_outside_request = sandbox_request(
        write_command(&write_outside_target, "allowed-readwrite-global"),
        &fixture.runtime_cwd,
        2_500,
    );
    let write_outside_result = manager.execute(&write_outside_request, &test_policy);
    if should_skip_windows_wfp_unavailable(&write_outside_result) {
        eprintln!(
            "skip policy_access_consistency default_read_write test because Windows WFP is unsupported in this environment"
        );
        return;
    }
    let write_outside = match write_outside_result {
        Ok(output) => output,
        Err(SandboxError::Unavailable(message))
            if cfg!(target_os = "linux") && message.contains("mount-namespace support") =>
        {
            return;
        }
        Err(error) => {
            panic!("default_read_write write outside path: manager execution failed: {error:?}")
        }
    };
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

#[cfg(target_os = "linux")]
#[test]
fn linux_no_access_without_runtime_roots_does_not_bootstrap_basic_read_command() {
    let fixture = Fixture::new("policy-noaccess-missing-runtime-roots");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxAccess::NoAccess,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
        ],
    );

    let result = manager.execute(
        &sandbox_request(read_command(&fixture.ro_seed), &fixture.runtime_cwd, 2_500),
        &test_policy,
    );

    assert!(
        !matches!(result, Ok(output) if output.exit_code == 0),
        "linux NoAccess shell/bootstrap commands should not succeed without runtime roots"
    );
}
