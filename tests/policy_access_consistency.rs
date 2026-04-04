mod common;

use std::fs;

use procwarden::{SandboxDefaultAccess, SandboxError, SandboxManager, SandboxPathPermission};

use common::{
    Fixture, assert_failure, assert_success, execute_case, policy, read_command, sandbox_request,
    should_skip_windows_wfp_unavailable, write_command,
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn default_read_only_enforces_readwrite_carveout() {
    let fixture = Fixture::new("policy-readonly");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxDefaultAccess::ReadOnly,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
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
fn default_read_write_enforces_readonly_overrides() {
    let fixture = Fixture::new("policy-readwrite");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxDefaultAccess::ReadWrite,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
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

    let read_ro = execute_case(
        &manager,
        &sandbox_request(read_command(&fixture.ro_seed), &fixture.runtime_cwd, 2_500),
        &test_policy,
        "default_read_write read readonly path",
    );
    assert_success(&read_ro, "default_read_write read readonly path");
}

#[test]
fn default_read_write_enforces_deny_overrides() {
    let fixture = Fixture::new("policy-readwrite-deny");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxDefaultAccess::ReadWrite,
        false,
        vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::deny(fixture.deny_dir.clone()),
        ],
    );

    let outside_write_target = fixture.outside_dir.join("allowed-readwrite-deny.txt");
    let outside_write_request = sandbox_request(
        write_command(&outside_write_target, "allowed-readwrite-deny"),
        &fixture.runtime_cwd,
        2_500,
    );
    let outside_write_result = manager.execute(&outside_write_request, &test_policy);
    if should_skip_windows_wfp_unavailable(&outside_write_result) {
        eprintln!(
            "skip policy_access_consistency default_read_write deny test because Windows WFP is unsupported in this environment"
        );
        return;
    }
    let outside_write = match outside_write_result {
        Ok(output) => output,
        Err(SandboxError::Unavailable(message))
            if cfg!(target_os = "linux") && message.contains("mount-namespace support") =>
        {
            return;
        }
        Err(error) => {
            panic!(
                "default_read_write write outside path with deny: manager execution failed: {error:?}"
            )
        }
    };
    assert_success(
        &outside_write,
        "default_read_write write outside path with deny",
    );

    let read_deny = execute_case(
        &manager,
        &sandbox_request(
            read_command(&fixture.deny_seed),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_write read denied path",
    );
    assert_failure(&read_deny, "default_read_write read denied path");

    let write_deny_target = fixture.deny_dir.join("blocked-readwrite-deny.txt");
    let write_deny = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_deny_target, "blocked-readwrite-deny"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_write write denied path",
    );
    assert_failure(&write_deny, "default_read_write write denied path");
    assert!(
        !write_deny_target.exists(),
        "default_read_write deny override should not create file"
    );
}

#[test]
fn default_read_only_enforces_deny_overrides() {
    let fixture = Fixture::new("policy-readonly-deny");
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

    let write_rw_target = fixture.rw_dir.join("allowed-readonly-deny-carveout.txt");
    let write_rw_request = sandbox_request(
        write_command(&write_rw_target, "allowed-readonly-deny-carveout"),
        &fixture.runtime_cwd,
        2_500,
    );
    let write_rw_result = manager.execute(&write_rw_request, &test_policy);
    if should_skip_windows_wfp_unavailable(&write_rw_result) {
        eprintln!(
            "skip policy_access_consistency default_read_only deny test because Windows WFP is unsupported in this environment"
        );
        return;
    }
    let write_rw = match write_rw_result {
        Ok(output) => output,
        Err(SandboxError::Unavailable(message))
            if cfg!(target_os = "linux") && message.contains("mount-namespace support") =>
        {
            return;
        }
        Err(error) => {
            panic!(
                "default_read_only write readwrite carveout with deny: manager execution failed: {error:?}"
            )
        }
    };
    assert_success(
        &write_rw,
        "default_read_only write readwrite carveout with deny",
    );

    let read_deny = execute_case(
        &manager,
        &sandbox_request(
            read_command(&fixture.deny_seed),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_only read denied path",
    );
    assert_failure(&read_deny, "default_read_only read denied path");

    let write_deny_target = fixture.deny_dir.join("blocked-readonly-deny.txt");
    let write_deny = execute_case(
        &manager,
        &sandbox_request(
            write_command(&write_deny_target, "blocked-readonly-deny"),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "default_read_only write denied path",
    );
    assert_failure(&write_deny, "default_read_only write denied path");
    assert!(
        !write_deny_target.exists(),
        "default_read_only deny override should not create file"
    );
}
