use std::collections::HashMap;
use std::error::Error;
use std::fs;
#[cfg(target_os = "windows")]
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::time::Duration;
#[cfg(target_os = "windows")]
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

use procwarden::{
    SandboxCommandRequest, SandboxDefaultAccess, SandboxError, SandboxManager,
    SandboxNetworkPolicy, SandboxPathPermission, SandboxPolicy,
};

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    if maybe_run_windows_network_probe_mode() {
        return Ok(());
    }

    println!("platform={}", std::env::consts::OS);

    probe_frontloaded_missing_path_validation()?;

    #[cfg(target_os = "linux")]
    probe_linux_overlay_capability()?;

    #[cfg(target_os = "linux")]
    probe_linux_policy_shape_matrix()?;

    #[cfg(target_os = "linux")]
    probe_linux_enforcement_cases()?;

    #[cfg(target_os = "macos")]
    probe_macos_matrix_contract()?;

    #[cfg(target_os = "windows")]
    probe_windows_matrix_and_timings()?;

    Ok(())
}

fn probe_frontloaded_missing_path_validation() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("frontloaded-missing-path");
    let manager = SandboxManager::new();
    let missing_path = fixture.runtime_cwd.join("missing-readonly-target");

    let policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadWrite,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![SandboxPathPermission::read_only(missing_path.clone())],
    };

    let result = manager.execute(
        &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
        &policy,
    );
    match result {
        Err(SandboxError::InvalidRequest(message))
            if message.contains("read_only path does not exist") =>
        {
            println!("manager.missing_path_validation=frontloaded_invalid_request");
            Ok(())
        }
        other => Err(format!(
            "expected frontloaded InvalidRequest for missing policy path, got {other:?}"
        )
        .into()),
    }
}

#[cfg(target_os = "linux")]
fn probe_linux_overlay_capability() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("linux-overlay-capability");
    let manager = SandboxManager::new();
    let policy = readwrite_with_readonly_policy(&fixture);

    let bootstrap = manager.execute(
        &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
        &policy,
    );
    match bootstrap {
        Ok(output) => {
            assert_success(&output, "linux bootstrap command")?;
            println!("linux.overlay_subtractive=available");
            Ok(())
        }
        Err(SandboxError::Unavailable(message)) if message.contains("mount-namespace support") => {
            println!("linux.overlay_subtractive=unavailable");
            println!("linux.unavailable_reason={message}");
            Ok(())
        }
        Err(error) => Err(format!("unexpected linux overlay capability result: {error:?}").into()),
    }
}

#[cfg(target_os = "linux")]
fn probe_linux_policy_shape_matrix() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("linux-matrix-contract");
    let manager = SandboxManager::new();

    let cases = vec![
        LinuxMatrixCase::new(
            "readwrite_none",
            SandboxDefaultAccess::ReadWrite,
            false,
            false,
            false,
        ),
        LinuxMatrixCase::new(
            "readwrite_readwrite",
            SandboxDefaultAccess::ReadWrite,
            false,
            true,
            false,
        ),
        LinuxMatrixCase::new(
            "readwrite_readonly",
            SandboxDefaultAccess::ReadWrite,
            true,
            false,
            false,
        ),
        LinuxMatrixCase::new(
            "readwrite_deny",
            SandboxDefaultAccess::ReadWrite,
            false,
            false,
            true,
        ),
        LinuxMatrixCase::new(
            "readwrite_readonly_readwrite",
            SandboxDefaultAccess::ReadWrite,
            true,
            true,
            false,
        ),
        LinuxMatrixCase::new(
            "readwrite_readonly_deny",
            SandboxDefaultAccess::ReadWrite,
            true,
            false,
            true,
        ),
        LinuxMatrixCase::new(
            "readonly_none",
            SandboxDefaultAccess::ReadOnly,
            false,
            false,
            false,
        ),
        LinuxMatrixCase::new(
            "readonly_readonly",
            SandboxDefaultAccess::ReadOnly,
            true,
            false,
            false,
        ),
        LinuxMatrixCase::new(
            "readonly_readwrite",
            SandboxDefaultAccess::ReadOnly,
            false,
            true,
            false,
        ),
        LinuxMatrixCase::new(
            "readonly_deny",
            SandboxDefaultAccess::ReadOnly,
            false,
            false,
            true,
        ),
        LinuxMatrixCase::new(
            "readonly_readonly_readwrite",
            SandboxDefaultAccess::ReadOnly,
            true,
            true,
            false,
        ),
        LinuxMatrixCase::new(
            "readonly_readwrite_deny",
            SandboxDefaultAccess::ReadOnly,
            false,
            true,
            true,
        ),
    ];

    for case in cases {
        let result = manager.execute(
            &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
            &case.policy(&fixture),
        );
        println!(
            "linux.matrix.{}={}",
            case.name,
            render_unix_matrix_result(&result)
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn probe_linux_enforcement_cases() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("linux-enforcement");
    let manager = SandboxManager::new();

    let readonly_readwrite_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
        ],
    };

    let write_rw_target = fixture.rw_dir.join("probe-readonly-rw.txt");
    let write_rw = manager.execute(
        &sandbox_request(write_command(&write_rw_target, "ok"), &fixture.runtime_cwd),
        &readonly_readwrite_policy,
    )?;
    assert_success(&write_rw, "linux readonly+readwrite write carve-out")?;

    let write_outside_target = fixture.deny_dir.join("probe-readonly-outside.txt");
    let write_outside = manager.execute(
        &sandbox_request(
            write_command(&write_outside_target, "blocked"),
            &fixture.runtime_cwd,
        ),
        &readonly_readwrite_policy,
    )?;
    assert_failure(&write_outside, "linux readonly+readwrite outside write")?;
    println!("linux.enforcement.readonly_readwrite=ok");

    let overlay_bootstrap = manager.execute(
        &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
        &readwrite_with_readonly_policy(&fixture),
    );
    if let Err(SandboxError::Unavailable(message)) = &overlay_bootstrap
        && message.contains("mount-namespace support")
    {
        let reason = sanitize_probe_message(message);
        println!("linux.readwrite_plus_readonly_enforcement=unavailable({reason})");
        println!("linux.readwrite_plus_deny_enforcement=unavailable({reason})");
        println!("linux.enforcement.readwrite_readonly=unavailable({reason})");
        println!("linux.enforcement.readwrite_deny=unavailable({reason})");
        println!("linux.enforcement.readonly_deny=unavailable({reason})");
        println!("linux.enforcement.readonly_readwrite_deny=unavailable({reason})");
        return Ok(());
    }
    let overlay_bootstrap =
        overlay_bootstrap.map_err(|error| format!("linux overlay bootstrap failed: {error:?}"))?;
    assert_success(&overlay_bootstrap, "linux overlay bootstrap")?;

    let readwrite_readonly_policy = readwrite_with_readonly_policy(&fixture);
    let write_other_target = fixture.rw_dir.join("probe-readwrite-outside.txt");
    let write_other = manager.execute(
        &sandbox_request(
            write_command(&write_other_target, "outside-ok"),
            &fixture.runtime_cwd,
        ),
        &readwrite_readonly_policy,
    )?;
    assert_success(&write_other, "linux readwrite+readonly other write")?;

    let write_ro_target = fixture.ro_dir.join("probe-readwrite-ro.txt");
    let write_ro = manager.execute(
        &sandbox_request(
            write_command(&write_ro_target, "blocked"),
            &fixture.runtime_cwd,
        ),
        &readwrite_readonly_policy,
    )?;
    assert_failure(&write_ro, "linux readwrite+readonly readonly override")?;
    let read_ro = manager.execute(
        &sandbox_request(read_command(&fixture.ro_seed), &fixture.runtime_cwd),
        &readwrite_readonly_policy,
    )?;
    assert_success(&read_ro, "linux readwrite+readonly read seed")?;
    println!("linux.enforcement.readwrite_readonly=ok");
    println!("linux.readwrite_plus_readonly_enforcement=ok");

    let readwrite_deny_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadWrite,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![SandboxPathPermission::deny(fixture.deny_dir.clone())],
    };
    let read_deny = manager.execute(
        &sandbox_request(read_command(&fixture.deny_seed), &fixture.runtime_cwd),
        &readwrite_deny_policy,
    )?;
    assert_failure(&read_deny, "linux readwrite+deny denied read")?;
    let write_deny_target = fixture.deny_dir.join("probe-readwrite-deny.txt");
    let write_deny = manager.execute(
        &sandbox_request(
            write_command(&write_deny_target, "blocked"),
            &fixture.runtime_cwd,
        ),
        &readwrite_deny_policy,
    )?;
    assert_failure(&write_deny, "linux readwrite+deny denied write")?;
    println!("linux.enforcement.readwrite_deny=ok");
    println!("linux.readwrite_plus_deny_enforcement=ok");

    let readonly_deny_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![SandboxPathPermission::deny(fixture.deny_dir.clone())],
    };
    let readonly_deny = manager.execute(
        &sandbox_request(read_command(&fixture.deny_seed), &fixture.runtime_cwd),
        &readonly_deny_policy,
    )?;
    assert_failure(&readonly_deny, "linux readonly+deny denied read")?;
    println!("linux.enforcement.readonly_deny=ok");

    let nested_deny_dir = fixture.rw_dir.join("nested-deny");
    fs::create_dir_all(&nested_deny_dir)?;
    let nested_deny_seed = nested_deny_dir.join("seed-nested-deny.txt");
    fs::write(&nested_deny_seed, "nested-deny-seed")?;

    let readonly_nested_deny_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::deny(nested_deny_dir.clone()),
        ],
    };

    let write_nested_parent_target = fixture.rw_dir.join("probe-readonly-nested-parent.txt");
    let write_nested_parent = manager.execute(
        &sandbox_request(
            write_command(&write_nested_parent_target, "parent-ok"),
            &fixture.runtime_cwd,
        ),
        &readonly_nested_deny_policy,
    )?;
    assert_success(
        &write_nested_parent,
        "linux readonly+readwrite+nested-deny parent write",
    )?;

    let read_nested_deny = manager.execute(
        &sandbox_request(read_command(&nested_deny_seed), &fixture.runtime_cwd),
        &readonly_nested_deny_policy,
    )?;
    assert_failure(
        &read_nested_deny,
        "linux readonly+readwrite+nested-deny denied read",
    )?;

    let write_nested_deny_target = nested_deny_dir.join("probe-readonly-nested-deny.txt");
    let write_nested_deny = manager.execute(
        &sandbox_request(
            write_command(&write_nested_deny_target, "blocked"),
            &fixture.runtime_cwd,
        ),
        &readonly_nested_deny_policy,
    )?;
    assert_failure(
        &write_nested_deny,
        "linux readonly+readwrite+nested-deny denied write",
    )?;
    println!("linux.enforcement.readonly_readwrite_deny=ok");

    Ok(())
}

#[cfg(target_os = "macos")]
fn probe_macos_matrix_contract() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("macos-matrix-contract");
    let manager = SandboxManager::new();
    let policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_write(fixture.alias_rw_dir.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
            SandboxPathPermission::deny(fixture.deny_dir.clone()),
        ],
    };

    let write_target = fixture.rw_dir.join("macos-overlay-write.txt");
    let write_output = manager.execute(
        &sandbox_request(
            write_command(&write_target, "seatbelt-ok"),
            &fixture.runtime_cwd,
        ),
        &policy,
    )?;
    assert_success(&write_output, "macos writable carve-out")?;

    let readonly_target = fixture.ro_dir.join("macos-readonly-blocked.txt");
    let readonly_output = manager.execute(
        &sandbox_request(
            write_command(&readonly_target, "blocked"),
            &fixture.runtime_cwd,
        ),
        &policy,
    )?;
    assert_failure(&readonly_output, "macos readonly enforcement")?;

    let deny_output = manager.execute(
        &sandbox_request(read_command(&fixture.deny_seed), &fixture.runtime_cwd),
        &policy,
    )?;
    assert_failure(&deny_output, "macos deny enforcement")?;

    let network_disabled = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    };
    let network_outbound_only = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::outbound_only(),
        path_permissions: vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    };
    let network_bidirectional = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::bidirectional(),
        path_permissions: vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    };
    let network_custom = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy {
            allow_unix: true,
            allow_ipv4: true,
            allow_ipv6: false,
            allow_connect: false,
            allow_bind: false,
            allow_listen: false,
            allow_accept: false,
        },
        path_permissions: vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    };

    println!(
        "macos.network.disabled.runnable={}",
        render_unix_matrix_result(&manager.execute(
            &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
            &network_disabled,
        ))
    );
    println!(
        "macos.network.outbound_only.runnable={}",
        render_unix_matrix_result(&manager.execute(
            &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
            &network_outbound_only,
        ))
    );
    println!(
        "macos.network.bidirectional.runnable={}",
        render_unix_matrix_result(&manager.execute(
            &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
            &network_bidirectional,
        ))
    );
    println!(
        "macos.network.custom_ipv4_only={}",
        render_unix_matrix_result(&manager.execute(
            &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
            &network_custom,
        ))
    );

    println!("macos.readonly_plus_readwrite=usable");
    println!("macos.path_deny=usable");
    println!("macos.alias_path_canonicalization=ok");
    Ok(())
}

#[cfg(target_os = "windows")]
fn probe_windows_matrix_and_timings() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new("windows-matrix-contract");
    let manager = SandboxManager::new();

    println!(
        "windows.host_process_elevated={}",
        windows_host_process_is_elevated()?
    );

    probe_windows_network_policy_shape(&manager, &fixture)?;
    probe_windows_policy_shape_matrix(&manager, &fixture)?;
    probe_windows_enforcement_cases(&manager, &fixture)?;
    probe_windows_timing_samples(&manager, &fixture)?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn probe_windows_network_policy_shape(
    manager: &SandboxManager,
    fixture: &Fixture,
) -> Result<(), Box<dyn Error>> {
    let network_bidirectional_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::bidirectional(),
        path_permissions: vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    };
    let network_outbound_only_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::outbound_only(),
        path_permissions: vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    };
    let network_disabled_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    };

    let bidirectional_runnable = manager.execute(
        &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
        &network_bidirectional_policy,
    );
    println!(
        "windows.network.bidirectional.runnable={}",
        render_windows_matrix_result(&bidirectional_runnable)
    );

    let outbound_only_runnable = manager.execute(
        &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
        &network_outbound_only_policy,
    );
    println!(
        "windows.network.outbound_only.runnable={}",
        render_windows_matrix_result(&outbound_only_runnable)
    );

    let disabled_runnable = manager.execute(
        &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
        &network_disabled_policy,
    );
    println!(
        "windows.network.disabled.runnable={}",
        render_windows_matrix_result(&disabled_runnable)
    );

    let loopback_listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("loopback listener bind failed: {error}"))?;
    let loopback_port = loopback_listener
        .local_addr()
        .map_err(|error| format!("loopback listener local_addr failed: {error}"))?
        .port();

    let loopback_bidirectional = manager.execute(
        &sandbox_request(
            windows_network_probe_command("127.0.0.1", loopback_port, 1_500)?,
            &fixture.runtime_cwd,
        ),
        &network_bidirectional_policy,
    );
    println!(
        "windows.network.loopback.same_binary_listener.bidirectional={}",
        render_windows_network_probe_result(&loopback_bidirectional)
    );

    let loopback_outbound_only = manager.execute(
        &sandbox_request(
            windows_network_probe_command("127.0.0.1", loopback_port, 1_500)?,
            &fixture.runtime_cwd,
        ),
        &network_outbound_only_policy,
    );
    println!(
        "windows.network.loopback.same_binary_listener.outbound_only={}",
        render_windows_network_probe_result(&loopback_outbound_only)
    );

    let loopback_disabled = manager.execute(
        &sandbox_request(
            windows_network_probe_command("127.0.0.1", loopback_port, 1_500)?,
            &fixture.runtime_cwd,
        ),
        &network_disabled_policy,
    );
    println!(
        "windows.network.loopback.same_binary_listener.disabled={}",
        render_windows_network_probe_result(&loopback_disabled)
    );

    let Some((gateway_ip, gateway_port)) = default_gateway_private_probe_target() else {
        println!(
            "windows.network.private_network.host_baseline=skipped(no_reachable_default_gateway_target)"
        );
        println!(
            "windows.network.private_network.bidirectional=skipped(no_reachable_default_gateway_target)"
        );
        println!(
            "windows.network.private_network.outbound_only=skipped(no_reachable_default_gateway_target)"
        );
        println!(
            "windows.network.private_network.disabled=skipped(no_reachable_default_gateway_target)"
        );
        return Ok(());
    };

    println!("windows.network.private_network.target={gateway_ip}:{gateway_port}");
    println!("windows.network.private_network.host_baseline=connect_ok");

    let private_bidirectional = manager.execute(
        &sandbox_request(
            windows_network_probe_command(&gateway_ip.to_string(), gateway_port, 1_500)?,
            &fixture.runtime_cwd,
        ),
        &network_bidirectional_policy,
    );
    println!(
        "windows.network.private_network.bidirectional={}",
        render_windows_network_probe_result(&private_bidirectional)
    );

    let private_outbound_only = manager.execute(
        &sandbox_request(
            windows_network_probe_command(&gateway_ip.to_string(), gateway_port, 1_500)?,
            &fixture.runtime_cwd,
        ),
        &network_outbound_only_policy,
    );
    println!(
        "windows.network.private_network.outbound_only={}",
        render_windows_network_probe_result(&private_outbound_only)
    );

    let private_disabled = manager.execute(
        &sandbox_request(
            windows_network_probe_command(&gateway_ip.to_string(), gateway_port, 1_500)?,
            &fixture.runtime_cwd,
        ),
        &network_disabled_policy,
    );
    println!(
        "windows.network.private_network.disabled={}",
        render_windows_network_probe_result(&private_disabled)
    );

    Ok(())
}

#[cfg(target_os = "windows")]
fn probe_windows_policy_shape_matrix(
    manager: &SandboxManager,
    fixture: &Fixture,
) -> Result<(), Box<dyn Error>> {
    let cases = vec![
        WindowsMatrixCase::new(
            "readwrite_none",
            SandboxDefaultAccess::ReadWrite,
            false,
            false,
            false,
        ),
        WindowsMatrixCase::new(
            "readwrite_readwrite",
            SandboxDefaultAccess::ReadWrite,
            false,
            true,
            false,
        ),
        WindowsMatrixCase::new(
            "readwrite_readonly",
            SandboxDefaultAccess::ReadWrite,
            true,
            false,
            false,
        ),
        WindowsMatrixCase::new(
            "readwrite_readonly_readwrite",
            SandboxDefaultAccess::ReadWrite,
            true,
            true,
            false,
        ),
        WindowsMatrixCase::new(
            "readwrite_deny",
            SandboxDefaultAccess::ReadWrite,
            false,
            false,
            true,
        ),
        WindowsMatrixCase::new(
            "readwrite_readonly_deny",
            SandboxDefaultAccess::ReadWrite,
            true,
            false,
            true,
        ),
        WindowsMatrixCase::new(
            "readonly_none",
            SandboxDefaultAccess::ReadOnly,
            false,
            false,
            false,
        ),
        WindowsMatrixCase::new(
            "readonly_readonly",
            SandboxDefaultAccess::ReadOnly,
            true,
            false,
            false,
        ),
        WindowsMatrixCase::new(
            "readonly_readwrite",
            SandboxDefaultAccess::ReadOnly,
            false,
            true,
            false,
        ),
        WindowsMatrixCase::new(
            "readonly_readonly_readwrite",
            SandboxDefaultAccess::ReadOnly,
            true,
            true,
            false,
        ),
        WindowsMatrixCase::new(
            "readonly_deny",
            SandboxDefaultAccess::ReadOnly,
            false,
            false,
            true,
        ),
        WindowsMatrixCase::new(
            "readonly_readwrite_deny",
            SandboxDefaultAccess::ReadOnly,
            false,
            true,
            true,
        ),
    ];

    for case in cases {
        let result = manager.execute(
            &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
            &case.policy(fixture),
        );
        println!(
            "windows.matrix.{}={}",
            case.name,
            render_windows_matrix_result(&result)
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn probe_windows_enforcement_cases(
    manager: &SandboxManager,
    fixture: &Fixture,
) -> Result<(), Box<dyn Error>> {
    let read_only_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
        ],
    };

    let write_rw_target = fixture.rw_dir.join("probe-readonly-rw.txt");
    let write_rw = manager.execute(
        &sandbox_request(write_command(&write_rw_target, "ok"), &fixture.runtime_cwd),
        &read_only_policy,
    );
    if is_windows_wfp_unavailable(&write_rw) {
        println!("windows.enforcement.readonly_readwrite=wfp_unavailable");
        println!("windows.enforcement.readwrite_readonly=wfp_unavailable");
        println!("windows.enforcement.readonly_deny=wfp_unavailable");
        println!("windows.enforcement.readwrite_deny=wfp_unavailable");
        println!("windows.timing.skipped_reason=wfp_unavailable");
        return Ok(());
    }
    assert_success(
        &write_rw
            .map_err(|error| format!("windows readonly+readwrite manager error: {error:?}"))?,
        "windows readonly+readwrite write carve-out",
    )?;

    let write_outside_target = fixture.outside_dir.join("probe-readonly-outside.txt");
    let write_outside = manager.execute(
        &sandbox_request(
            write_command(&write_outside_target, "blocked"),
            &fixture.runtime_cwd,
        ),
        &read_only_policy,
    );
    assert_failed_result(&write_outside, "windows readonly+readwrite outside write")?;
    println!("windows.enforcement.readonly_readwrite=ok");

    let read_write_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadWrite,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_only(fixture.ro_dir.clone()),
        ],
    };

    let write_outside_target = fixture.outside_dir.join("probe-readwrite-outside.txt");
    let write_outside = manager.execute(
        &sandbox_request(
            write_command(&write_outside_target, "outside-ok"),
            &fixture.runtime_cwd,
        ),
        &read_write_policy,
    );
    assert_success(
        &write_outside
            .map_err(|error| format!("windows readwrite+readonly manager error: {error:?}"))?,
        "windows readwrite+readonly outside write",
    )?;

    let write_ro_target = fixture.ro_dir.join("probe-readwrite-ro.txt");
    let write_ro = manager.execute(
        &sandbox_request(
            write_command(&write_ro_target, "blocked"),
            &fixture.runtime_cwd,
        ),
        &read_write_policy,
    );
    assert_failed_result(&write_ro, "windows readwrite+readonly readonly override")?;
    println!("windows.enforcement.readwrite_readonly=ok");

    let read_only_deny_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadOnly,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::read_write(fixture.rw_dir.clone()),
            SandboxPathPermission::deny(fixture.deny_dir.clone()),
        ],
    };
    let read_deny = manager.execute(
        &sandbox_request(read_command(&fixture.deny_seed), &fixture.runtime_cwd),
        &read_only_deny_policy,
    );
    assert_failed_result(&read_deny, "windows readonly+deny denied read")?;
    println!("windows.enforcement.readonly_deny=ok");

    let read_write_deny_policy = SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadWrite,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![
            SandboxPathPermission::read_write(fixture.runtime_cwd.clone()),
            SandboxPathPermission::deny(fixture.deny_dir.clone()),
        ],
    };
    let read_deny = manager.execute(
        &sandbox_request(read_command(&fixture.deny_seed), &fixture.runtime_cwd),
        &read_write_deny_policy,
    );
    assert_failed_result(&read_deny, "windows readwrite+deny denied read")?;
    println!("windows.enforcement.readwrite_deny=ok");

    Ok(())
}

#[cfg(target_os = "windows")]
fn probe_windows_timing_samples(
    manager: &SandboxManager,
    fixture: &Fixture,
) -> Result<(), Box<dyn Error>> {
    println!("windows.timing.note=wall_clock_ms_for_manager_execute");
    println!(
        "windows.timing.redundant_shapes_note=default_equivalent_entries_are_normalized_before_backend_dispatch"
    );

    let cases = vec![
        WindowsTimingCase::new("readonly_none", SandboxDefaultAccess::ReadOnly, vec![]),
        WindowsTimingCase::new(
            "readonly_readwrite",
            SandboxDefaultAccess::ReadOnly,
            vec![SandboxPathPermission::read_write(fixture.rw_dir.clone())],
        ),
        WindowsTimingCase::new(
            "readonly_readonly",
            SandboxDefaultAccess::ReadOnly,
            vec![SandboxPathPermission::read_only(fixture.ro_dir.clone())],
        ),
        WindowsTimingCase::new(
            "readonly_deny",
            SandboxDefaultAccess::ReadOnly,
            vec![SandboxPathPermission::deny(fixture.deny_dir.clone())],
        ),
        WindowsTimingCase::new("readwrite_none", SandboxDefaultAccess::ReadWrite, vec![]),
        WindowsTimingCase::new(
            "readwrite_readonly",
            SandboxDefaultAccess::ReadWrite,
            vec![SandboxPathPermission::read_only(fixture.ro_dir.clone())],
        ),
        WindowsTimingCase::new(
            "readwrite_readwrite",
            SandboxDefaultAccess::ReadWrite,
            vec![SandboxPathPermission::read_write(fixture.rw_dir.clone())],
        ),
        WindowsTimingCase::new(
            "readwrite_deny",
            SandboxDefaultAccess::ReadWrite,
            vec![SandboxPathPermission::deny(fixture.deny_dir.clone())],
        ),
    ];

    for case in cases {
        let Some(samples) = benchmark_windows_policy_case(manager, fixture, &case)? else {
            println!("windows.timing.skipped_reason=wfp_unavailable");
            return Ok(());
        };
        println!(
            "windows.timing.{}.samples_ms={}",
            case.name,
            join_samples(&samples)
        );
        println!(
            "windows.timing.{}.avg_ms={}",
            case.name,
            average_ms(&samples)
        );
        println!(
            "windows.timing.{}.min_ms={}",
            case.name,
            samples.iter().min().copied().unwrap_or_default()
        );
        println!(
            "windows.timing.{}.max_ms={}",
            case.name,
            samples.iter().max().copied().unwrap_or_default()
        );
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn benchmark_windows_policy_case(
    manager: &SandboxManager,
    fixture: &Fixture,
    case: &WindowsTimingCase,
) -> Result<Option<Vec<u128>>, Box<dyn Error>> {
    const ITERATIONS: usize = 3;

    let mut samples = Vec::with_capacity(ITERATIONS);
    let policy = SandboxPolicy {
        default_access: case.default_access,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: case.path_permissions.clone(),
    };

    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let result = manager.execute(
            &sandbox_request(exit_zero_command(), &fixture.runtime_cwd),
            &policy,
        );
        if is_windows_wfp_unavailable(&result) {
            return Ok(None);
        }
        let output = result.map_err(|error| {
            format!(
                "windows timing case {} failed to execute: {error:?}",
                case.name
            )
        })?;
        assert_success(&output, case.name)?;
        samples.push(start.elapsed().as_millis());
    }

    Ok(Some(samples))
}

#[cfg(target_os = "windows")]
fn render_windows_matrix_result(
    result: &Result<procwarden::SandboxExecOutput, SandboxError>,
) -> String {
    match result {
        Ok(output) if output.exit_code == 0 => "runnable".to_string(),
        Ok(output) => format!("command_failed(exit={})", output.exit_code),
        Err(SandboxError::InvalidRequest(message)) => {
            format!("invalid_request({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Denied(message)) => {
            format!("denied({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Unavailable(message)) => {
            format!("unavailable({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Windows(message)) => {
            format!("windows_error({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Io(error)) => {
            format!("io_error({})", sanitize_probe_message(&error.to_string()))
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn sanitize_probe_message(message: &str) -> String {
    message.replace(['\n', '\r'], " ")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn render_unix_matrix_result(
    result: &Result<procwarden::SandboxExecOutput, SandboxError>,
) -> String {
    match result {
        Ok(output) if output.exit_code == 0 => "runnable".to_string(),
        Ok(output) => format!("command_failed(exit={})", output.exit_code),
        Err(SandboxError::InvalidRequest(message)) => {
            format!("invalid_request({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Denied(message)) => {
            format!("denied({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Unavailable(message)) => {
            format!("unavailable({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Io(error)) => {
            format!("io_error({})", sanitize_probe_message(&error.to_string()))
        }
        Err(other) => format!(
            "unexpected({})",
            sanitize_probe_message(&format!("{other:?}"))
        ),
    }
}

#[cfg(target_os = "windows")]
fn render_windows_network_probe_result(
    result: &Result<procwarden::SandboxExecOutput, SandboxError>,
) -> String {
    match result {
        Ok(output) if output.exit_code == 0 => "connect_ok".to_string(),
        Ok(output) => {
            let stderr = sanitize_probe_message(output.stderr.trim());
            let stdout = sanitize_probe_message(output.stdout.trim());
            format!(
                "connect_failed(exit={},stderr={},stdout={})",
                output.exit_code,
                truncate_probe_detail(&stderr),
                truncate_probe_detail(&stdout),
            )
        }
        Err(SandboxError::InvalidRequest(message)) => {
            format!("invalid_request({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Denied(message)) => {
            format!("denied({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Unavailable(message)) => {
            format!("unavailable({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Windows(message)) => {
            format!("windows_error({})", sanitize_probe_message(message))
        }
        Err(SandboxError::Io(error)) => {
            format!("io_error({})", sanitize_probe_message(&error.to_string()))
        }
    }
}

#[cfg(target_os = "windows")]
fn truncate_probe_detail(detail: &str) -> String {
    const MAX_LEN: usize = 160;
    if detail.is_empty() {
        return "none".to_string();
    }
    if detail.len() <= MAX_LEN {
        return detail.to_string();
    }
    format!("{}...", &detail[..MAX_LEN])
}

#[cfg(target_os = "windows")]
fn is_windows_wfp_unavailable(
    result: &Result<procwarden::SandboxExecOutput, SandboxError>,
) -> bool {
    matches!(
        result,
        Err(SandboxError::Windows(message)) if message.contains("FwpmEngineOpen0 failed: 50")
    )
}

#[cfg(target_os = "windows")]
fn assert_failed_result(
    result: &Result<procwarden::SandboxExecOutput, SandboxError>,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    match result {
        Ok(output) if output.exit_code != 0 => Ok(()),
        Ok(output) => Err(format!(
            "{context} succeeded unexpectedly: stdout={}, stderr={}",
            output.stdout, output.stderr
        )
        .into()),
        Err(error) => Err(format!("{context} returned unexpected manager error: {error:?}").into()),
    }
}

#[cfg(target_os = "windows")]
#[cfg(target_os = "windows")]
fn average_ms(samples: &[u128]) -> u128 {
    let total = samples.iter().sum::<u128>();
    total / samples.len() as u128
}

#[cfg(target_os = "windows")]
fn join_samples(samples: &[u128]) -> String {
    samples
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(target_os = "windows")]
fn windows_host_process_is_elevated() -> Result<bool, Box<dyn Error>> {
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "powershell elevation probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    match String::from_utf8_lossy(&output.stdout).trim() {
        "True" => Ok(true),
        "False" => Ok(false),
        other => Err(format!("unexpected powershell elevation probe output: {other}").into()),
    }
}

#[cfg(target_os = "windows")]
fn default_gateway_ipv4() -> Option<Ipv4Addr> {
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 -ExpandProperty NextHop",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    std::str::from_utf8(&output.stdout)
        .ok()?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?
        .parse::<Ipv4Addr>()
        .ok()
}

#[cfg(target_os = "windows")]
fn default_gateway_private_probe_target() -> Option<(Ipv4Addr, u16)> {
    let gateway_ip = default_gateway_ipv4()?;
    for port in [53_u16, 80, 443] {
        if TcpStream::connect_timeout(
            &SocketAddr::from((gateway_ip, port)),
            Duration::from_secs(2),
        )
        .is_ok()
        {
            return Some((gateway_ip, port));
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn windows_network_probe_command(
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<Vec<String>, Box<dyn Error>> {
    Ok(vec![
        std::env::current_exe()?.to_string_lossy().to_string(),
        "--windows-net-probe".to_string(),
        host.to_string(),
        port.to_string(),
        timeout_ms.to_string(),
    ])
}

#[cfg(target_os = "windows")]
fn maybe_run_windows_network_probe_mode() -> bool {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 5 || args.get(1).map(String::as_str) != Some("--windows-net-probe") {
        return false;
    }

    let host = &args[2];
    let port = args[3].parse::<u16>().expect("probe port should parse");
    let timeout_ms = args[4].parse::<u64>().expect("probe timeout should parse");
    run_windows_network_probe(host, port, timeout_ms);
    true
}

#[cfg(target_os = "windows")]
fn run_windows_network_probe(host: &str, port: u16, timeout_ms: u64) {
    use windows_sys::Win32::NetworkManagement::WindowsFirewall::{
        NETISO_ERROR_TYPE_INTERNET_CLIENT, NETISO_ERROR_TYPE_INTERNET_CLIENT_SERVER,
        NETISO_ERROR_TYPE_NONE, NETISO_ERROR_TYPE_PRIVATE_NETWORK,
        NetworkIsolationDiagnoseConnectFailureAndGetInfo,
    };

    fn to_wide(value: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let address = format!("{host}:{port}")
        .parse::<SocketAddr>()
        .expect("probe host must be an IPv4 literal");

    match TcpStream::connect_timeout(&address, Duration::from_millis(timeout_ms)) {
        Ok(stream) => {
            println!("connect=ok");
            drop(stream);
            return;
        }
        Err(error) => {
            eprintln!("connect_error={error}");
        }
    }

    let host_wide = to_wide(host);
    let mut diagnosis = NETISO_ERROR_TYPE_NONE;
    let status = unsafe {
        NetworkIsolationDiagnoseConnectFailureAndGetInfo(host_wide.as_ptr(), &mut diagnosis)
    };
    println!("diag_status={status}");
    println!(
        "diag_reason={}",
        match diagnosis {
            NETISO_ERROR_TYPE_NONE => "none",
            NETISO_ERROR_TYPE_PRIVATE_NETWORK => "private_network",
            NETISO_ERROR_TYPE_INTERNET_CLIENT => "internet_client",
            NETISO_ERROR_TYPE_INTERNET_CLIENT_SERVER => "internet_client_server",
            _ => "unknown",
        }
    );
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
struct WindowsMatrixCase {
    name: &'static str,
    default_access: SandboxDefaultAccess,
    include_read_only: bool,
    include_read_write: bool,
    include_deny: bool,
}

#[cfg(target_os = "linux")]
struct LinuxMatrixCase {
    name: &'static str,
    default_access: SandboxDefaultAccess,
    include_read_only: bool,
    include_read_write: bool,
    include_deny: bool,
}

#[cfg(target_os = "linux")]
impl LinuxMatrixCase {
    const fn new(
        name: &'static str,
        default_access: SandboxDefaultAccess,
        include_read_only: bool,
        include_read_write: bool,
        include_deny: bool,
    ) -> Self {
        Self {
            name,
            default_access,
            include_read_only,
            include_read_write,
            include_deny,
        }
    }

    fn policy(&self, fixture: &Fixture) -> SandboxPolicy {
        let mut path_permissions = Vec::new();
        if self.include_read_only {
            path_permissions.push(SandboxPathPermission::read_only(fixture.ro_dir.clone()));
        }
        if self.include_read_write {
            path_permissions.push(SandboxPathPermission::read_write(fixture.rw_dir.clone()));
        }
        if self.include_deny {
            path_permissions.push(SandboxPathPermission::deny(fixture.deny_dir.clone()));
        }

        SandboxPolicy {
            default_access: self.default_access,
            network_policy: SandboxNetworkPolicy::disabled(),
            path_permissions,
        }
    }
}

#[cfg(target_os = "windows")]
impl WindowsMatrixCase {
    const fn new(
        name: &'static str,
        default_access: SandboxDefaultAccess,
        include_read_only: bool,
        include_read_write: bool,
        include_deny: bool,
    ) -> Self {
        Self {
            name,
            default_access,
            include_read_only,
            include_read_write,
            include_deny,
        }
    }

    fn policy(&self, fixture: &Fixture) -> SandboxPolicy {
        let mut path_permissions = Vec::new();
        if self.include_read_only {
            path_permissions.push(SandboxPathPermission::read_only(fixture.ro_dir.clone()));
        }
        if self.include_read_write {
            path_permissions.push(SandboxPathPermission::read_write(fixture.rw_dir.clone()));
        }
        if self.include_deny {
            path_permissions.push(SandboxPathPermission::deny(fixture.deny_dir.clone()));
        }

        SandboxPolicy {
            default_access: self.default_access,
            network_policy: SandboxNetworkPolicy::disabled(),
            path_permissions,
        }
    }
}

#[cfg(target_os = "windows")]
struct WindowsTimingCase {
    name: &'static str,
    default_access: SandboxDefaultAccess,
    path_permissions: Vec<SandboxPathPermission>,
}

#[cfg(target_os = "windows")]
impl WindowsTimingCase {
    fn new(
        name: &'static str,
        default_access: SandboxDefaultAccess,
        path_permissions: Vec<SandboxPathPermission>,
    ) -> Self {
        Self {
            name,
            default_access,
            path_permissions,
        }
    }
}

#[cfg(target_os = "linux")]
fn readwrite_with_readonly_policy(fixture: &Fixture) -> SandboxPolicy {
    SandboxPolicy {
        default_access: SandboxDefaultAccess::ReadWrite,
        network_policy: SandboxNetworkPolicy::disabled(),
        path_permissions: vec![SandboxPathPermission::read_only(fixture.ro_dir.clone())],
    }
}

fn assert_success(
    output: &procwarden::SandboxExecOutput,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    if output.exit_code == 0 {
        return Ok(());
    }

    Err(format!(
        "{context} failed unexpectedly: exit_code={}, stdout={}, stderr={}",
        output.exit_code, output.stdout, output.stderr
    )
    .into())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_failure(
    output: &procwarden::SandboxExecOutput,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    if output.exit_code != 0 {
        return Ok(());
    }

    Err(format!(
        "{context} succeeded unexpectedly: stdout={}, stderr={}",
        output.stdout, output.stderr
    )
    .into())
}

fn sandbox_request(command: Vec<String>, cwd: &Path) -> SandboxCommandRequest {
    SandboxCommandRequest {
        command,
        cwd: cwd.to_path_buf(),
        env: sandbox_env(),
        timeout_ms: Some(2_500),
    }
}

fn sandbox_env() -> HashMap<String, String> {
    let mut env = HashMap::new();
    for key in [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "WINDIR",
        "HOME",
        "USERPROFILE",
        "TMP",
        "TEMP",
        "TMPDIR",
    ] {
        if let Ok(value) = std::env::var(key) {
            env.insert(key.to_string(), value);
        }
    }
    env
}

#[cfg(windows)]
fn exit_zero_command() -> Vec<String> {
    vec![
        "cmd.exe".to_string(),
        "/C".to_string(),
        "exit 0".to_string(),
    ]
}

#[cfg(not(windows))]
fn exit_zero_command() -> Vec<String> {
    vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "exit 0".to_string(),
    ]
}

fn read_command(target: &Path) -> Vec<String> {
    #[cfg(windows)]
    {
        let escaped_target = escape_powershell_single_quoted(target);
        vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            format!(
                "try {{ [System.IO.File]::ReadAllText('{escaped_target}') | Out-Null; exit 0 }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
            ),
        ]
    }

    #[cfg(not(windows))]
    {
        vec!["/bin/cat".to_string(), path_arg(target)]
    }
}

fn write_command(target: &Path, payload: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        let escaped_target = escape_powershell_single_quoted(target);
        let escaped_payload = payload.replace('\'', "''");
        vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            format!(
                "try {{ [System.IO.File]::WriteAllText('{escaped_target}', '{escaped_payload}'); exit 0 }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
            ),
        ]
    }

    #[cfg(not(windows))]
    {
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "printf '%s' \"$2\" > \"$1\"".to_string(),
            "sh".to_string(),
            path_arg(target),
            payload.to_string(),
        ]
    }
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg(windows)]
fn escape_powershell_single_quoted(path: &Path) -> String {
    path_arg(path).replace('\'', "''")
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "procwarden-ci-probe-{prefix}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("probe temp dir should be created");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Fixture {
    _workspace: TempDir,
    runtime_cwd: PathBuf,
    deny_dir: PathBuf,
    deny_seed: PathBuf,
    ro_dir: PathBuf,
    #[cfg(target_os = "linux")]
    ro_seed: PathBuf,
    rw_dir: PathBuf,
    #[cfg(target_os = "macos")]
    alias_rw_dir: PathBuf,
    #[cfg(target_os = "windows")]
    outside_dir: PathBuf,
}

impl Fixture {
    fn new(prefix: &str) -> Self {
        let workspace = TempDir::new(prefix);
        let runtime_cwd = workspace.path().join("runtime-cwd");
        let deny_dir = workspace.path().join("denied");
        let ro_dir = workspace.path().join("readonly");
        let rw_dir = workspace.path().join("readwrite");
        let outside_dir = workspace.path().join("outside");

        for dir in [&runtime_cwd, &deny_dir, &ro_dir, &rw_dir, &outside_dir] {
            fs::create_dir_all(dir).expect("probe directory should be created");
        }
        let deny_seed = deny_dir.join("seed-deny.txt");
        fs::write(&deny_seed, "deny-seed").expect("deny seed should be created");
        #[cfg(target_os = "linux")]
        let ro_seed = ro_dir.join("seed-ro.txt");
        #[cfg(target_os = "linux")]
        fs::write(&ro_seed, "readonly-seed").expect("readonly seed should be created");

        #[cfg(target_os = "macos")]
        let alias_rw_dir = workspace
            .path()
            .join("readwrite")
            .join("..")
            .join("readwrite");

        Self {
            _workspace: workspace,
            runtime_cwd,
            deny_dir,
            deny_seed,
            ro_dir,
            #[cfg(target_os = "linux")]
            ro_seed,
            rw_dir,
            #[cfg(target_os = "macos")]
            alias_rw_dir,
            #[cfg(target_os = "windows")]
            outside_dir,
        }
    }
}
