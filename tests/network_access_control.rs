mod common;

use std::net::TcpListener;
use std::time::Duration;

use procwarden::{SandboxAccess, SandboxManager, SandboxPathPermission};
#[cfg(target_os = "windows")]
use procwarden::SandboxError;

use common::{
    Fixture, assert_failure, connect_command, execute_case, policy, sandbox_request,
    should_skip_windows_wfp_unavailable, spawn_http_probe,
};

const EXTERNAL_HOST: &str = "1.1.1.1";
const EXTERNAL_PORT: u16 = 443;

#[cfg(target_os = "windows")]
#[test]
fn network_enabled_is_explicitly_rejected_on_windows() {
    let fixture = Fixture::new("network-enabled-unsupported");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxAccess::NoAccess,
        true,
        vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    );

    let result = manager.execute(
        &sandbox_request(
            connect_command(EXTERNAL_HOST, EXTERNAL_PORT, 2_000),
            &fixture.runtime_cwd,
            3_000,
        ),
        &test_policy,
    );
    assert!(
        matches!(
            result,
            Err(SandboxError::InvalidRequest(message)) if message.contains("network_access=true")
        ),
        "windows backend should fail closed for unsupported network_access=true"
    );
}

#[test]
fn network_disabled_blocks_loopback_and_external_tcp_connect() {
    let fixture = Fixture::new("network-disabled");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxAccess::NoAccess,
        false,
        vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    );

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener should bind");
    let port = listener
        .local_addr()
        .expect("loopback listener address should resolve")
        .port();
    let accepted_rx = spawn_http_probe(listener, Duration::from_secs(2));

    let loopback_request = sandbox_request(
        connect_command("127.0.0.1", port, 1_500),
        &fixture.runtime_cwd,
        2_500,
    );
    let loopback_result = manager.execute(&loopback_request, &test_policy);
    if should_skip_windows_wfp_unavailable(&loopback_result) {
        eprintln!(
            "skip network_disabled test because Windows WFP is unsupported in this environment"
        );
        return;
    }
    let loopback_output = loopback_result.unwrap_or_else(|error| {
        panic!("network_disabled loopback connect: manager execution failed: {error:?}")
    });
    assert_failure(&loopback_output, "network_disabled loopback connect");

    let accepted = accepted_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap_or(false);
    assert!(
        !accepted,
        "network_disabled loopback connect should not reach listener"
    );

    let external_output = execute_case(
        &manager,
        &sandbox_request(
            connect_command(EXTERNAL_HOST, EXTERNAL_PORT, 2_000),
            &fixture.runtime_cwd,
            3_000,
        ),
        &test_policy,
        "network_disabled external connect",
    );
    assert_failure(&external_output, "network_disabled external connect");
}
