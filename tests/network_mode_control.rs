#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::net::TcpListener;
use std::time::Duration;

#[cfg(target_os = "macos")]
use procwarden::SandboxError;
use procwarden::{
    SandboxDefaultAccess, SandboxManager, SandboxNetworkPolicy, SandboxPathPermission,
};

use common::{
    Fixture, assert_failure, assert_success, connect_command, execute_case, listen_command, policy,
    sandbox_request, spawn_http_probe,
};

#[test]
fn network_disabled_blocks_loopback_tcp_connect() {
    let fixture = Fixture::new("network-disabled-loopback");
    let manager = SandboxManager::new();

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener should bind");
    let port = listener
        .local_addr()
        .expect("loopback listener address should resolve")
        .port();
    let accepted_rx = spawn_http_probe(listener, Duration::from_secs(2));

    let output = execute_case(
        &manager,
        &sandbox_request(
            connect_command("127.0.0.1", port, 1_500),
            &fixture.runtime_cwd,
            2_500,
        ),
        &policy(
            SandboxDefaultAccess::ReadOnly,
            SandboxNetworkPolicy::disabled(),
            vec![SandboxPathPermission::read_write(
                fixture.runtime_cwd.clone(),
            )],
        ),
        "network_disabled loopback connect",
    );
    assert_failure(&output, "network_disabled loopback connect");
    assert!(
        !accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false),
        "network_disabled loopback connect should not reach listener"
    );
}

#[test]
fn network_outbound_only_allows_loopback_tcp_connect() {
    let fixture = Fixture::new("network-outbound-only-loopback");
    let manager = SandboxManager::new();

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener should bind");
    let port = listener
        .local_addr()
        .expect("loopback listener address should resolve")
        .port();
    let accepted_rx = spawn_http_probe(listener, Duration::from_secs(2));

    let output = execute_case(
        &manager,
        &sandbox_request(
            connect_command("127.0.0.1", port, 1_500),
            &fixture.runtime_cwd,
            2_500,
        ),
        &policy(
            SandboxDefaultAccess::ReadOnly,
            SandboxNetworkPolicy::outbound_only(),
            vec![SandboxPathPermission::read_write(
                fixture.runtime_cwd.clone(),
            )],
        ),
        "network_outbound_only loopback connect",
    );
    assert_success(&output, "network_outbound_only loopback connect");
    assert!(
        accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false),
        "network_outbound_only loopback connect should reach listener"
    );
}

#[test]
fn network_outbound_only_blocks_tcp_listen() {
    let fixture = Fixture::new("network-outbound-only-listen");
    let manager = SandboxManager::new();

    let output = execute_case(
        &manager,
        &sandbox_request(listen_command("127.0.0.1"), &fixture.runtime_cwd, 2_500),
        &policy(
            SandboxDefaultAccess::ReadOnly,
            SandboxNetworkPolicy::outbound_only(),
            vec![SandboxPathPermission::read_write(
                fixture.runtime_cwd.clone(),
            )],
        ),
        "network_outbound_only listen",
    );
    assert_failure(&output, "network_outbound_only listen");
}

#[test]
fn network_bidirectional_allows_tcp_listen() {
    let fixture = Fixture::new("network-bidirectional-listen");
    let manager = SandboxManager::new();

    let output = execute_case(
        &manager,
        &sandbox_request(listen_command("127.0.0.1"), &fixture.runtime_cwd, 2_500),
        &policy(
            SandboxDefaultAccess::ReadOnly,
            SandboxNetworkPolicy::bidirectional(),
            vec![SandboxPathPermission::read_write(
                fixture.runtime_cwd.clone(),
            )],
        ),
        "network_bidirectional listen",
    );
    assert_success(&output, "network_bidirectional listen");
}

#[cfg(target_os = "macos")]
#[test]
fn custom_network_policy_is_rejected_on_macos() {
    let fixture = Fixture::new("network-custom-policy-macos");
    let manager = SandboxManager::new();

    let result = manager.execute(
        &sandbox_request(
            vec!["/usr/bin/true".to_string()],
            &fixture.runtime_cwd,
            2_500,
        ),
        &policy(
            SandboxDefaultAccess::ReadOnly,
            SandboxNetworkPolicy {
                allow_unix: true,
                allow_ipv4: true,
                allow_ipv6: false,
                allow_connect: false,
                allow_bind: false,
                allow_listen: false,
                allow_accept: false,
            },
            vec![SandboxPathPermission::read_write(
                fixture.runtime_cwd.clone(),
            )],
        ),
    );

    match result {
        Err(SandboxError::Unavailable(message)) => {
            assert!(
                message.contains("only supports SandboxNetworkPolicy::disabled(), ::outbound_only(), or ::bidirectional()"),
                "unexpected macOS unavailable message: {message}"
            );
        }
        other => panic!("expected macOS custom policy to fail closed, got {other:?}"),
    }
}
