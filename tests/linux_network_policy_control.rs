#![cfg(target_os = "linux")]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::thread;
use std::time::Duration;

use procwarden::{
    SandboxDefaultAccess, SandboxManager, SandboxNetworkPolicy, SandboxPathPermission,
};

use common::{
    Fixture, accept_command, assert_failure, assert_success, bind_command, connect_command,
    execute_case, listen_command, policy, sandbox_request, socket_family_command,
    spawn_accept_probe,
};

fn custom_policy() -> SandboxNetworkPolicy {
    SandboxNetworkPolicy {
        allow_unix: false,
        allow_ipv4: false,
        allow_ipv6: false,
        allow_connect: false,
        allow_bind: false,
        allow_listen: false,
        allow_accept: false,
    }
}

fn runtime_policy(
    fixture: &Fixture,
    network_policy: SandboxNetworkPolicy,
) -> procwarden::SandboxPolicy {
    policy(
        SandboxDefaultAccess::ReadOnly,
        network_policy,
        vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    )
}

fn host_supports_socket_family(family: &str) -> bool {
    let command = socket_family_command(family);
    let status = Command::new(&command[0]).args(&command[1..]).status();
    matches!(status, Ok(status) if status.success())
}

fn free_loopback_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("ephemeral port should be reserved");
    let port = listener
        .local_addr()
        .expect("listener address should resolve")
        .port();
    drop(listener);
    port
}

fn spawn_host_loopback_connector(port: u16, delay: Duration) -> thread::JoinHandle<bool> {
    thread::spawn(move || {
        thread::sleep(delay);
        let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        TcpStream::connect_timeout(&target, Duration::from_secs(2)).is_ok()
    })
}

#[test]
fn unix_socket_creation_is_blocked_when_unix_family_is_disabled() {
    let fixture = Fixture::new("linux-network-unix-disabled");
    let manager = SandboxManager::new();

    let output = execute_case(
        &manager,
        &sandbox_request(socket_family_command("unix"), &fixture.runtime_cwd, 2_500),
        &runtime_policy(&fixture, custom_policy()),
        "unix socket creation disabled",
    );
    assert_failure(&output, "unix socket creation disabled");
}

#[test]
fn unix_socket_creation_is_allowed_when_unix_family_is_enabled() {
    let fixture = Fixture::new("linux-network-unix-enabled");
    let manager = SandboxManager::new();

    let output = execute_case(
        &manager,
        &sandbox_request(socket_family_command("unix"), &fixture.runtime_cwd, 2_500),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_unix: true,
                ..custom_policy()
            },
        ),
        "unix socket creation enabled",
    );
    assert_success(&output, "unix socket creation enabled");
}

#[test]
fn ipv4_socket_creation_is_blocked_when_ipv4_family_is_disabled() {
    let fixture = Fixture::new("linux-network-ipv4-disabled");
    let manager = SandboxManager::new();

    let output = execute_case(
        &manager,
        &sandbox_request(socket_family_command("ipv4"), &fixture.runtime_cwd, 2_500),
        &runtime_policy(&fixture, custom_policy()),
        "ipv4 socket creation disabled",
    );
    assert_failure(&output, "ipv4 socket creation disabled");
}

#[test]
fn ipv4_socket_creation_is_allowed_when_ipv4_family_is_enabled() {
    let fixture = Fixture::new("linux-network-ipv4-enabled");
    let manager = SandboxManager::new();

    let output = execute_case(
        &manager,
        &sandbox_request(socket_family_command("ipv4"), &fixture.runtime_cwd, 2_500),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_ipv4: true,
                ..custom_policy()
            },
        ),
        "ipv4 socket creation enabled",
    );
    assert_success(&output, "ipv4 socket creation enabled");
}

#[test]
fn ipv6_socket_creation_is_blocked_when_ipv6_family_is_disabled() {
    if !host_supports_socket_family("ipv6") {
        eprintln!("skip ipv6 disabled test because host cannot create IPv6 stream sockets");
        return;
    }

    let fixture = Fixture::new("linux-network-ipv6-disabled");
    let manager = SandboxManager::new();

    let output = execute_case(
        &manager,
        &sandbox_request(socket_family_command("ipv6"), &fixture.runtime_cwd, 2_500),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_ipv4: true,
                ..custom_policy()
            },
        ),
        "ipv6 socket creation disabled",
    );
    assert_failure(&output, "ipv6 socket creation disabled");
}

#[test]
fn ipv6_socket_creation_is_allowed_when_ipv6_family_is_enabled() {
    if !host_supports_socket_family("ipv6") {
        eprintln!("skip ipv6 enabled test because host cannot create IPv6 stream sockets");
        return;
    }

    let fixture = Fixture::new("linux-network-ipv6-enabled");
    let manager = SandboxManager::new();

    let output = execute_case(
        &manager,
        &sandbox_request(socket_family_command("ipv6"), &fixture.runtime_cwd, 2_500),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_ipv6: true,
                ..custom_policy()
            },
        ),
        "ipv6 socket creation enabled",
    );
    assert_success(&output, "ipv6 socket creation enabled");
}

#[test]
fn connect_is_blocked_when_connect_permission_is_disabled() {
    let fixture = Fixture::new("linux-network-connect-disabled");
    let manager = SandboxManager::new();

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener should bind");
    let port = listener
        .local_addr()
        .expect("listener addr should resolve")
        .port();
    let accepted_rx = spawn_accept_probe(listener, Duration::from_secs(2));

    let output = execute_case(
        &manager,
        &sandbox_request(
            connect_command("127.0.0.1", port, 1_500),
            &fixture.runtime_cwd,
            2_500,
        ),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_ipv4: true,
                ..custom_policy()
            },
        ),
        "connect disabled",
    );
    assert_failure(&output, "connect disabled");
    assert!(
        !accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false),
        "connect disabled should not reach listener"
    );
}

#[test]
fn connect_is_allowed_when_connect_permission_is_enabled() {
    let fixture = Fixture::new("linux-network-connect-enabled");
    let manager = SandboxManager::new();

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener should bind");
    let port = listener
        .local_addr()
        .expect("listener addr should resolve")
        .port();
    let accepted_rx = spawn_accept_probe(listener, Duration::from_secs(2));

    let output = execute_case(
        &manager,
        &sandbox_request(
            connect_command("127.0.0.1", port, 1_500),
            &fixture.runtime_cwd,
            2_500,
        ),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_ipv4: true,
                allow_connect: true,
                ..custom_policy()
            },
        ),
        "connect enabled",
    );
    assert_success(&output, "connect enabled");
    assert!(
        accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false),
        "connect enabled should reach listener"
    );
}

#[test]
fn bind_is_blocked_when_bind_permission_is_disabled() {
    let fixture = Fixture::new("linux-network-bind-disabled");
    let manager = SandboxManager::new();
    let port = free_loopback_port();

    let output = execute_case(
        &manager,
        &sandbox_request(bind_command("127.0.0.1", port), &fixture.runtime_cwd, 2_500),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_ipv4: true,
                ..custom_policy()
            },
        ),
        "bind disabled",
    );
    assert_failure(&output, "bind disabled");
}

#[test]
fn bind_is_allowed_when_bind_permission_is_enabled() {
    let fixture = Fixture::new("linux-network-bind-enabled");
    let manager = SandboxManager::new();
    let port = free_loopback_port();

    let output = execute_case(
        &manager,
        &sandbox_request(bind_command("127.0.0.1", port), &fixture.runtime_cwd, 2_500),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_ipv4: true,
                allow_bind: true,
                ..custom_policy()
            },
        ),
        "bind enabled",
    );
    assert_success(&output, "bind enabled");
}

#[test]
fn listen_is_blocked_when_listen_permission_is_disabled() {
    let fixture = Fixture::new("linux-network-listen-disabled");
    let manager = SandboxManager::new();

    let output = execute_case(
        &manager,
        &sandbox_request(listen_command("127.0.0.1"), &fixture.runtime_cwd, 2_500),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_ipv4: true,
                allow_bind: true,
                ..custom_policy()
            },
        ),
        "listen disabled",
    );
    assert_failure(&output, "listen disabled");
}

#[test]
fn listen_is_allowed_when_listen_permission_is_enabled() {
    let fixture = Fixture::new("linux-network-listen-enabled");
    let manager = SandboxManager::new();

    let output = execute_case(
        &manager,
        &sandbox_request(listen_command("127.0.0.1"), &fixture.runtime_cwd, 2_500),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_ipv4: true,
                allow_bind: true,
                allow_listen: true,
                ..custom_policy()
            },
        ),
        "listen enabled",
    );
    assert_success(&output, "listen enabled");
}

#[test]
fn accept_is_blocked_when_accept_permission_is_disabled() {
    let fixture = Fixture::new("linux-network-accept-disabled");
    let manager = SandboxManager::new();
    let port = free_loopback_port();

    let connector = spawn_host_loopback_connector(port, Duration::from_millis(200));
    let output = execute_case(
        &manager,
        &sandbox_request(
            accept_command("127.0.0.1", port, 1_500),
            &fixture.runtime_cwd,
            2_500,
        ),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_ipv4: true,
                allow_bind: true,
                allow_listen: true,
                ..custom_policy()
            },
        ),
        "accept disabled",
    );
    let _ = connector.join();
    assert_failure(&output, "accept disabled");
}

#[test]
fn accept_is_allowed_when_accept_permission_is_enabled() {
    let fixture = Fixture::new("linux-network-accept-enabled");
    let manager = SandboxManager::new();
    let port = free_loopback_port();

    let connector = spawn_host_loopback_connector(port, Duration::from_millis(200));
    let output = execute_case(
        &manager,
        &sandbox_request(
            accept_command("127.0.0.1", port, 1_500),
            &fixture.runtime_cwd,
            2_500,
        ),
        &runtime_policy(
            &fixture,
            SandboxNetworkPolicy {
                allow_ipv4: true,
                allow_bind: true,
                allow_listen: true,
                allow_accept: true,
                ..custom_policy()
            },
        ),
        "accept enabled",
    );
    assert!(
        connector.join().unwrap_or(false),
        "host connector should succeed"
    );
    assert_success(&output, "accept enabled");
}
