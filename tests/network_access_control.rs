mod common;

use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;

use procwarden::{SandboxDefaultAccess, SandboxManager, SandboxPathPermission};

use common::{
    Fixture, assert_failure, assert_success, execute_case, policy, sandbox_request,
    should_skip_windows_wfp_unavailable, spawn_http_probe,
};

fn default_gateway_ipv4() -> Option<Ipv4Addr> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
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
fn windows_net_diag_command(host: &str, port: u16, timeout_ms: u64) -> Vec<String> {
    vec![
        std::env::var("CARGO_BIN_EXE_windows_net_diag")
            .expect("windows_net_diag binary should be built for integration tests"),
        host.to_string(),
        port.to_string(),
        timeout_ms.to_string(),
    ]
}

#[cfg(target_os = "windows")]
#[test]
fn network_enabled_allows_private_network_tcp_connect() {
    let fixture = Fixture::new("network-enabled-allowed");
    let manager = SandboxManager::new();
    let Some((gateway_ip, gateway_port)) = default_gateway_private_probe_target() else {
        eprintln!(
            "skip network_enabled test because no reachable default-gateway TCP target is available"
        );
        return;
    };

    let test_policy = policy(
        SandboxDefaultAccess::ReadOnly,
        true,
        vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    );
    let private_network_output = execute_case(
        &manager,
        &sandbox_request(
            windows_net_diag_command(&gateway_ip.to_string(), gateway_port, 1_500),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "network_enabled private-network connect",
    );
    assert_success(
        &private_network_output,
        "network_enabled private-network connect",
    );
}

#[cfg(target_os = "windows")]
#[test]
fn network_enabled_still_blocks_loopback_tcp_connect() {
    let fixture = Fixture::new("network-enabled-loopback");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxDefaultAccess::ReadOnly,
        true,
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

    let loopback_output = execute_case(
        &manager,
        &sandbox_request(
            windows_net_diag_command("127.0.0.1", port, 1_500),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "network_enabled loopback connect",
    );
    assert_failure(&loopback_output, "network_enabled loopback connect");
    assert!(
        !accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false),
        "network_enabled loopback connect should not reach listener on the current Windows backend"
    );
}

#[test]
fn network_disabled_blocks_loopback_and_external_tcp_connect() {
    let fixture = Fixture::new("network-disabled");
    let manager = SandboxManager::new();
    let Some((gateway_ip, gateway_port)) = default_gateway_private_probe_target() else {
        eprintln!(
            "skip network_disabled private-network probe because no reachable default-gateway TCP target is available"
        );
        return;
    };

    let test_policy = policy(
        SandboxDefaultAccess::ReadOnly,
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
        windows_net_diag_command("127.0.0.1", port, 1_500),
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

    let private_network_output = execute_case(
        &manager,
        &sandbox_request(
            windows_net_diag_command(&gateway_ip.to_string(), gateway_port, 1_500),
            &fixture.runtime_cwd,
            2_500,
        ),
        &test_policy,
        "network_disabled private-network connect",
    );
    assert_failure(
        &private_network_output,
        "network_disabled private-network connect",
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "diagnostic helper for Windows network debugging"]
fn debug_network_enabled_diagnose_connect_failure() {
    let fixture = Fixture::new("network-enabled-debug");
    let manager = SandboxManager::new();
    let Some((gateway_ip, gateway_port)) = default_gateway_private_probe_target() else {
        eprintln!(
            "skip network diagnostic because no reachable default-gateway TCP target is available"
        );
        return;
    };
    let diag_exe = std::env::var("CARGO_BIN_EXE_windows_net_diag")
        .expect("windows_net_diag binary should be built for integration tests");

    let output = execute_case(
        &manager,
        &sandbox_request(
            vec![
                diag_exe,
                gateway_ip.to_string(),
                gateway_port.to_string(),
                "1500".to_string(),
            ],
            &fixture.runtime_cwd,
            10_000,
        ),
        &policy(
            SandboxDefaultAccess::ReadOnly,
            true,
            vec![SandboxPathPermission::read_write(
                fixture.runtime_cwd.clone(),
            )],
        ),
        "debug network enabled connect failure",
    );

    eprintln!("stdout:\n{}", output.stdout);
    eprintln!("stderr:\n{}", output.stderr);
    eprintln!(
        "exit_code={} timed_out={}",
        output.exit_code, output.timed_out
    );
}
