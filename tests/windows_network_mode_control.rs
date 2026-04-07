#![cfg(target_os = "windows")]

mod common;

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::thread;
use std::time::Duration;

use procwarden::{
    SandboxDefaultAccess, SandboxManager, SandboxNetworkPolicy, SandboxPathPermission,
};

use common::{
    Fixture, assert_failure, assert_success, connect_command, execute_case, listen_command, policy,
    sandbox_request, should_skip_windows_wfp_unavailable, spawn_http_probe,
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

fn windows_net_diag_command(host: &str, port: u16, timeout_ms: u64) -> Vec<String> {
    vec![
        std::env::var("CARGO_BIN_EXE_windows_net_diag")
            .expect("windows_net_diag binary should be built for integration tests"),
        host.to_string(),
        port.to_string(),
        timeout_ms.to_string(),
    ]
}

fn listener_accept_command(host: &str, port_file: &std::path::Path) -> Vec<String> {
    let escaped_host = host.replace('\'', "''");
    let escaped_port_file = port_file.to_string_lossy().replace('\'', "''");
    vec![
        "powershell.exe".to_string(),
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-Command".to_string(),
        format!(
            "try {{ $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse('{escaped_host}'), 0); $listener.Start(); [System.IO.File]::WriteAllText('{escaped_port_file}', $listener.LocalEndpoint.Port.ToString()); $deadline = [DateTime]::UtcNow.AddMilliseconds(2500); while ([DateTime]::UtcNow -lt $deadline) {{ if ($listener.Pending()) {{ $client = $listener.AcceptTcpClient(); $client.Close(); $listener.Stop(); exit 0 }}; Start-Sleep -Milliseconds 50 }}; $listener.Stop(); [Console]::Error.WriteLine('accept timeout'); exit 1 }} catch {{ [Console]::Error.WriteLine($_.Exception.ToString()); exit 1 }}"
        ),
    ]
}

fn loopback_listener_accept_command(port_file: &std::path::Path) -> Vec<String> {
    listener_accept_command("127.0.0.1", port_file)
}

fn sanitize_probe_detail(detail: &str) -> String {
    detail.replace(['\r', '\n'], " ")
}

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

fn render_probe_result(
    result: Result<procwarden::SandboxExecOutput, procwarden::SandboxError>,
) -> String {
    match result {
        Ok(output) if output.exit_code == 0 => match output.degraded_mode_reason {
            Some(reason) => format!(
                "ok(degraded={})",
                truncate_probe_detail(&sanitize_probe_detail(&reason))
            ),
            None => "ok".to_string(),
        },
        Ok(output) => format!(
            "blocked(exit={},stderr={},stdout={},degraded={})",
            output.exit_code,
            truncate_probe_detail(&sanitize_probe_detail(output.stderr.trim())),
            truncate_probe_detail(&sanitize_probe_detail(output.stdout.trim())),
            output
                .degraded_mode_reason
                .as_deref()
                .map(sanitize_probe_detail)
                .map(|reason| truncate_probe_detail(&reason))
                .unwrap_or_else(|| "none".to_string()),
        ),
        Err(error) => {
            truncate_probe_detail(&sanitize_probe_detail(&format!("manager_error({error:?})")))
        }
    }
}

fn mode_key(network_policy: SandboxNetworkPolicy) -> &'static str {
    if network_policy == SandboxNetworkPolicy::disabled() {
        "disabled"
    } else if network_policy == SandboxNetworkPolicy::outbound_only() {
        "outbound_only"
    } else if network_policy == SandboxNetworkPolicy::bidirectional() {
        "bidirectional"
    } else {
        panic!("unsupported helper policy for mode_key: {network_policy:?}");
    }
}

fn probe_host_connect_to_sandbox_listener(
    fixture: &Fixture,
    test_policy: &procwarden::SandboxPolicy,
) -> String {
    let port_file = fixture.runtime_cwd.join("sandbox-loopback-port.txt");
    let _ = fs::remove_file(&port_file);

    let runtime_cwd = fixture.runtime_cwd.clone();
    let policy = test_policy.clone();
    let port_file_for_child = port_file.clone();
    let sandbox_rx = thread::spawn(move || {
        let manager = SandboxManager::new();
        manager.execute(
            &sandbox_request(
                loopback_listener_accept_command(&port_file_for_child),
                &runtime_cwd,
                4_000,
            ),
            &policy,
        )
    });

    let mut port = None;
    for _ in 0..40 {
        if let Ok(contents) = fs::read_to_string(&port_file)
            && let Ok(parsed) = contents.trim().parse::<u16>()
        {
            port = Some(parsed);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let host_connect = match port {
        Some(port) => TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(1_500),
        )
        .map(|stream| {
            drop(stream);
            "host_connect_ok".to_string()
        })
        .unwrap_or_else(|error| format!("host_connect_failed({error})")),
        None => "listener_port_unavailable".to_string(),
    };

    let sandbox_result = sandbox_rx
        .join()
        .unwrap_or_else(|_| panic!("sandbox listener probe thread should join"));
    let sandbox_rendered = render_probe_result(sandbox_result);
    format!("{host_connect};sandbox={sandbox_rendered}")
}

fn powershell_output(command: &str) -> String {
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()
        .unwrap_or_else(|error| panic!("powershell command failed to launch: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    format!(
        "status={:?};stdout={};stderr={}",
        output.status.code(),
        stdout,
        stderr
    )
}

#[test]
fn network_bidirectional_allows_private_network_tcp_connect() {
    let fixture = Fixture::new("network-bidirectional-allowed");
    let manager = SandboxManager::new();
    let Some((gateway_ip, gateway_port)) = default_gateway_private_probe_target() else {
        eprintln!(
            "skip network_bidirectional test because no reachable default-gateway TCP target is available"
        );
        return;
    };

    let test_policy = policy(
        SandboxDefaultAccess::ReadOnly,
        SandboxNetworkPolicy::bidirectional(),
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
        "network_bidirectional private-network connect",
    );
    assert_success(
        &private_network_output,
        "network_bidirectional private-network connect",
    );
}

#[test]
fn network_outbound_only_allows_private_network_tcp_connect() {
    let fixture = Fixture::new("network-outbound-only-private");
    let manager = SandboxManager::new();
    let Some((gateway_ip, gateway_port)) = default_gateway_private_probe_target() else {
        eprintln!(
            "skip network_outbound_only private-network probe because no reachable default-gateway TCP target is available"
        );
        return;
    };

    let test_policy = policy(
        SandboxDefaultAccess::ReadOnly,
        SandboxNetworkPolicy::outbound_only(),
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
        "network_outbound_only private-network connect",
    );
    assert_success(
        &private_network_output,
        "network_outbound_only private-network connect",
    );
}

#[test]
fn network_bidirectional_still_blocks_loopback_tcp_connect() {
    let fixture = Fixture::new("network-bidirectional-loopback");
    let manager = SandboxManager::new();

    let test_policy = policy(
        SandboxDefaultAccess::ReadOnly,
        SandboxNetworkPolicy::bidirectional(),
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
        "network_bidirectional loopback connect",
    );
    assert_failure(&loopback_output, "network_bidirectional loopback connect");
    assert!(
        !accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false),
        "network_bidirectional loopback connect should not reach listener on the current Windows backend"
    );
}

#[test]
fn network_disabled_blocks_loopback_and_private_tcp_connect() {
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
        SandboxNetworkPolicy::disabled(),
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

#[test]
#[ignore = "diagnostic helper for Windows network debugging"]
fn debug_network_bidirectional_diagnose_connect_failure() {
    let fixture = Fixture::new("network-bidirectional-debug");
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
            SandboxNetworkPolicy::bidirectional(),
            vec![SandboxPathPermission::read_write(
                fixture.runtime_cwd.clone(),
            )],
        ),
        "debug network bidirectional connect failure",
    );

    eprintln!("stdout:\n{}", output.stdout);
    eprintln!("stderr:\n{}", output.stderr);
    eprintln!(
        "exit_code={} timed_out={}",
        output.exit_code, output.timed_out
    );
}

#[test]
#[ignore = "diagnostic helper for current Windows host network matrix"]
fn debug_current_host_windows_network_matrix() {
    let fixture = Fixture::new("network-current-host-matrix");
    let manager = SandboxManager::new();
    let private_target = default_gateway_private_probe_target();

    if let Some((gateway_ip, gateway_port)) = private_target {
        println!("current_host.windows.network.private_target={gateway_ip}:{gateway_port}");
    } else {
        println!("current_host.windows.network.private_target=unavailable");
    }

    for network_policy in [
        SandboxNetworkPolicy::disabled(),
        SandboxNetworkPolicy::outbound_only(),
        SandboxNetworkPolicy::bidirectional(),
    ] {
        let policy = policy(
            SandboxDefaultAccess::ReadOnly,
            network_policy,
            vec![SandboxPathPermission::read_write(
                fixture.runtime_cwd.clone(),
            )],
        );
        let key = mode_key(network_policy);

        let runnable_result = manager.execute(
            &sandbox_request(
                vec![
                    "cmd.exe".to_string(),
                    "/C".to_string(),
                    "exit 0".to_string(),
                ],
                &fixture.runtime_cwd,
                2_500,
            ),
            &policy,
        );
        if should_skip_windows_wfp_unavailable(&runnable_result) {
            println!("current_host.windows.network.{key}.runnable=wfp_unavailable");
            return;
        }
        println!(
            "current_host.windows.network.{key}.runnable={}",
            render_probe_result(runnable_result)
        );

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("loopback listener should bind");
        let loopback_port = listener
            .local_addr()
            .expect("loopback listener address should resolve")
            .port();
        let accepted_rx = spawn_http_probe(listener, Duration::from_secs(2));
        let loopback_result = manager.execute(
            &sandbox_request(
                windows_net_diag_command("127.0.0.1", loopback_port, 1_500),
                &fixture.runtime_cwd,
                2_500,
            ),
            &policy,
        );
        let accepted = accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false);
        println!(
            "current_host.windows.network.{key}.loopback_connect.windows_net_diag={}",
            render_probe_result(loopback_result)
        );
        println!("current_host.windows.network.{key}.loopback_listener.accepted={accepted}");

        let listen_result = manager.execute(
            &sandbox_request(listen_command("127.0.0.1"), &fixture.runtime_cwd, 2_500),
            &policy,
        );
        println!(
            "current_host.windows.network.{key}.loopback_listen={}",
            render_probe_result(listen_result)
        );
        println!(
            "current_host.windows.network.{key}.host_to_sandbox_loopback_accept={}",
            probe_host_connect_to_sandbox_listener(&fixture, &policy)
        );

        if let Some((gateway_ip, gateway_port)) = private_target {
            let private_result = manager.execute(
                &sandbox_request(
                    windows_net_diag_command(&gateway_ip.to_string(), gateway_port, 1_500),
                    &fixture.runtime_cwd,
                    2_500,
                ),
                &policy,
            );
            println!(
                "current_host.windows.network.{key}.private_connect.windows_net_diag={}",
                render_probe_result(private_result)
            );
        } else {
            println!(
                "current_host.windows.network.{key}.private_connect.windows_net_diag=skipped(no_reachable_default_gateway_target)"
            );
        }
    }
}

#[test]
#[ignore = "diagnostic helper for bidirectional loopback-server activation failures"]
fn debug_bidirectional_loopback_server_activation_reason() {
    let fixture = Fixture::new("network-bidirectional-loopback-server-reason");
    let manager = SandboxManager::new();
    let policy = policy(
        SandboxDefaultAccess::ReadOnly,
        SandboxNetworkPolicy::bidirectional(),
        vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    );

    let runnable = manager
        .execute(
            &sandbox_request(
                vec![
                    "cmd.exe".to_string(),
                    "/C".to_string(),
                    "exit 0".to_string(),
                ],
                &fixture.runtime_cwd,
                2_500,
            ),
            &policy,
        )
        .expect("bidirectional runnable should execute");
    println!(
        "bidirectional_runnable_degraded={:?}",
        runnable.degraded_mode_reason
    );

    let listen = manager
        .execute(
            &sandbox_request(listen_command("127.0.0.1"), &fixture.runtime_cwd, 2_500),
            &policy,
        )
        .expect("bidirectional listen should execute");
    println!(
        "bidirectional_listen_degraded={:?}",
        listen.degraded_mode_reason
    );
    println!("bidirectional_listen_stdout={}", listen.stdout);
    println!("bidirectional_listen_stderr={}", listen.stderr);
    println!("bidirectional_listen_exit={}", listen.exit_code);
}

#[test]
#[ignore = "diagnostic helper for active bidirectional listener visibility"]
fn debug_bidirectional_listener_visibility() {
    let fixture = Fixture::new("network-bidirectional-listener-visibility");
    let policy = policy(
        SandboxDefaultAccess::ReadOnly,
        SandboxNetworkPolicy::bidirectional(),
        vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    );
    let port_file = fixture.runtime_cwd.join("listener-port.txt");
    let _ = fs::remove_file(&port_file);

    let runtime_cwd = fixture.runtime_cwd.clone();
    let policy_for_thread = policy.clone();
    let port_file_for_thread = port_file.clone();
    let sandbox_rx = thread::spawn(move || {
        let manager = SandboxManager::new();
        manager.execute(
            &sandbox_request(
                loopback_listener_accept_command(&port_file_for_thread),
                &runtime_cwd,
                5_000,
            ),
            &policy_for_thread,
        )
    });

    let mut port = None;
    for _ in 0..40 {
        if let Ok(contents) = fs::read_to_string(&port_file)
            && let Ok(parsed) = contents.trim().parse::<u16>()
        {
            port = Some(parsed);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let port = port.expect("listener port should be published");

    println!("listener_port={port}");
    println!(
        "nettcp={}",
        powershell_output(&format!(
            "Get-NetTCPConnection -State Listen -LocalAddress 127.0.0.1 -LocalPort {port} | Select-Object -First 3 LocalAddress,LocalPort,OwningProcess | Format-List"
        ))
    );
    println!(
        "checknetisolation_processes={}",
        powershell_output(
            "Get-CimInstance Win32_Process -Filter \"Name = 'CheckNetIsolation.exe'\" | Select-Object ProcessId,CommandLine | Format-List"
        )
    );

    let connect_result = TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(1_500),
    );
    println!("host_connect_result={connect_result:?}");

    let sandbox_result = sandbox_rx
        .join()
        .unwrap_or_else(|_| panic!("sandbox listener visibility thread should join"))
        .expect("sandbox listener command should execute");
    println!(
        "sandbox_listener_result={}",
        render_probe_result(Ok(sandbox_result))
    );
}

#[test]
#[ignore = "diagnostic helper for bidirectional bind address comparison"]
fn debug_bidirectional_bind_address_comparison() {
    let fixture = Fixture::new("network-bidirectional-bind-compare");
    let policy = policy(
        SandboxDefaultAccess::ReadOnly,
        SandboxNetworkPolicy::bidirectional(),
        vec![SandboxPathPermission::read_write(
            fixture.runtime_cwd.clone(),
        )],
    );

    for host in ["127.0.0.1", "0.0.0.0"] {
        let port_file = fixture
            .runtime_cwd
            .join(format!("listener-port-{}.txt", host.replace('.', "_")));
        let _ = fs::remove_file(&port_file);

        let runtime_cwd = fixture.runtime_cwd.clone();
        let policy_for_thread = policy.clone();
        let port_file_for_thread = port_file.clone();
        let host_for_thread = host.to_string();
        let sandbox_rx = thread::spawn(move || {
            let manager = SandboxManager::new();
            manager.execute(
                &sandbox_request(
                    listener_accept_command(&host_for_thread, &port_file_for_thread),
                    &runtime_cwd,
                    5_000,
                ),
                &policy_for_thread,
            )
        });

        let mut port = None;
        for _ in 0..40 {
            if let Ok(contents) = fs::read_to_string(&port_file)
                && let Ok(parsed) = contents.trim().parse::<u16>()
            {
                port = Some(parsed);
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let port = port.expect("listener port should be published");

        let connect_result = TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], port)),
            Duration::from_millis(1_500),
        );
        let sandbox_result = sandbox_rx
            .join()
            .unwrap_or_else(|_| panic!("sandbox bind comparison thread should join"))
            .expect("sandbox bind comparison command should execute");

        println!(
            "bind_host={host} port={port} host_connect={connect_result:?} sandbox={}",
            render_probe_result(Ok(sandbox_result))
        );
    }
}

#[test]
#[ignore = "diagnostic helper for powershell loopback connect comparison"]
fn debug_powershell_loopback_connect_matrix() {
    let fixture = Fixture::new("network-powershell-loopback-connect");
    let manager = SandboxManager::new();

    for network_policy in [
        SandboxNetworkPolicy::disabled(),
        SandboxNetworkPolicy::outbound_only(),
        SandboxNetworkPolicy::bidirectional(),
    ] {
        let policy = policy(
            SandboxDefaultAccess::ReadOnly,
            network_policy,
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
        let output = manager
            .execute(
                &sandbox_request(
                    connect_command("127.0.0.1", port, 1_500),
                    &fixture.runtime_cwd,
                    2_500,
                ),
                &policy,
            )
            .expect("powershell loopback connect should execute");
        let accepted = accepted_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap_or(false);

        println!(
            "mode={} powershell_loopback_connect={} accepted={accepted}",
            mode_key(network_policy),
            render_probe_result(Ok(output))
        );
    }
}
