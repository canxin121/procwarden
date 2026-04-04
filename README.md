# procwarden
- 中文文档（简体中文）：[README.zh-CN.md](./README.zh-CN.md)

`procwarden` runs a command under a small filesystem and network sandbox on Linux, macOS, and Windows.

Public entry point:

- `SandboxManager::execute(&SandboxCommandRequest, &SandboxPolicy)`

## Quick Tutorial

Use `procwarden` in five decisions:

1. Build the environment explicitly.
2. Pick the default filesystem mode.
3. Pick the network mode.
4. Add only the path overrides you really need.
5. Execute the command.

Practical defaults:

- `SandboxDefaultAccess::ReadOnly`: safest starting point when only a few paths need to be writable.
- `SandboxDefaultAccess::ReadWrite`: use when the process mostly behaves like a normal process and you only need to subtract access from a few paths.

Path override meanings:

- `SandboxPathPermission::read_write(path)`: writable carve-out
- `SandboxPathPermission::read_only(path)`: readable but not writable
- `SandboxPathPermission::deny(path)`: neither readable nor writable

Network mode meanings:

- `SandboxNetworkMode::Disabled`: deny IP networking
- `SandboxNetworkMode::OutboundOnly`: request an outbound-oriented IP policy. Linux and macOS enforce this as outbound-only networking without listener setup. Windows maps it through AppContainer and firewall controls, where private-network outbound is the main verified path and loopback or listener behavior remains host- and executable-dependent.
- `SandboxNetworkMode::Bidirectional`: request that procwarden not add its own network direction restriction. Linux and macOS treat this as ordinary sandboxed networking. Windows still relies on backend-specific AppContainer and firewall controls, so this is not a blanket loopback guarantee there.

These names are intent-level APIs. On Windows, check the support matrix below before treating them as hard direction guarantees.

Example:

```rust
use std::collections::HashMap;

use procwarden::{
    SandboxCommandRequest, SandboxDefaultAccess, SandboxManager, SandboxNetworkMode,
    SandboxPathPermission, SandboxPolicy,
};

let manager = SandboxManager::new();

let mut env = HashMap::new();
if let Ok(path) = std::env::var("PATH") {
    env.insert("PATH".to_string(), path);
}

let policy = SandboxPolicy {
    default_access: SandboxDefaultAccess::ReadOnly,
    network_mode: SandboxNetworkMode::Disabled,
    path_permissions: vec![
        SandboxPathPermission::read_write("/tmp/procwarden-job"),
        SandboxPathPermission::deny("/workspace/secrets"),
    ],
};

let request = SandboxCommandRequest {
    command: vec!["python3".into(), "job.py".into()],
    cwd: "/workspace".into(),
    env,
    timeout_ms: Some(30_000),
};

let output = manager.execute(&request, &policy)?;
assert_eq!(output.exit_code, 0);
# Ok::<(), procwarden::SandboxError>(())
```

Practical rules:

- `procwarden` does not automatically inherit the parent process environment.
- If your command relies on lookup, pass at least `PATH`.
- If the command needs writable scratch space, create it first and add it as `read_write`.
- If a rule is equal to the default mode, the manager normalizes the redundant rule away.
- `cwd` and every `path_permissions` path must already exist.
- Paths are canonicalized before backend dispatch.
- A descendant path cannot reopen access inside a denied ancestor.
- `timeout_ms` kills the command and normalizes timeout exit code to `124`.
- `SandboxNetworkMode::Disabled` means "deny IP networking", not "deny public internet only".

## Support Matrix

The tables below keep only the policy shapes that actually change behavior.

Shared note:

- `ReadOnly + read_only` is redundant and normalized away.
- `ReadWrite + read_write` is redundant and normalized away.

### Filesystem

| Platform | `ReadOnly` | `ReadOnly + read_write` | `ReadOnly + deny` | `ReadWrite` | `ReadWrite + read_only` | `ReadWrite + deny` | Conditions |
|---|---|---|---|---|---|---|---|
| Linux | Usable | Usable | Usable with condition | Usable | Usable with condition | Usable with condition | Rechecked locally on 2026-04-04 on `Linux 6.17.0-19-generic` `x86_64`. Any effective subtractive rule (`deny`, or `read_only` under `ReadWrite`) needs user/mount namespace support (`CLONE_NEWUSER` + `CLONE_NEWNS`, or equivalent `CAP_SYS_ADMIN`) and existing target paths. If unavailable, procwarden fails closed with `SandboxError::Unavailable`. |
| macOS | Usable with condition | Usable with condition | Usable with condition | Usable with condition | Usable with condition | Usable with condition | Requires `/usr/bin/sandbox-exec`, or `PROCWARDEN_MACOS_SANDBOX_EXEC` pointing to a working replacement. |
| Windows | Usable | Usable | Usable | Usable | Usable | Usable | Implemented with AppContainer plus ACL changes. Treat the matrix as something to validate on a real Windows host, not only on `windows-latest`. Existing paths are canonicalized before backend dispatch and sanitized again before ACL application. |

### Network

| Platform | `Disabled` | `OutboundOnly` | `Bidirectional` | Conditions |
|---|---|---|---|---|
| Linux | Usable | Usable | Usable | Rechecked locally on 2026-04-04. `Disabled` blocks loopback, private-network, and external IP networking. `OutboundOnly` allows outbound connect and blocks listener setup. Restricted modes depend on seccomp support for `x86_64` or `aarch64`; if unavailable, procwarden fails closed. |
| macOS | Usable with condition | Usable with condition | Usable with condition | Requires `/usr/bin/sandbox-exec`, or `PROCWARDEN_MACOS_SANDBOX_EXEC` pointing to a working replacement. `Disabled` maps to `(deny network*)`. `OutboundOnly` maps to `(deny network-bind)` plus `(deny network-inbound)`. |
| Windows | Usable with condition | Usable with condition | Usable with condition | Implemented with AppContainer and network filters. `Disabled` fails closed if the WFP or elevated-helper path is unavailable. `OutboundOnly` and `Bidirectional` depend on the elevated firewall-helper path. Private-network outbound access is the main verified path. Procwarden now requests client loopback exemption for both `OutboundOnly` and `Bidirectional`, and starts the `Bidirectional` server-side loopback helper with stale-process cleanup so repeated runs do not self-poison. Loopback is still host-dependent on the current backend, so treat Windows network control as conditional, especially for loopback and listener behavior. |

#### Current Windows Host Recheck

Rechecked locally on 2026-04-04 on `Windows NT 10.0.19044.0` with a non-elevated parent process. The exact private-network probe target is host-dependent and can vary between runs; the latest focused matrix recheck on this host used `198.18.0.2:53`, and earlier targeted probes also reached `192.168.0.1:80`.

`cargo test --test windows_network_mode_control -- --nocapture`, `cargo test --test windows_network_mode_control debug_current_host_windows_network_matrix -- --ignored --nocapture`, and the focused ignored diagnostics for `windows_net_diag.exe`, PowerShell `TcpClient`, active listener visibility, bind-address comparison, and repeated `Bidirectional` runs all ran on this host. After fixing the Windows-only `CheckNetIsolation -is` stale-process leak in the elevated helper path, the remaining Windows loopback behavior is still executable-specific rather than a stable contract.

| Mode | Runnable | Private-network connect (`windows_net_diag.exe`) | Loopback connect (`windows_net_diag.exe`) | Loopback connect (PowerShell `TcpClient`) | Host -> sandbox loopback connect | Listener setup (`TcpListener`) | `ci_matrix_probe.exe` same-binary loopback connect | Current-host conclusion |
|---|---|---|---|---|---|---|---|---|
| `Disabled` | Yes | Blocked | Blocked | Blocked | Blocked | Allowed | Blocked | Effective deny path worked for connect/accept. Bare `bind/listen` still succeeds. |
| `OutboundOnly` | Yes | Allowed | Blocked | Blocked | Blocked | Allowed | Allowed | Final behavior on this host is "private-network outbound plus a same-binary loopback exception", not generic loopback outbound. |
| `Bidirectional` | Yes | Allowed | Blocked | Blocked | Blocked | Allowed | Allowed | Repeated runs no longer self-poison with stale `CheckNetIsolation -is` processes. On this host generic Win32 loopback still does not work, but the same-binary `ci_matrix_probe.exe` path does. |

## Recheck On Your Host

```bash
cargo test --test policy_combination_matrix -- --nocapture
cargo test --test network_mode_control -- --nocapture
cargo test --workspace --all-targets -- --nocapture
cargo run --quiet --bin ci_matrix_probe
```

On Windows, also run:

```bash
cargo test --test windows_network_mode_control -- --nocapture
cargo test --test windows_network_mode_control debug_current_host_windows_network_matrix -- --ignored --nocapture
```
