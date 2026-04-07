# procwarden
- 中文文档（简体中文）：[README.zh-CN.md](./README.zh-CN.md)

`procwarden` runs a command under a small filesystem and network sandbox on Linux, macOS, and Windows.

Public entry point:

- `SandboxManager::execute(&SandboxCommandRequest, &SandboxPolicy)`

## Quick Tutorial

Use `procwarden` in five decisions:

1. Build the environment explicitly.
2. Pick the default filesystem mode.
3. Pick the network policy.
4. Add only the path overrides you really need.
5. Execute the command.

Practical defaults:

- `SandboxDefaultAccess::ReadOnly`: safest starting point when only a few paths need to be writable.
- `SandboxDefaultAccess::ReadWrite`: use when the process mostly behaves like a normal process and you only need to subtract access from a few paths.

Path override meanings:

- `SandboxPathPermission::read_write(path)`: writable carve-out
- `SandboxPathPermission::read_only(path)`: readable but not writable
- `SandboxPathPermission::deny(path)`: neither readable nor writable

Network policy quick choices:

- `SandboxNetworkPolicy::disabled()`: blocks IP socket creation and blocks `connect` / `bind` / `listen` / `accept`
- `SandboxNetworkPolicy::outbound_only()`: allows outbound IP connect and blocks listener setup
- `SandboxNetworkPolicy::bidirectional()`: allows the coarse helper shape with no procwarden-imposed direction limit

Simple example:

```rust
use std::collections::HashMap;

use procwarden::{
    SandboxCommandRequest, SandboxDefaultAccess, SandboxManager, SandboxNetworkPolicy,
    SandboxPathPermission, SandboxPolicy,
};

let manager = SandboxManager::new();

let mut env = HashMap::new();
if let Ok(path) = std::env::var("PATH") {
    env.insert("PATH".to_string(), path);
}

let policy = SandboxPolicy {
    default_access: SandboxDefaultAccess::ReadOnly,
    network_policy: SandboxNetworkPolicy::disabled(),
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

Custom Linux network policy:

```rust
use procwarden::SandboxNetworkPolicy;

let linux_outbound_ipv4_only = SandboxNetworkPolicy {
    allow_unix: true,
    allow_ipv4: true,
    allow_ipv6: false,
    allow_connect: true,
    allow_bind: false,
    allow_listen: false,
    allow_accept: false,
};
```

What the Linux fields mean:

- `allow_unix`, `allow_ipv4`, `allow_ipv6`: gate socket-family creation
- `allow_connect`, `allow_bind`, `allow_listen`, `allow_accept`: gate those syscalls

Important scope note:

- Linux currently supports fine-grained policy at socket-family creation and `connect` / `bind` / `listen` / `accept` syscall level.
- It is not yet an IP / port / CIDR firewall.
- macOS and Windows currently support only the three helper shapes above. Other custom `SandboxNetworkPolicy` values fail closed with `SandboxError::Unavailable`.

Practical rules:

- `procwarden` does not automatically inherit the parent process environment.
- If your command relies on lookup, pass at least `PATH`.
- If the command needs writable scratch space, create it first and add it as `read_write`.
- If a rule is equal to the default mode, the manager normalizes the redundant rule away.
- `cwd` and every `path_permissions` path must already exist.
- Paths are canonicalized before backend dispatch.
- A descendant path cannot reopen access inside a denied ancestor.
- `timeout_ms` kills the command and normalizes timeout exit code to `124`.

## Support Matrix

### Filesystem

| Platform | Status | Conditions |
|---|---|---|
| Linux | Usable | Rechecked locally on 2026-04-07 on `Linux 6.17.0-20-generic` `x86_64`. Any effective subtractive rule (`deny`, or `read_only` under `ReadWrite`) needs user/mount namespace support (`CLONE_NEWUSER` + `CLONE_NEWNS`, or equivalent `CAP_SYS_ADMIN`) and existing target paths. If unavailable, procwarden fails closed with `SandboxError::Unavailable`. |
| macOS | Usable with condition | Requires `/usr/bin/sandbox-exec`, or `PROCWARDEN_MACOS_SANDBOX_EXEC` pointing to a working replacement. |
| Windows | Usable with condition | Implemented with AppContainer plus ACL changes. Validate on a real Windows host, not only on `windows-latest`. Existing paths are canonicalized before backend dispatch and sanitized again before ACL application. |

### Network

| Platform | `disabled()/outbound_only()/bidirectional()` | Custom `SandboxNetworkPolicy` | Conditions |
|---|---|---|---|
| Linux | Usable | Usable | Rechecked locally on 2026-04-07. Local tests now cover `allow_unix`, `allow_ipv4`, `allow_ipv6`, `allow_connect`, `allow_bind`, `allow_listen`, and `allow_accept`. Current Linux support is syscall-level, not IP / port / CIDR matching. |
| macOS | Usable with condition | Unsupported, fails closed | Requires `/usr/bin/sandbox-exec`, or `PROCWARDEN_MACOS_SANDBOX_EXEC` pointing to a working replacement. Custom fine-grained policy shapes are intentionally rejected. |
| Windows | Usable with condition | Unsupported, fails closed | Implemented with AppContainer and network filters. `disabled()` fails closed if the WFP or elevated-helper path is unavailable. `outbound_only()` and `bidirectional()` request client loopback exemption, and `bidirectional()` may also start a server-side loopback helper. Actual loopback and listener behavior still remains host- and executable-dependent on the current backend. Custom fine-grained policy shapes are intentionally rejected. |

## Recheck On Your Host

```bash
cargo test --test linux_network_policy_control -- --nocapture
cargo test --test network_mode_control -- --nocapture
cargo test --test policy_combination_matrix -- --nocapture
cargo test --workspace --all-targets -- --nocapture
cargo run --quiet --bin ci_matrix_probe
```

On Windows, also run:

```bash
cargo test --test windows_network_mode_control -- --nocapture
cargo test --test windows_network_mode_control debug_current_host_windows_network_matrix -- --ignored --nocapture
```
