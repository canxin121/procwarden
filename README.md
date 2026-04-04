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
- `SandboxNetworkMode::OutboundOnly`: allow outbound IP traffic and deny inbound IP traffic
- `SandboxNetworkMode::Bidirectional`: do not impose a procwarden network direction limit

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
| Windows | Usable with condition | Usable with condition | Usable with condition | Implemented with AppContainer and network filters. `Disabled` fails closed if the WFP or elevated-helper path is unavailable. `OutboundOnly` and `Bidirectional` depend on the elevated firewall-helper path. Private-network outbound access is the main verified path. Loopback is still host-dependent on the current backend, so treat Windows network control as conditional, especially for loopback and listener behavior. |

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
```
