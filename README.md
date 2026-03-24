# procwarden

`procwarden` is a cross-platform process sandbox crate with policy-driven filesystem access control.

It is designed for **explicit capability requests** and **observable effective enforcement**.

## Core model

Policy is modeled as:

- `path_permissions: Vec<SandboxPathPermission>`
  - each entry is read-only or read-write
- `global_access: SandboxAccess` (`NoAccess` / `ReadOnly` / `ReadWrite`)
- `network_access: bool`

This enables flexible combinations:

- specific readable paths
- specific writable paths
- full read
- full read+write

## Quick example

```rust
use std::path::PathBuf;

use procwarden::{SandboxCommandRequest, SandboxManager, SandboxPathPermission, SandboxPolicy};

let manager = SandboxManager::new();

let policy = SandboxPolicy::new_custom_policy()
    .with_permissions([
        SandboxPathPermission::read_only(PathBuf::from("/opt/shared")),
        SandboxPathPermission::read_write(PathBuf::from("/tmp/job-123")),
    ])
    .with_network_access(false);

let request = SandboxCommandRequest {
    command: vec!["python3".into(), "script.py".into()],
    cwd: PathBuf::from("/workspace"),
    env: std::collections::HashMap::new(),
    timeout_ms: Some(30_000),
};

let output = manager.execute(&request, &policy, &PathBuf::from("/workspace"))?;
println!("exit = {}", output.exit_code);
println!("backend = {}", output.enforcement.backend);
# Ok::<(), procwarden::SandboxError>(())
```

## Capability matrix

| Platform | Filesystem read allowlist | Filesystem write allowlist | Network restriction | Child-process coverage |
|---|---|---|---|---|
| Linux (landlock+seccomp) | Strong | Strong | Strong (seccomp) | RestrictedAndJob |
| macOS (virtualization runner) | Strong | Strong | Strong (runner-configurable) | RestrictedAndJob |
| Windows AppContainer | Strong | Strong | Strong (AppContainer capability isolation; downgraded if loopback exemption is detected/unverifiable) | RestrictedAndJob |
| Fallback adapter | None | None | BestEffort | None |

## Windows backend

Windows uses a single sandbox backend: **AppContainer**.

There is no runtime backend selection. This keeps policy behavior consistent
with the permission model.

## macOS backend

macOS uses a non-deprecated virtualization runner integration.

By default, procwarden looks for the runner at:

- `/usr/local/bin/procwarden-macos-runner`

You can override this path with:

- `PROCWARDEN_MACOS_RUNNER`

If the runner is unavailable, macOS sandboxed execution fails closed with
`SandboxError::Unavailable`.

## Enforcement report

Each execution returns `SandboxExecOutput.enforcement` with:

- requested read/write allowlist flags
- effective strength (`None`, `BestEffort`, `Strong`)
- boolean effective read/write enforcement flags
- effective network enforcement strength
- path interception counters
- machine-readable degrade codes (`DegradeReasonCode`)
- human-readable degrade reasons

This report is intended for policy telemetry and audit trails.

## Unsandboxed mode

Use `SandboxPolicy::new_unsandboxed_policy()` when you intentionally want
global read-write + networking.

This is equivalent to `global_access = ReadWrite` + `network_access = true`.
