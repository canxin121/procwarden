# procwarden

`procwarden` is a cross-platform process sandbox crate with explicit policy-driven filesystem and network permissions.

## Core model

Policy is modeled as:

- `path_permissions: Vec<SandboxPathPermission>`
  - each entry is read-only or read-write
- `global_access: SandboxAccess` (`NoAccess` / `ReadOnly` / `ReadWrite`)
- `network_access: bool`

## Quick example

```rust
use std::path::PathBuf;

use procwarden::{
    SandboxAccess, SandboxCommandRequest, SandboxManager, SandboxPathPermission, SandboxPolicy,
};

let manager = SandboxManager::new();

let policy = SandboxPolicy {
    path_permissions: vec![
        SandboxPathPermission::read_only(PathBuf::from("/opt/shared")),
        SandboxPathPermission::read_write(PathBuf::from("/tmp/job-123")),
    ],
    global_access: SandboxAccess::NoAccess,
    network_access: false,
};

let request = SandboxCommandRequest {
    command: vec!["python3".into(), "script.py".into()],
    cwd: PathBuf::from("/workspace"),
    env: std::collections::HashMap::new(),
    timeout_ms: Some(30_000),
};

let output = manager.execute(&request, &policy)?;
println!("exit = {}", output.exit_code);
# Ok::<(), procwarden::SandboxError>(())
```

## Capability matrix

| Platform | Sandboxed execution |
|---|---|
| Linux (landlock+seccomp) | supported |
| macOS (virtualization runner) | supported |
| Windows AppContainer | supported |

## Windows backend

Windows uses a single sandbox backend: **AppContainer**.

Path safety defaults are fixed:

- Reparse points are always rejected for allowlisted paths.
- UNC paths are always permitted as allowlisted paths.

## macOS backend

macOS uses a non-deprecated virtualization runner integration.

By default, procwarden looks for the runner at:

- `/usr/local/bin/procwarden-macos-runner`

You can override this path with:

- `PROCWARDEN_MACOS_RUNNER`

If the runner is unavailable, macOS sandboxed execution fails closed with
`SandboxError::Unavailable`.

## Notes

- `procwarden` only provides sandboxed execution paths.
- Unsupported targets fail at compile time.
