# procwarden
- 中文文档（简体中文）：[README.zh-CN.md](./README.zh-CN.md)

`procwarden` is a cross-platform Rust crate for running a command under a simple sandbox policy on Linux, macOS, and Windows.

The public entry point is:

- `SandboxManager::execute(&SandboxCommandRequest, &SandboxPolicy)`

## 5-Minute Tutorial

Use `procwarden` in four steps:

1. Pick a default filesystem mode.
2. Add explicit path overrides.
3. Decide whether networking is allowed.
4. Execute the command.

Practical rule of thumb:

- Use `SandboxDefaultAccess::ReadOnly` when you want a safe default and only a few writable paths.
- Use `SandboxDefaultAccess::ReadWrite` when you want normal write access and only need to subtract access from a few paths.

Path override meanings:

- `SandboxPathPermission::read_write(path)`: writable carve-out
- `SandboxPathPermission::read_only(path)`: readable but not writable
- `SandboxPathPermission::deny(path)`: not readable and not writable

Example:

```rust
use std::collections::HashMap;

use procwarden::{
    SandboxCommandRequest, SandboxDefaultAccess, SandboxManager, SandboxPathPermission,
    SandboxPolicy,
};

let manager = SandboxManager::new();

let mut env = HashMap::new();
if let Ok(path) = std::env::var("PATH") {
    env.insert("PATH".to_string(), path);
}

let policy = SandboxPolicy {
    default_access: SandboxDefaultAccess::ReadOnly,
    network_access: false,
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

Practical notes:

- `env` is explicit. `procwarden` does not automatically inherit the parent process environment.
- If your command relies on command lookup, pass at least `PATH`.
- If your command needs a writable scratch directory, create it first and add it as `read_write`.

## Rules You Need To Know

- `cwd` must already exist and must be a directory.
- Every `path_permissions` path must already exist.
- Paths are canonicalized before backend dispatch.
- Redundant rules are removed automatically before execution.
- A descendant path cannot reopen access under a `deny` ancestor.
- `timeout_ms` kills long-running commands and normalizes timeout exit code to `124`.
- `network_access = false` means "deny IP networking", not just "deny public internet".

## Filesystem Matrices

These tables describe practical filesystem behavior. They intentionally focus on the public policy model:

- `default_access`: fallback behavior for paths not listed in `path_permissions`
- `path_permissions`: explicit per-path overrides

Shared meanings:

- `Usable`: verified and expected to work
- `Usable but redundant`: accepted, but the extra rule does not change effective behavior after manager normalization

### Linux

Verified locally on April 4, 2026 on:

- `Linux 6.17.0-19-generic`
- non-root user
- `kernel.unprivileged_userns_clone=1`
- `user.max_user_namespaces=479289`

Linux rows differ by host capability, so the condition is listed per row.

| `default_access` | `path_permissions` shape | Status on tested Linux host | Condition to expect the same result elsewhere |
|---|---|---|---|
| `ReadWrite` | none | Usable | None |
| `ReadWrite` | `read_write` only | Usable but redundant | None |
| `ReadWrite` | `read_only` only | Usable | Requires user/mount namespace support (`CLONE_NEWUSER` + `CLONE_NEWNS`, or equivalent `CAP_SYS_ADMIN`) |
| `ReadWrite` | `deny` only | Usable | Requires user/mount namespace support (`CLONE_NEWUSER` + `CLONE_NEWNS`, or equivalent `CAP_SYS_ADMIN`) |
| `ReadWrite` | `read_only + read_write` | Usable but redundant | Same condition as `ReadWrite + read_only`; `read_write` is normalized away |
| `ReadWrite` | `read_only + deny` | Usable | Requires user/mount namespace support (`CLONE_NEWUSER` + `CLONE_NEWNS`, or equivalent `CAP_SYS_ADMIN`) |
| `ReadOnly` | none | Usable | None |
| `ReadOnly` | `read_only` only | Usable but redundant | None |
| `ReadOnly` | `read_write` only | Usable | None |
| `ReadOnly` | `deny` only | Usable | Requires user/mount namespace support (`CLONE_NEWUSER` + `CLONE_NEWNS`, or equivalent `CAP_SYS_ADMIN`) |
| `ReadOnly` | `read_only + read_write` | Usable | None. `read_only` is normalized away |
| `ReadOnly` | `read_write + deny` | Usable | Requires user/mount namespace support (`CLONE_NEWUSER` + `CLONE_NEWNS`, or equivalent `CAP_SYS_ADMIN`) |

Linux-specific conditions:

- Any Linux row that needs subtractive overlays (`read_only` under `ReadWrite`, or any effective `deny`) also requires the target path to already exist.
- If namespace support is missing, execution fails closed with `SandboxError::Unavailable`.

### macOS

Verified on GitHub Actions `macos-latest` on April 4, 2026 in run `23970597090`.

Shared macOS condition:

- `/usr/bin/sandbox-exec` must exist, or `PROCWARDEN_MACOS_SANDBOX_EXEC` must point to a valid replacement

| `default_access` | `path_permissions` shape | Status on current macOS runner |
|---|---|---|
| `ReadWrite` | none | Usable |
| `ReadWrite` | `read_write` only | Usable but redundant |
| `ReadWrite` | `read_only` only | Usable |
| `ReadWrite` | `deny` only | Usable |
| `ReadWrite` | `read_only + read_write` | Usable |
| `ReadWrite` | `read_only + deny` | Usable |
| `ReadOnly` | none | Usable |
| `ReadOnly` | `read_only` only | Usable but redundant |
| `ReadOnly` | `read_write` only | Usable |
| `ReadOnly` | `deny` only | Usable |
| `ReadOnly` | `read_only + read_write` | Usable |
| `ReadOnly` | `read_write + deny` | Usable |

macOS-specific conditions:

- Existing policy paths are canonicalized before SBPL rules are generated.
- Alias paths such as `/var/...` and `/private/var/...` are normalized up front when the target exists.

### Windows

Latest verified on a real Windows machine on April 3, 2026.

This table is filesystem-only. On Windows, `network_access = false` is a separate host-dependent concern and is called out in the network notes below.

| `default_access` | `path_permissions` shape | Status on latest verified Windows machine |
|---|---|---|
| `ReadWrite` | none | Usable |
| `ReadWrite` | `read_write` only | Usable but redundant |
| `ReadWrite` | `read_only` only | Usable |
| `ReadWrite` | `deny` only | Usable |
| `ReadWrite` | `read_only + read_write` | Usable |
| `ReadWrite` | `read_only + deny` | Usable |
| `ReadOnly` | none | Usable |
| `ReadOnly` | `read_only` only | Usable but redundant |
| `ReadOnly` | `read_write` only | Usable |
| `ReadOnly` | `deny` only | Usable |
| `ReadOnly` | `read_only + read_write` | Usable |
| `ReadOnly` | `read_write + deny` | Usable |

Windows-specific conditions:

- Filesystem rows above are based on a real Windows machine, not a GitHub-hosted runner.
- Existing paths are canonicalized before backend dispatch and then sanitized again for ACL application.

## Network Notes

- Linux: `network_access = false` uses seccomp and blocks IP networking, including loopback, private network traffic, and external network traffic.
- macOS: `network_access = false` maps to Seatbelt `(deny network*)`.
- Windows: `network_access = false` is the most host-dependent path. On the latest verified real Windows machine it was usable, but on hosts without working WFP setup or helper fallback, execution fails closed instead of silently allowing network access.

## Recheck On Your Host

If you want to verify the current matrix on your own machine, run:

```bash
cargo test --test policy_combination_matrix -- --nocapture
cargo test --workspace --all-targets -- --nocapture
cargo run --quiet --bin ci_matrix_probe
```
