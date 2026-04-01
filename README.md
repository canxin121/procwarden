# procwarden

- 中文文档（简体中文）：[README.zh-CN.md](./README.zh-CN.md)

`procwarden` is a cross-platform process sandbox crate with an explicit policy model.

The crate exposes one execution API:

- `SandboxManager::execute(&SandboxCommandRequest, &SandboxPolicy)`

and dispatches to platform-specific backends for Linux, macOS, and Windows.

---

## Policy model

`SandboxPolicy` currently contains:

- `path_permissions: Vec<SandboxPathPermission>`
  - each entry has a `path` and an `access` level
  - constructors:
    - `SandboxPathPermission::read_only(path)`
    - `SandboxPathPermission::read_write(path)`
    - `SandboxPathPermission::deny(path)`
- `default_access: SandboxAccess`
  - `NoAccess | ReadOnly | ReadWrite`
  - interpreted as a default rule for paths not explicitly listed in `path_permissions`
  - explicit path rules (`read_only` / `read_write` / `deny`) are overlays on top of this default
  - when a backend cannot safely represent a subtractive overlay shape, it rejects the request fail-closed (`SandboxError::InvalidRequest`) instead of silently weakening policy
- `network_access: bool`

`SandboxCommandRequest` contains:

- `command: Vec<String>`
- `cwd: PathBuf`
- `env: HashMap<String, String>`
- `timeout_ms: Option<u64>`

Before platform dispatch, the manager:

1. Validates request shape (`command` non-empty, executable token non-empty, `cwd` exists and is a directory).
2. Validates allow-path policy entries (`ReadOnly` / `ReadWrite`) are non-empty and currently exist, otherwise returns `SandboxError::InvalidRequest`.
3. Sanitizes environment variables (removes dangerous loader/shell injection variables such as `LD_PRELOAD`, `LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`, `BASH_FUNC_*`).

---

## Quick usage example

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
    default_access: SandboxAccess::NoAccess,
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

---

## Shared execution behavior (all platforms)

- Standard output and error are captured.
- Timeout is enforced.
- Timeout exit code is normalized to `124`.
- `SandboxExecOutput` includes:
  - `exit_code`
  - `stdout`
  - `stderr`
  - `aggregated_output`
  - `duration`
  - `timed_out`
  - `degraded_mode_reason` (`Option<String>`, populated when backend must run in an explicitly-degraded enforcement mode)

---

## Linux backend (Landlock + seccomp)

Implementation entry: `src/platform/linux.rs`

### Filesystem sandbox implementation

Linux filesystem restrictions are applied in `pre_exec`, but the backend currently uses two different enforcement paths:

- `default_access == ReadWrite`
  - if no `ReadOnly` / `NoAccess` overlays are present, the backend leaves the filesystem unrestricted.
  - if `ReadOnly` or `NoAccess` overlays are present, the backend builds bind-mount overlays inside a private mount namespace.
  - all overlay targets must already exist, otherwise execution fails with `SandboxError::InvalidRequest`.
  - if the host cannot create the required user/mount namespaces, execution fails with `SandboxError::Unavailable` instead of silently weakening the policy.
- `default_access == ReadOnly` without any `NoAccess` (`deny`) overlay:
  - installs a Landlock ruleset.
  - grants global read access plus explicit write carve-outs from `read_write` paths.
- `default_access == ReadOnly` with any `NoAccess` (`deny`) overlay:
  - installs deny bind-mount overlays first, then installs the Landlock ruleset for global read-only plus explicit write carve-outs.
  - all denied overlay targets must already exist.
  - if the host cannot create the required user/mount namespaces, execution fails with `SandboxError::Unavailable`.
- `default_access == NoAccess`
  - installs a Landlock allowlist for explicit readable/writable roots.
  - non-overlapping `deny` entries are accepted but are usually redundant because the default is already deny.
  - overlapping `allow` + `deny` scopes are implemented by installing deny bind-mount overlays on the overlapping denied paths before Landlock is applied.
  - overlapping denied overlay targets must already exist.
  - if overlapping deny overlays are needed and the host cannot create the required user/mount namespaces, execution fails with `SandboxError::Unavailable`.
  - the allowlist must include any runtime-readable roots needed to start the executable and its loader/interpreter in addition to the target data paths.

Internal mapping used by the backend:

- `default_read_access = (default_access != NoAccess)`
- `default_write_access = (default_access == ReadWrite)`
- `readable_roots = path_permissions where access in {ReadOnly, ReadWrite}`
- `writable_roots = path_permissions where access == ReadWrite`

Rule construction details for the Landlock path:

- if `default_read_access` is true, `"/"` is granted read access.
- otherwise, read access is granted only to `readable_roots`.
- `/dev/null` is always granted read/write for practical process I/O compatibility.
- `writable_roots` receive read/write permissions.

In practice, `default_access == NoAccess` usually needs runtime roots such as `/bin`, `/usr/bin`, `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, and `/usr/libexec` in the allowlist if the command is launched through `/bin/sh`, an interpreter, or a dynamically linked executable.

### Network sandbox implementation

When `network_access == false`, a seccomp filter is installed in `pre_exec`:

- denies key network syscalls (`connect`, `accept`, `bind`, `listen`, `send*`, `recv*`, `setsockopt`, etc.).
- denies `ptrace`.
- restricts `socket` and `socketpair` to `AF_UNIX` only.
- this is an all-IP-network deny mode (not internet-only): loopback (`127.0.0.1` / `::1`), local subnet, and external network traffic are blocked.

### Notes specific to Linux backend

- The backend uses kernel enforcement primitives directly (Landlock + seccomp).
- If Landlock reports `NotEnforced`, execution fails.

---

## Windows backend (AppContainer + ACL + WFP network filtering)

Implementation entry: `src/platform/windows/mod.rs`

### High-level execution flow

1. Normalize selected environment defaults (`/dev/null`-like values -> `NUL`, non-interactive pager defaults).
2. Build allow/deny path plan from policy.
3. Validate and sanitize allow/deny paths.
4. Resolve the executable path.
5. Create AppContainer context (SID/profile).
6. If the process is not elevated, request a single UAC elevation and start one elevated helper for ACL + optional network block lifecycle.
7. If already elevated, use native ACL/WFP setup in-process.
8. Apply ACL access plan for the AppContainer SID (native path or elevated helper path).
9. Launch process with AppContainer security capabilities.
10. Capture output and enforce timeout.

### Path safety validation implementation

Windows allow/deny paths are validated through `ensure_safe_allow_path`:

- path must exist.
- path is canonicalized and de-duplicated (ASCII case-insensitive mode).

### ACL plan implementation

Policy is converted to an ACL plan using default+overlay semantics:

- `allow_readonly_paths = read_only_paths`
- `allow_readwrite_paths = read_write_paths`
- `deny_readwrite_paths = denied_paths` (`NoAccess` entries)
- if `default_access == ReadWrite`, `read_only_paths` are additionally enforced as deny-write overlays

Then the backend:

- adds deny read/write/execute ACEs for `deny_readwrite_paths`.
- adds deny-write ACEs for read-only overlays under `default_access == ReadWrite`.
- adds allow read/execute ACEs for `allow_readonly_paths`.
- adds allow read/write/execute ACEs for `allow_readwrite_paths`.
- tracks changes and revokes them on drop (rollback object).

When the caller is not elevated, ACL and optional network block setup/cleanup are delegated to a single elevated helper process (one UAC prompt per sandbox execution).

### Process creation and containment

Process launch uses AppContainer-capable `CreateProcessW` attribute lists:

- `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` (AppContainer SID)
- `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` (restricted child-process policy; unsupported/restricted hosts are handled with compatibility fallback)
- `PROC_THREAD_ATTRIBUTE_JOB_LIST` (job object with kill-on-close)

### Network behavior on Windows backend

When `network_access == false`, the backend installs Windows Filtering Platform (WFP) filters in a dynamic session:

- Filters are added transactionally via FWPM APIs.
- Filters target both:
  - application id (`ALE_APP_ID`, derived from resolved executable path), and
  - AppContainer package identity (`ALE_PACKAGE_ID`, sandbox SID).
- Block action is applied on ALE layers for connect/accept/resource-assignment in IPv4 and IPv6.
- Filters live only for the sandbox session lifetime and are removed when the engine session closes (dynamic session semantics).
- Effectively this is all-IP-network deny for the sandboxed process (loopback + local subnet + external network), not only public internet deny.

If WFP setup fails with privilege/support limitations (`ERROR_ACCESS_DENIED` / `ERROR_NOT_SUPPORTED`), the backend automatically requests administrator elevation (UAC) and installs temporary firewall block rules via an elevated helper.

If automatic elevation fails (for example user cancellation), execution fails closed with an explicit error.

---

## macOS backend (built-in Seatbelt via sandbox-exec)

Implementation entry: `src/platform/macos.rs`

The macOS backend uses the system Seatbelt interface through `/usr/bin/sandbox-exec`.

### Runtime resolution

- default sandbox binary: `/usr/bin/sandbox-exec`
- override via env var: `PROCWARDEN_MACOS_SANDBOX_EXEC`

If the sandbox executable is missing, execution fails closed with `SandboxError::Unavailable`.

### Policy translation to SBPL profile

The crate compiles `SandboxPolicy` into an inline SBPL profile string and invokes:

- `sandbox-exec -p <profile> -- <command...>`

Current mapping strategy:

- base profile starts with `(version 1)` and `(allow default)`
- `network_access == false` adds `(deny network*)`
- this deny applies to local and external network access (e.g. loopback and remote endpoints).
- default access is then mapped:
  - `ReadWrite`: explicit `read_only` paths become `file-write*` deny rules; explicit `deny` paths become `file-read*` and `file-write*` deny rules.
  - `ReadOnly`: emit a global `(deny file-write*)`, then explicit `read_write` carve-out allow rules, then explicit `deny` path rules last so deny still overrides carve-outs.
  - `NoAccess`: emit global `(deny file-read*)` and `(deny file-write*)`, then explicit read/write allowlist carve-outs, then explicit `deny` path rules last so deny still overrides overlapping allowlist entries.

Path rules are emitted as both `(literal "...")` and `(subpath "...")` filters.

In practice, macOS path permissions should be canonicalized before constructing `SandboxPathPermission` entries. This avoids alias mismatches such as `/var/...` versus `/private/var/...`, which can make a rule look correct while still missing the real path evaluated by Seatbelt.

---

## Practical Linux/macOS Path Matrix

The matrices below separate the two policy dimensions explicitly:

- `default_access`: the fallback policy for paths not listed in `path_permissions`
- `path_permissions`: the explicit per-path overrides (`read_only`, `read_write`, `deny`)
- operational bootstrap requirements are separate from the matrix itself: under `NoAccess`, normal commands often still need extra allowlisted runtime roots for the executable, loader/interpreter, and usable working directory.

"Accepted" means the backend accepts the request shape. "Usable" means it is a reasonable documented contract today. "Conditional" means the combination depends on extra host/runtime prerequisites. "Host-capability-dependent" means the policy shape is supported, but the Linux host must also provide the required mount-namespace capability. "Conditional + host-capability-dependent" means both kinds of prerequisites apply.

### Linux

| `default_access` | `path_permissions` shape | Backend result | Practical status | Notes |
|---|---|---|---|---|
| `ReadWrite` | none | Accepted | Usable | Unrestricted filesystem mode |
| `ReadWrite` | `read_write` only | Accepted | Usable but redundant | `read_write` entries do not add new power over a global write default |
| `ReadWrite` | `read_only` only | Accepted | Host-capability-dependent | Implemented via mount-namespace overlays; overlay targets must already exist |
| `ReadWrite` | `deny` only | Accepted | Host-capability-dependent | Same overlay caveat as above |
| `ReadWrite` | `read_only + deny` | Accepted | Host-capability-dependent | Same overlay caveat as above |
| `ReadOnly` | none | Accepted | Usable | Global read-only mode |
| `ReadOnly` | `read_only` only | Accepted | Usable but redundant | The default already allows reads and denies writes |
| `ReadOnly` | `read_write` only | Accepted | Usable | Explicit write carve-outs |
| `ReadOnly` | `deny` only | Accepted | Host-capability-dependent | Denied paths are implemented with overlays; writes remain controlled by Landlock |
| `ReadOnly` | `read_only + read_write` | Accepted | Usable | `read_only` is redundant; `read_write` adds writable carve-outs |
| `ReadOnly` | any shape containing `deny` | Accepted | Host-capability-dependent | Includes `read_write + deny` and `read_only + read_write + deny`; deny paths use overlays |
| `NoAccess` | none | Accepted | Usually not usable for normal commands | Normal dynamically linked commands still need runtime-readable roots to bootstrap |
| `NoAccess` | `read_only` only | Accepted | Conditional | Explicit read allowlist only; runtime/bootstrap roots must also be allowed if needed |
| `NoAccess` | `read_write` only | Accepted | Conditional | Explicit read/write allowlist only; same bootstrap caveat |
| `NoAccess` | `read_only + read_write` | Accepted | Conditional | Typical allowlist mode; same bootstrap caveat |
| `NoAccess` | non-overlapping `deny` added to any non-overlapping allowlist | Accepted | Conditional | Usually redundant because the default is already deny |
| `NoAccess` | overlapping allow + `deny` | Accepted | Conditional + host-capability-dependent | Overlapping denied paths are implemented with overlays; runtime roots and namespace support are both required |

Linux-specific caveats:

- Any Linux policy shape that requires deny/read-only bind overlays returns `SandboxError::Unavailable` on hosts without the required user/mount namespace support (`CLONE_NEWUSER`/`CLONE_NEWNS` or equivalent `CAP_SYS_ADMIN` capability).
- `NoAccess` policies must usually allow runtime/bootstrap roots such as `/bin`, `/usr/bin`, `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`, and `/usr/libexec` in addition to the target data paths.

### macOS

| `default_access` | `path_permissions` shape | Backend result | Practical status | Notes |
|---|---|---|---|---|
| `ReadWrite` | none | Accepted | Usable | Unrestricted filesystem mode |
| `ReadWrite` | `read_write` only | Accepted | Usable but redundant | `read_write` entries do not change a global write default |
| `ReadWrite` | `read_only` only | Accepted | Usable with canonicalized paths | Denies writes under those paths |
| `ReadWrite` | `deny` only | Accepted | Usable with canonicalized paths | Denies reads and writes under those paths |
| `ReadWrite` | `read_only + deny` | Accepted | Usable with canonicalized, non-overlapping paths | Normal subtractive overlay case on macOS |
| `ReadOnly` | none | Accepted | Usable | Global read-only mode |
| `ReadOnly` | `read_only` only | Accepted | Usable but redundant | `read_only` entries do not add new restrictions over a global read-only default |
| `ReadOnly` | `read_write` only | Accepted | Usable with canonicalized paths | Writable carve-outs depend on the policy path matching the canonical path seen by Seatbelt |
| `ReadOnly` | `deny` only | Accepted | Usable with canonicalized paths | Read/write deny path; same canonicalization caveat |
| `ReadOnly` | `read_only + read_write` | Accepted | Usable with canonicalized paths | `read_only` is redundant; `read_write` adds writable carve-outs |
| `ReadOnly` | `read_write + deny` | Accepted | Usable with canonicalized, non-overlapping paths | Writable carve-out plus denied path; explicit deny rules are emitted after carve-outs |
| `ReadOnly` | `read_only + read_write + deny` | Accepted | Usable with canonicalized, non-overlapping paths | Same caveat as above |
| `NoAccess` | none | Accepted | Usually not usable for normal commands | Command/runtime bootstrap paths are also denied |
| `NoAccess` | `read_only` only | Accepted | Conditional | Usable on current `macos-15-arm64` CI when the allowlist also includes canonicalized runtime roots and required bootstrap device nodes |
| `NoAccess` | `read_write` only | Accepted | Conditional | Same bootstrap caveat: include runtime roots plus required macOS device nodes |
| `NoAccess` | `read_only + read_write` | Accepted | Conditional | Runnable on current CI with the bootstrap allowlist; typical strict-allowlist mode |
| `NoAccess` | non-overlapping `deny` added to any non-overlapping allowlist | Accepted | Conditional | Runnable on current CI with the same bootstrap prerequisites; `deny` is usually redundant because the default is already deny |
| `NoAccess` | overlapping allow + `deny` | Accepted | Conditional, verify deny precedence on the target macOS | The policy shape is runnable on current CI; explicit deny is still emitted after allowlist rules, but overlap precedence should still be validated on the macOS version you target |

macOS-specific caveats:

- Path-based policies are only reliable when the policy paths match the canonical paths seen by Seatbelt, for example `/private/var/...` instead of an unresolved `/var/...` alias.
- `NoAccess` profiles now emit literal read allowances for every ancestor of each allowlisted readable path. Without those ancestor literals, Seatbelt could deny path traversal before the allowlisted subtree was ever reached.
- In practice, runnable macOS `NoAccess` policies still need bootstrap paths beyond the target data subtree. Current CI coverage on `macos-15-arm64` uses canonicalized runtime roots plus read-write device nodes such as `/dev/null`, `/dev/tty`, and `/dev/dtracehelper`.
- Treat macOS `NoAccess` as conditionally runnable rather than universally runnable: validate the exact command, runtime roots, and device-node requirements on the macOS version you ship against.

---

## Three-platform comparison

| Dimension | Linux | Windows | macOS |
|---|---|---|---|
| Primary backend | Landlock + seccomp in-process setup | AppContainer + ACL overlay + WFP filters | Seatbelt profile via system `sandbox-exec` |
| Filesystem enforcement location | Kernel (Landlock) | OS isolation + ACL adjustments | Seatbelt policy (`sandbox-exec`) |
| Network enforcement location | seccomp syscall filtering | WFP ALE-layer filter enforcement | Seatbelt `network*` rule filtering |
| Path pre-validation in this crate | Minimal path extraction; kernel decides enforcement | Strict path safety validation before ACL apply | Paths forwarded to runner arguments |
| Process timeout handling | Process-group aware timeout kill | Explicit timeout with termination and job containment | Uses shared timeout runner wrapper |
| Missing backend dependency behavior | N/A | N/A | Fails closed when `sandbox-exec` missing |

---

## Testing and CI status

- GitHub Actions runs on `ubuntu-latest`, `macos-latest`, `windows-latest`.
- CI includes:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace --all-targets -- --nocapture`

Current automated coverage emphasis:

- `tests/policy_combination_matrix.rs`: default-access/path-permission shape matrix, including Linux overlay-backed `ReadWrite` / `ReadOnly + deny` / `NoAccess + overlapping deny` cases and runnable `NoAccess` allowlist coverage on both Linux and macOS CI.
- `tests/policy_access_consistency.rs`: runtime behavior checks for the main default-policy modes, including Linux `NoAccess` bootstrap regression coverage and macOS `NoAccess` / `ReadOnly + read_write + deny` behavior when run on macOS CI.
- `tests/network_access_control.rs`: loopback and external TCP deny checks when `network_access == false`.
- `src/platform/macos.rs` unit tests: SBPL generation order checks for `ReadWrite`, `ReadOnly`, and `NoAccess` profiles.

---

## Notes

- `procwarden` only provides sandboxed execution paths.
- Unsupported targets fail at compile time.
- Backend mechanisms are intentionally platform-specific; policy shape is unified but low-level enforcement is not identical across OSes.
