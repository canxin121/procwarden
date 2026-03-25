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
- `global_access: SandboxAccess`
  - `NoAccess | ReadOnly | ReadWrite`
- `network_access: bool`

`SandboxCommandRequest` contains:

- `command: Vec<String>`
- `cwd: PathBuf`
- `env: HashMap<String, String>`
- `timeout_ms: Option<u64>`

Before platform dispatch, the manager:

1. Validates request shape (`command` non-empty, executable token non-empty, `cwd` exists and is a directory).
2. Sanitizes environment variables (removes dangerous loader/shell injection variables such as `LD_PRELOAD`, `LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`, `BASH_FUNC_*`).

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

---

## Linux backend (Landlock + seccomp)

Implementation entry: `src/platform/linux.rs`

### Filesystem sandbox implementation

Linux filesystem restrictions are applied in `pre_exec` using Landlock:

- `global_access == ReadWrite`
  - skips Landlock filesystem restriction setup.
- otherwise:
  - installs a Landlock ruleset.
  - grants read scopes and write scopes based on policy-derived roots.

Internal mapping used by the backend:

- `full_disk_read_access = (global_access != NoAccess)`
- `full_disk_write_access = (global_access == ReadWrite)`
- `readable_roots = path_permissions where access in {ReadOnly, ReadWrite}`
- `writable_roots = path_permissions where access == ReadWrite`

Rule construction details:

- if `full_disk_read_access` is true, `"/"` is granted read access.
- otherwise, read access is granted only to `readable_roots`.
- `/dev/null` is always granted read/write for practical process I/O compatibility.
- `writable_roots` receive read/write permissions.

### Network sandbox implementation

When `network_access == false`, a seccomp filter is installed in `pre_exec`:

- denies key network syscalls (`connect`, `accept`, `bind`, `listen`, `send*`, `recv*`, `setsockopt`, etc.).
- denies `ptrace`.
- restricts `socket` and `socketpair` to `AF_UNIX` only.

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
6. If `network_access == false`, install temporary WFP block filters for the executable + AppContainer SID.
7. Apply ACL access plan for the AppContainer SID.
8. Launch process with AppContainer security capabilities.
9. Capture output and enforce timeout.

### Path safety validation implementation

Windows allow/deny paths are validated through `ensure_safe_allow_path`:

- path must exist.
- path is canonicalized and de-duplicated (ASCII case-insensitive mode).

### ACL plan implementation

Policy is converted to an ACL plan:

- if `global_access == ReadWrite`: no explicit allow/deny ACL overlay is added by this layer.
- otherwise:
  - `allow_readonly_paths = read_only_paths`
  - `allow_readwrite_paths = read_write_paths`
  - `deny_paths = denied_paths` (NoAccess entries)

Then the backend:

- adds deny-write ACEs for `deny_paths`.
- adds allow read/execute ACEs for `allow_readonly_paths`.
- adds allow read/write/execute ACEs for `allow_readwrite_paths`.
- tracks changes and revokes them on drop (rollback object).

### Process creation and containment

Process launch uses AppContainer-capable `CreateProcessW` attribute lists:

- `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` (AppContainer SID)
- `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY` (restricted child-process policy)
- `PROC_THREAD_ATTRIBUTE_JOB_LIST` (job object with kill-on-close)

### Network behavior on Windows backend

When `network_access == false`, the backend installs Windows Filtering Platform (WFP) filters in a dynamic session:

- Filters are added transactionally via FWPM APIs.
- Filters target both:
  - application id (`ALE_APP_ID`, derived from resolved executable path), and
  - AppContainer package identity (`ALE_PACKAGE_ID`, sandbox SID).
- Block action is applied on ALE layers for connect/accept/resource-assignment in IPv4 and IPv6.
- Filters live only for the sandbox session lifetime and are removed when the engine session closes (dynamic session semantics).

If WFP setup fails (for example due to missing privileges), execution fails closed with an error.

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
- `deny` paths are translated first into explicit `file-read*` and `file-write*` deny rules
- global access is then mapped:
  - `ReadWrite`: writable everywhere except explicit read-only/deny path rules
  - `ReadOnly`: optional writable carve-outs, then fallback `(deny file-write*)`
  - `NoAccess`: optional read/write carve-outs, then fallback `(deny file-read*)` + `(deny file-write*)`

Path rules are emitted as both `(literal "...")` and `(subpath "...")` filters.

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

- Linux: extensive runtime integration matrix (policy permutations, parent/child/grandchild behavior, network on/off, stress, timeout, path boundaries).
- Windows: compile + integration coverage around AppContainer policy and path safety behavior.
- macOS: SBPL profile compilation and fail-closed behavior tests in crate; runtime enforcement is provided by system `sandbox-exec`.

---

## Notes

- `procwarden` only provides sandboxed execution paths.
- Unsupported targets fail at compile time.
- Backend mechanisms are intentionally platform-specific; policy shape is unified but low-level enforcement is not identical across OSes.
