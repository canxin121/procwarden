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
  - each entry has a `path` and a path-level access mode
  - constructors:
    - `SandboxPathPermission::read_only(path)`
    - `SandboxPathPermission::read_write(path)`
- `default_access: SandboxDefaultAccess`
  - `ReadOnly | ReadWrite`
  - interpreted as the fallback rule for paths not explicitly listed in `path_permissions`
  - explicit path rules are overlays on top of this default
  - there is intentionally no global `NoAccess` / allowlist mode in the current API
  - when a backend cannot safely represent a subtractive overlay shape, it rejects the request fail-closed (`SandboxError::InvalidRequest`) instead of silently weakening policy
- `network_access: bool`

`SandboxCommandRequest` contains:

- `command: Vec<String>`
- `cwd: PathBuf`
- `env: HashMap<String, String>`
- `timeout_ms: Option<u64>`

Before platform dispatch, the manager:

1. Validates request shape (`command` non-empty, executable token non-empty, `cwd` exists and is a directory).
2. Validates allow-path policy entries (`read_only` / `read_write`) are non-empty and currently exist, otherwise returns `SandboxError::InvalidRequest`.
3. Sanitizes environment variables (removes dangerous loader/shell injection variables such as `LD_PRELOAD`, `LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`, `BASH_FUNC_*`).

---

## Quick usage example

```rust
use std::path::PathBuf;

use procwarden::{
    SandboxCommandRequest, SandboxDefaultAccess, SandboxManager, SandboxPathPermission,
    SandboxPolicy,
};

let manager = SandboxManager::new();

let policy = SandboxPolicy {
    path_permissions: vec![
        SandboxPathPermission::read_only(PathBuf::from("/opt/shared")),
        SandboxPathPermission::read_write(PathBuf::from("/tmp/job-123")),
    ],
    default_access: SandboxDefaultAccess::ReadOnly,
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

Linux filesystem restrictions are applied in `pre_exec`, and the backend uses two enforcement paths:

- `default_access == ReadWrite`
  - if no `read_only` overlays are present, the backend leaves the filesystem unrestricted.
  - if `read_only` overlays are present, the backend builds bind-mount overlays inside a private mount namespace.
  - all overlay targets must already exist, otherwise execution fails with `SandboxError::InvalidRequest`.
  - if the host cannot create the required user/mount namespaces, execution fails with `SandboxError::Unavailable` instead of silently weakening the policy.
- `default_access == ReadOnly`
  - the backend installs a Landlock ruleset that grants global read access plus explicit write carve-outs from `read_write` paths.

Internal mapping used by the backend:

- `default_write_access = (default_access == ReadWrite)`
- `readable_roots = path_permissions where access in {ReadOnly, ReadWrite}`
- `writable_roots = path_permissions where access == ReadWrite`

Rule construction details for the Landlock path:

- under `ReadOnly`, `"/"` is granted read access.
- `/dev/null` is always granted read/write for practical process I/O compatibility.
- `writable_roots` receive read/write permissions.

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
2. Build the ACL overlay plan from policy.
3. Validate and sanitize overlay paths.
4. Resolve the executable path.
5. Create AppContainer context (SID/profile).
6. If the process is not elevated, request a single UAC elevation and start one elevated helper for ACL + optional network block lifecycle.
7. If already elevated, use native ACL/WFP setup in-process.
8. Apply ACL access plan for the AppContainer SID (native path or elevated helper path).
9. Launch process with AppContainer security capabilities.
10. Capture output and enforce timeout.

### Path safety validation implementation

Manager-level request/policy validation now canonicalizes every existing `cwd` / `path_permissions`
entry before backend dispatch and rejects missing or uncanonicalizable paths with
`SandboxError::InvalidRequest`.

Windows ACL inputs are then sanitized through `ensure_safe_allow_path`:

- path must exist.
- path is canonicalized and de-duplicated again in ASCII case-insensitive mode for ACL application.

### ACL plan implementation

Policy is converted to an ACL plan using default+overlay semantics:

- if `default_access == ReadOnly`, the backend also grants readonly access to the inferred execution scope (for example `cwd`, executable path, executable parent, and path-like command arguments).
- if `default_access == ReadOnly`, explicit `read_write` paths add writable carve-outs on top of that readonly scope.
- if `default_access == ReadWrite`, the inferred execution scope becomes read/write by default, while explicit `read_only` paths are additionally enforced as deny-write overlays.

Then the backend:

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

If WFP setup fails with privilege/support limitations (`ERROR_ACCESS_DENIED` / `ERROR_NOT_SUPPORTED`)
and the current process is not already elevated, the backend requests administrator elevation (UAC)
and installs temporary firewall block rules via an elevated helper.

If the current process is already elevated and WFP still reports unsupported, execution fails closed
with `SandboxError::Windows`; there is no weaker network-enforcement downgrade.

If automatic elevation fails (for example user cancellation), execution fails closed with an
explicit error.

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
- this deny applies to local and external network access (for example loopback and remote endpoints).
- default access is then mapped:
  - `ReadWrite`: explicit `read_only` paths become `file-write*` deny rules.
  - `ReadOnly`: emit a global `(deny file-write*)`, then explicit `read_write` carve-out allow rules.

Path rules are emitted as both `(literal "...")` and `(subpath "...")` filters.

Manager-level validation canonicalizes every existing `SandboxPathPermission` path before the macOS
backend builds SBPL rules. That closes the old alias mismatch gap for existing paths such as
`/var/...` versus `/private/var/...`; missing or uncanonicalizable paths now fail closed up front with
`SandboxError::InvalidRequest`.

---

## Practical Linux/macOS Path Matrix

The matrices below separate the two policy dimensions explicitly:

- `default_access`: the fallback policy for paths not listed in `path_permissions`
- `path_permissions`: the explicit per-path overrides (`read_only`, `read_write`)

"Accepted" means the backend accepts the request shape. "Usable" means it is a reasonable documented
contract today. "Host-capability-dependent" means the policy shape is supported, but the Linux host
must also provide the required mount-namespace capability.

Interpretation notes for the current model:

- There are no filesystem-matrix rows labeled "Conditional" anymore because the global `NoAccess` / allowlist mode has been removed from the public API.
- All `path_permissions` are validated up front by the manager: the path must be non-empty, must already exist, and is canonicalized before platform dispatch.
- The manager also normalizes redundant path rules before platform dispatch: default-equivalent entries are dropped, exact-path conflicts collapse to the effective explicit state, and same-access descendants already covered by an ancestor are removed.
- For Linux rows labeled "Host-capability-dependent":
  - usable means the host can create the required user/mount namespaces after the manager-level path validation has already succeeded.
  - if namespace support is missing, execution fails closed with `SandboxError::Unavailable`.
  - this is not a degraded mode; the backend does not silently continue with weaker enforcement.

### Linux

| `default_access` | `path_permissions` shape | Backend result | Practical status | Notes |
|---|---|---|---|---|
| `ReadWrite` | none | Accepted | Usable | Unrestricted filesystem mode |
| `ReadWrite` | `read_write` only | Accepted | Usable but redundant | `read_write` entries do not add new power over a global write default; manager normalizes them away before backend dispatch |
| `ReadWrite` | `read_only` only | Accepted | Host-capability-dependent | Implemented via mount-namespace overlays; overlay targets must already exist |
| `ReadWrite` | `read_only + read_write` | Accepted | Host-capability-dependent | `read_write` is redundant and is normalized away; `read_only` still needs mount-namespace overlays |
| `ReadOnly` | none | Accepted | Usable | Global read-only mode |
| `ReadOnly` | `read_only` only | Accepted | Usable but redundant | The default already allows reads and denies writes; manager normalizes these entries away |
| `ReadOnly` | `read_write` only | Accepted | Usable | Explicit write carve-outs |
| `ReadOnly` | `read_only + read_write` | Accepted | Usable | `read_only` is redundant and is normalized away; `read_write` adds writable carve-outs |

Linux-specific caveats:

- Any Linux policy shape that requires read-only bind overlays returns `SandboxError::Unavailable` on hosts without the required user/mount namespace support (`CLONE_NEWUSER`/`CLONE_NEWNS` or equivalent `CAP_SYS_ADMIN` capability).
- Overlay-backed subtractive rules currently apply only to already-existing path objects. This is a backend contract on top of the kernel primitives we use: bind mounts need an existing mount point, and creating that target inside only a private mount namespace would still create it on the shared host filesystem.

### macOS

| `default_access` | `path_permissions` shape | Backend result | Practical status | Notes |
|---|---|---|---|---|
| `ReadWrite` | none | Accepted | Usable | Unrestricted filesystem mode |
| `ReadWrite` | `read_write` only | Accepted | Usable but redundant | `read_write` entries do not change a global write default; manager normalizes them away before SBPL generation |
| `ReadWrite` | `read_only` only | Accepted | Usable | Denies writes under those paths |
| `ReadWrite` | `read_only + read_write` | Accepted | Usable | `read_write` is redundant and is normalized away; `read_only` still subtracts writes under those paths |
| `ReadOnly` | none | Accepted | Usable | Global read-only mode |
| `ReadOnly` | `read_only` only | Accepted | Usable but redundant | `read_only` entries do not add new restrictions over a global read-only default; manager normalizes them away |
| `ReadOnly` | `read_write` only | Accepted | Usable | Writable carve-outs are emitted against canonicalized paths |
| `ReadOnly` | `read_only + read_write` | Accepted | Usable | `read_only` is redundant and is normalized away; `read_write` adds writable carve-outs |

macOS-specific caveats:

- Manager-side validation now canonicalizes every existing policy path before SBPL generation and rejects missing or uncanonicalizable entries with `SandboxError::InvalidRequest`.
- There is no strict global-allowlist / `NoAccess` mode in the current API; macOS support is intentionally limited to global read-only or global read-write defaults with path overlays.

---

## GitHub-hosted runner observations

The matrix above describes the platform contract. GitHub Actions results are an observation layer on
top of that contract, not a replacement for it.

As of April 2, 2026, a key fully green three-platform CI run for the current Windows
investigation is:

- [`23888267558`](https://github.com/canxin121/procwarden/actions/runs/23888267558) on `windows-matrix-investigation` ("Fix Windows target clippy lint in matrix probe")

Historical green runs that were still useful for the Linux/macOS investigation:

- [`23849870506`](https://github.com/canxin121/procwarden/actions/runs/23849870506) on `master` ("Clarify Linux and macOS matrix caveats")
- [`23845006394`](https://github.com/canxin121/procwarden/actions/runs/23845006394) on `master` ("fix: align macos noaccess matrix with CI")

What those runs tell us:

- `ubuntu-latest` currently passes the Linux matrix, including the rows still documented as Host-capability-dependent.
- That does not let us relabel those Linux rows as universally Usable: the contract still depends on user/mount namespace support, and other Linux hosts may still fail closed with `SandboxError::Unavailable`.
- `macos-latest` currently passes the remaining public macOS matrix for the `ReadOnly` / `ReadWrite` defaults with path overlays.
- Historical `NoAccess` investigation runs on April 1, 2026 failed on `macos-latest`, for example [`23848403152`](https://github.com/canxin121/procwarden/actions/runs/23848403152) on branch `macos-noaccess-investigation`. That mode has since been removed from the public API and is intentionally no longer part of the matrix.
- CI now also runs a dedicated hosted-runner probe (`cargo run --quiet --bin ci_matrix_probe`) and writes its findings into the GitHub Actions step summary.
- On `windows-latest`, that probe now records the remaining Windows filesystem support matrix for the public `read_only` / `read_write` overlay model plus per-policy wall-clock timing samples so we can tell whether the backend is merely functional or too slow to be practical on hosted runners.

### Windows hosted-runner result (`windows-latest`)

Run [`23888267558`](https://github.com/canxin121/procwarden/actions/runs/23888267558) gives the
first clean three-platform observation for the current public API on GitHub-hosted Windows:

| Probe dimension | Observed result | Interpretation |
|---|---|---|
| Host process elevation | `windows.host_process_elevated=true` | The runner process was already elevated |
| `network_access=true` | `invalid_request` | Current Windows backend contract only supports `network_access=false` |
| Any probed `network_access=false` policy shape | `windows_error(FwpmEngineOpen0 failed: 50 ...)` | WFP dynamic-session setup is unsupported on this host, so execution fails before process launch |
| Enforcement follow-up probes | `wfp_unavailable` | No downgrade occurred; the backend failed closed instead of running with weaker network isolation |
| Per-shape timing samples | `windows.timing.skipped_reason=wfp_unavailable` | There is no "very slow but usable" result here; the runner is effectively unusable for Windows backend execution |

Practical conclusion for GitHub-hosted Windows:

- The current `windows-latest` runner is not a usable environment for this backend.
- The limiting factor is host WFP availability, not the path-permission matrix implementation in this crate.
- Because the process is already elevated on that runner, the non-elevated auto-elevation firewall fallback path is never taken.
- The full `windows-latest` CI job took about 80 seconds, but the hosted-runner diagnostics step took about 1 second; there is no evidence of long per-policy execution time because requests abort during WFP setup.

---

## Three-platform comparison

| Dimension | Linux | Windows | macOS |
|---|---|---|---|
| Primary backend | Landlock + seccomp in-process setup | AppContainer + ACL overlay + WFP filters | Seatbelt profile via system `sandbox-exec` |
| Filesystem enforcement location | Kernel (Landlock) | OS isolation + ACL adjustments | Seatbelt policy (`sandbox-exec`) |
| Network enforcement location | seccomp syscall filtering | WFP ALE-layer filter enforcement | Seatbelt `network*` rule filtering |
| Path pre-validation in this crate | Manager canonicalizes existing request/policy paths before dispatch; kernel still enforces namespaces and overlays | Manager canonicalizes existing request/policy paths, then Windows re-sanitizes ACL inputs case-insensitively | Manager canonicalizes existing request/policy paths before SBPL emission |
| Process timeout handling | Process-group aware timeout kill | Explicit timeout with termination and job containment | Uses shared timeout runner wrapper |
| Missing backend dependency behavior | N/A | Fails closed on unsupported WFP hosts when no helper fallback applies | Fails closed when `sandbox-exec` missing |

---

## Testing and CI status

- GitHub Actions runs on `ubuntu-latest`, `macos-latest`, `windows-latest`.
- CI includes:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --test policy_combination_matrix -- --nocapture`
  - `cargo test --workspace --all-targets -- --nocapture`
  - `cargo run --quiet --bin ci_matrix_probe`
  - upload `ci-matrix-probe-${os}` artifacts from each hosted runner

Current automated coverage emphasis:

- `tests/policy_combination_matrix.rs`: default-access/path-permission shape matrix, including Linux overlay-backed `ReadWrite + read_only` cases and Linux existing-overlay-target fail-closed coverage.
- `tests/policy_access_consistency.rs`: runtime behavior checks for the main default-policy modes.
- `tests/network_access_control.rs`: loopback and external TCP deny checks when `network_access == false`.
- `src/platform/macos.rs` unit tests: SBPL generation order checks for `ReadWrite` and `ReadOnly` profiles.

---

## Notes

- `procwarden` only provides sandboxed execution paths.
- Unsupported targets fail at compile time.
- Backend mechanisms are intentionally platform-specific; policy shape is unified but low-level enforcement is not identical across OSes.
