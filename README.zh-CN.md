# procwarden（中文文档）

- English README: [README.md](./README.md)

`procwarden` 是一个跨平台的进程沙盒 crate，提供统一的策略模型与平台化执行后端。

本 crate 暴露一个统一执行入口：

- `SandboxManager::execute(&SandboxCommandRequest, &SandboxPolicy)`

并在 Linux / macOS / Windows 上分发到各自的后端实现。

---

## 策略模型

当前 `SandboxPolicy` 包含：

- `path_permissions: Vec<SandboxPathPermission>`
  - 每一项都包含 `path` 和路径级访问模式
  - 构造函数：
    - `SandboxPathPermission::deny(path)`
    - `SandboxPathPermission::read_only(path)`
    - `SandboxPathPermission::read_write(path)`
- `default_access: SandboxDefaultAccess`
  - `ReadOnly | ReadWrite`
  - 表示未命中 `path_permissions` 时的默认访问策略
  - 显式路径规则会叠加覆盖默认策略
  - 当前 API 有意不再提供全局 `NoAccess` / allowlist 模式
  - 若后端无法安全表达某些“减法覆盖”组合，会 fail-closed 返回 `SandboxError::InvalidRequest`，不会静默弱化策略
- `network_access: bool`

`SandboxCommandRequest` 包含：

- `command: Vec<String>`
- `cwd: PathBuf`
- `env: HashMap<String, String>`
- `timeout_ms: Option<u64>`

在进入平台后端前，manager 会先做：

1. 请求校验（`command` 非空、可执行 token 非空、`cwd` 必须存在且为目录）。
2. 策略路径校验（`deny` / `read_only` / `read_write` 路径必须非空且当前存在，否则返回 `SandboxError::InvalidRequest`）。
3. 环境变量净化（移除高风险加载/注入变量，如 `LD_PRELOAD`、`LD_*`、`DYLD_*`、`BASH_ENV`、`ENV`、`BASH_FUNC_*`）。

---

## 快速使用示例

```rust
use std::path::PathBuf;

use procwarden::{
    SandboxCommandRequest, SandboxDefaultAccess, SandboxManager, SandboxPathPermission,
    SandboxPolicy,
};

let manager = SandboxManager::new();

let policy = SandboxPolicy {
    path_permissions: vec![
        SandboxPathPermission::deny(PathBuf::from("/workspace/secrets")),
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

## 共享执行行为（所有平台）

- 捕获标准输出和标准错误。
- 支持超时控制。
- 超时退出码统一归一为 `124`。
- 返回 `SandboxExecOutput`，包含：
  - `exit_code`
  - `stdout`
  - `stderr`
  - `aggregated_output`
  - `duration`
  - `timed_out`
  - `degraded_mode_reason`（`Option<String>`，当后端以显式降级约束模式运行时返回原因）

---

## Linux 后端（Landlock + seccomp）

实现入口：`src/platform/linux.rs`

### 文件系统沙盒实现

Linux 文件系统限制在 `pre_exec` 中设置，当前后端分成两条执行路径：

- `default_access == ReadWrite`
  - 若不存在 `read_only` 覆盖路径，则保持文件系统默认可访问。
  - 若存在 `read_only` 覆盖路径，则通过私有 mount namespace 中的 bind-mount overlay 实现覆盖。
  - 所有 overlay 目标路径都必须已经存在，否则返回 `SandboxError::InvalidRequest`。
  - 若宿主环境无法创建所需的 user/mount namespace，则返回 `SandboxError::Unavailable`，不会静默弱化策略。
- `default_access == ReadOnly`
  - 安装 Landlock ruleset，提供全局读权限，并通过 `read_write` 路径提供显式写 carve-out。

后端内部映射关系：

- `default_write_access = (default_access == ReadWrite)`
- `readable_roots = path_permissions 中 access ∈ {ReadOnly, ReadWrite}`
- `writable_roots = path_permissions 中 access == ReadWrite`

Landlock 路径下的规则细节：

- 在 `ReadOnly` 模式下，对 `"/"` 授予读权限。
- 始终对 `/dev/null` 授予读写权限（保证常见进程 I/O 兼容）。
- 对 `writable_roots` 授予读写权限。

### 网络沙盒实现

当 `network_access == false` 时，在 `pre_exec` 安装 seccomp 过滤器：

- 拒绝核心网络 syscall（`connect`、`accept`、`bind`、`listen`、`send*`、`recv*`、`setsockopt` 等）。
- 拒绝 `ptrace`。
- `socket` / `socketpair` 仅允许 `AF_UNIX`。
- 该模式是“全 IP 网络阻断”（不是只禁公网）：会阻断 loopback（`127.0.0.1` / `::1`）、内网网段与外网访问。

### Linux 后端说明

- 该后端直接依赖内核级约束（Landlock + seccomp）。
- 如果 Landlock 返回 `NotEnforced`，则执行失败。

---

## Windows 后端（AppContainer + ACL + WFP 网络过滤）

实现入口：`src/platform/windows/mod.rs`

### 高层执行流程

1. 规范化部分环境默认值（如 `/dev/null` 风格值映射到 `NUL`、设置非交互 pager 默认值）。
2. 从 policy 构建 ACL 覆盖计划。
3. 对覆盖路径做校验和清洗。
4. 解析可执行文件路径。
5. 创建 AppContainer 上下文（SID/profile）。
6. 当当前进程非管理员时，请求一次 UAC 提权，并启动一个统一提权 helper 管理 ACL + 可选网络阻断生命周期。
7. 若当前已是管理员，则在当前进程内走原生 ACL/WFP 设置路径。
8. 对 AppContainer SID 应用 ACL 访问计划（原生路径或统一提权 helper 路径）。
9. 以 AppContainer 安全能力启动目标进程。
10. 捕获输出并处理超时。

### 路径安全校验实现

manager 层现在会在分发到后端前，统一对所有已存在的 `cwd` / `path_permissions`
做 canonicalize；缺失路径或无法 canonicalize 的路径会直接返回
`SandboxError::InvalidRequest`。

Windows ACL 输入随后还会通过 `ensure_safe_allow_path` 再做一次清洗：

- 路径必须存在。
- 再做一遍 canonicalize，并按 ASCII 大小写不敏感方式去重，供 ACL 应用使用。

### ACL 计划实现

policy 按“默认 + 覆盖”转换为 ACL 计划：

- 当 `default_access == ReadOnly` 时，后端还会给推断出的执行范围增加只读权限，例如 `cwd`、可执行文件路径、可执行文件父目录，以及命令参数中解析出的路径。
- 当 `default_access == ReadOnly` 时，显式 `read_write` 路径会在这个只读范围上增加可写 carve-out。
- 当 `default_access == ReadWrite` 时，这些推断出的执行范围默认变成可读写，而显式 `read_only` 路径会额外生成 deny-write 覆盖。

随后：

- 对 `default_access == ReadWrite` 下的 read-only 覆盖路径增加 deny-write ACE。
- 对 `allow_readonly_paths` 增加 allow read/execute ACE。
- 对 `allow_readwrite_paths` 增加 allow read/write/execute ACE。
- 用 rollback 对象跟踪并在结束时撤销。

当调用方非管理员时，ACL 与可选网络阻断的设置/清理会委托给单个提权 helper 进程（每次 sandbox 执行仅一次 UAC）。

### 进程创建与约束

通过 AppContainer 相关属性创建进程（`CreateProcessW` 属性列表）：

- `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`（AppContainer SID）
- `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`（限制子进程策略；在不支持/受限宿主上使用兼容回退）
- `PROC_THREAD_ATTRIBUTE_JOB_LIST`（job 对象 + kill-on-close）

### Windows 的网络行为

当 `network_access == false` 时，后端会通过 WFP（Windows Filtering Platform）在动态会话中安装阻断规则：

- 使用 FWPM API 事务化添加过滤器。
- 过滤条件同时包含：
  - 应用标识（`ALE_APP_ID`，由可执行文件路径解析得到）
  - AppContainer 包身份（`ALE_PACKAGE_ID`，对应沙盒 SID）
- 在 IPv4/IPv6 的 connect/accept/resource-assignment 对应 ALE 层执行 block。
- 过滤器随动态会话生命周期存在；会话关闭后自动清理。
- 效果上属于沙盒进程“全 IP 网络阻断”（loopback + 内网 + 外网），不是仅阻断公网。

若 WFP 因权限/环境限制失败（`ERROR_ACCESS_DENIED` / `ERROR_NOT_SUPPORTED`），且当前进程
本身还不是管理员，后端会自动发起管理员提权（UAC），并通过提权 helper 安装临时防火墙
阻断规则。

若当前进程已经是管理员，而 WFP 仍报告 unsupported，则执行会直接以
`SandboxError::Windows` fail-closed，不会降级到更弱的网络约束模式。

若自动提权失败（例如用户取消），执行会以明确错误 fail-closed。

---

## macOS 后端（内置 Seatbelt：sandbox-exec）

实现入口：`src/platform/macos.rs`

macOS 后端通过系统自带的 `/usr/bin/sandbox-exec` 使用 Seatbelt 策略。

### 运行时解析

- 默认 sandbox 可执行路径：`/usr/bin/sandbox-exec`
- 可通过环境变量覆盖：`PROCWARDEN_MACOS_SANDBOX_EXEC`

如果 sandbox 可执行文件不存在，执行会 fail-closed，返回 `SandboxError::Unavailable`。

### 策略映射到 SBPL profile

crate 会把 `SandboxPolicy` 编译为内联 SBPL profile，然后执行：

- `sandbox-exec -p <profile> -- <command...>`

当前映射策略：

- profile 以 `(version 1)` 和 `(allow default)` 开始
- `network_access == false` 时添加 `(deny network*)`
- 该 deny 覆盖本地与外部网络访问（例如 loopback 与远端地址）。
- 再映射默认权限：
  - `ReadWrite`：对显式 `read_only` 路径生成 `file-write*` deny。
  - 显式 `deny` 路径会同时生成 `file-read*` 与 `file-write*` deny。
  - `ReadOnly`：先发出全局 `(deny file-write*)`，再加入显式 `read_write` carve-out allow，最后再叠加显式 `deny` 路径。

每条路径规则会同时输出 `(literal "...")` 与 `(subpath "...")` 条件。

manager 层现在会先把所有已存在的 `SandboxPathPermission` 路径 canonicalize，再交给
macOS 后端生成 SBPL 规则。这样像 `/var/...` 与 `/private/var/...` 这种既有别名路径，
只要目标对象存在，就会先在入口处归一化；缺失路径或无法 canonicalize 的路径会直接
fail-closed，返回 `SandboxError::InvalidRequest`。

---

## Linux/Windows/macOS 实际可用文件系统矩阵

下面这些表把两个文件系统策略维度拆开写：

- `default_access`：未命中 `path_permissions` 时的默认策略
- `path_permissions`：显式路径覆盖规则（`deny`、`read_only`、`read_write`）

其中“Accepted”表示后端接受该请求形状；“可用”表示当前可以作为稳定文档 contract
依赖；“依赖宿主能力”表示策略形状本身受支持，但 Linux 宿主还必须具备所需的
mount-namespace 能力。

当前模型下，这些标签应这样理解：

- 现在的文件系统矩阵里已经没有“有条件可用”行，因为公开 API 已经移除了全局 `NoAccess` / allowlist 模式。
- 所有 `path_permissions` 都会先经过 manager 前置校验：路径不能为空、必须已经存在，并且会在平台分发前 canonicalize。
- manager 还会在平台分发前做冗余规则归一化：与默认权限等价的条目会被删除；同一路径上的冲突会折叠成真正生效的显式状态；已经被同 access 祖先覆盖的子路径条目也会被移除。
- `deny` 只作为“路径级显式状态”存在；当前 API 仍然没有全局 `NoAccess` 默认模式。
- 不允许在显式 `deny` 祖先路径下面再用子路径重新放开权限；这种形状会 fail-closed，返回 `SandboxError::InvalidRequest`。
- 对 Linux 中标记为“依赖宿主能力”的行：
  - “可用”意味着 manager 侧路径校验已通过，并且宿主还能创建所需的 user/mount namespace。
  - 如果 namespace 能力缺失，执行会 fail-closed，返回 `SandboxError::Unavailable`。
  - 这不是降级模式；后端不会在弱化约束后继续执行。

### Linux

| `default_access` | `path_permissions` 形状 | 后端结果 | 实际状态 | 说明 |
|---|---|---|---|---|
| `ReadWrite` | 无 | Accepted | 可用 | 全局可读写模式 |
| `ReadWrite` | 仅 `read_write` | Accepted | 可用但冗余 | 默认已全局可写，额外 `read_write` 不增加权限；manager 会在分发到后端前把它归一化掉 |
| `ReadWrite` | 仅 `read_only` | Accepted | 依赖宿主能力 | 通过 mount-namespace overlay 实现；overlay 目标路径必须已存在 |
| `ReadWrite` | 仅 `deny` | Accepted | 依赖宿主能力 | 通过 mount-namespace 替换 overlay 加不可读占位对象实现 |
| `ReadWrite` | `read_only + read_write` | Accepted | 依赖宿主能力 | `read_write` 冗余，会被归一化掉；`read_only` 仍需要 mount-namespace overlay |
| `ReadWrite` | `read_only + deny` | Accepted | 依赖宿主能力 | `deny` 比 `read_only` 更强；两者在 Linux 上都依赖 overlay |
| `ReadOnly` | 无 | Accepted | 可用 | 全局只读模式 |
| `ReadOnly` | 仅 `read_only` | Accepted | 可用但冗余 | 默认已允许读、拒绝写；manager 会把这些条目归一化掉 |
| `ReadOnly` | 仅 `read_write` | Accepted | 可用 | 显式写 carve-out |
| `ReadOnly` | 仅 `deny` | Accepted | 依赖宿主能力 | 通过 mount-namespace 替换 overlay 加不可读占位对象实现 |
| `ReadOnly` | `read_only + read_write` | Accepted | 可用 | `read_only` 冗余，会被归一化掉；`read_write` 提供写 carve-out |
| `ReadOnly` | `read_write + deny` | Accepted | 依赖宿主能力 | `deny` 可以进一步收紧写 carve-out；Linux 仍依赖 overlay |

Linux 额外前提：

- 任何需要 read-only 或 deny overlay 的 Linux 策略形状，在宿主不支持所需 user/mount namespace（`CLONE_NEWUSER`/`CLONE_NEWNS`，或等价 `CAP_SYS_ADMIN`）时，都会返回 `SandboxError::Unavailable`。
- 依赖 overlay 的减法规则目前只适用于“已经存在的路径对象”。这不仅是当前后端契约，也来自所用内核原语的边界：bind mount 需要已有 mount point，而如果只在私有 mount namespace 里临时创建这个目标，那个文件或目录仍然会真实出现在共享的宿主文件系统上。
- 对具备能力的宿主，目录级 `deny` overlay 现在会先 bind mount，再 remount 成只读。这样可以堵住 2026-04-04 本地复测时暴露出来的那个缺口：旧实现会让“已有条目被隐藏了，但 denied 目录里仍然能新建文件”。

### Linux 真机矩阵（本机，2026-04-04 重新复测）

下面这些行记录的是 2026-04-04 在当前这台 Linux 机器上重新复测得到的真实结果
（`Linux 6.17.0-19-generic`、非 root `uid=1000`、`kernel.unprivileged_userns_clone=1`、
`user.max_user_namespaces=479289`）。它们比上面的 contract 表更窄，只描述当前 `main`
分支在这台宿主上的实际行为。

| `default_access` | `path_permissions` 形状 | probe 行 | enforcement 跟进 | 这台机器上的实际状态 | 说明 |
|---|---|---|---|---|---|
| `ReadWrite` | 无 | `linux.matrix.readwrite_none=runnable` | N/A | 可用 | 不需要任何 overlay |
| `ReadWrite` | 仅 `read_write` | `linux.matrix.readwrite_readwrite=runnable` | N/A | 可用但冗余 | manager 会在分发到后端前把这个冗余 `read_write` 条目归一化掉 |
| `ReadWrite` | 仅 `read_only` | `linux.matrix.readwrite_readonly=runnable` | `linux.enforcement.readwrite_readonly=ok` | 可用 | 已在本机复测“非 readonly 路径可写”以及“readonly 路径内写入被阻断” |
| `ReadWrite` | 仅 `deny` | `linux.matrix.readwrite_deny=runnable` | `linux.enforcement.readwrite_deny=ok` | 可用 | 已在本机复测“已有文件读取被阻断”以及“denied 目录内新建文件被阻断” |
| `ReadWrite` | `read_only + read_write` | `linux.matrix.readwrite_readonly_readwrite=runnable` | `linux.enforcement.readwrite_readonly=ok` | 可用但冗余 | 生效行为与 `ReadWrite` + `read_only` 相同，因为 `read_write` 会被归一化掉 |
| `ReadWrite` | `read_only + deny` | `linux.matrix.readwrite_readonly_deny=runnable` | `linux.enforcement.readwrite_readonly=ok`; `linux.enforcement.readwrite_deny=ok` | 可用 | 已在本机复测两类减法 overlay 同时处于可用状态 |
| `ReadOnly` | 无 | `linux.matrix.readonly_none=runnable` | N/A | 可用 | 全局只读模式 |
| `ReadOnly` | 仅 `read_only` | `linux.matrix.readonly_readonly=runnable` | N/A | 可用但冗余 | manager 会在分发到后端前把这个冗余 `read_only` 条目归一化掉 |
| `ReadOnly` | 仅 `read_write` | `linux.matrix.readonly_readwrite=runnable` | `linux.enforcement.readonly_readwrite=ok` | 可用 | 已在本机复测“carve-out 内可写”和“carve-out 外仍不可写” |
| `ReadOnly` | 仅 `deny` | `linux.matrix.readonly_deny=runnable` | `linux.enforcement.readonly_deny=ok` | 可用 | 已在本机复测 denied 路径下已有文件的读取会被阻断 |
| `ReadOnly` | `read_only + read_write` | `linux.matrix.readonly_readonly_readwrite=runnable` | `linux.enforcement.readonly_readwrite=ok` | 可用 | 生效行为与 `ReadOnly` + `read_write` 相同，因为 `read_only` 会被归一化掉 |
| `ReadOnly` | `read_write + deny` | `linux.matrix.readonly_readwrite_deny=runnable` | `linux.enforcement.readonly_readwrite_deny=ok` | 可用 | 已在本机复测“可写 carve-out 下的 nested deny 仍能收紧读写” |

这次宿主级复测的直接依据是：

- `cargo run --quiet --bin ci_matrix_probe`
- `cargo test --test policy_combination_matrix -- --nocapture`
- `cargo test --test policy_access_consistency -- --nocapture`
- `cargo test -- --nocapture`

### Windows

| `default_access` | `path_permissions` 形状 | 后端结果 | 实际状态 | 说明 |
|---|---|---|---|---|
| `ReadWrite` | 无 | Accepted | 可用 | 当前 AppContainer 模型下的全局可读写文件系统模式 |
| `ReadWrite` | 仅 `read_write` | Accepted | 可用但冗余 | 默认已全局可写，额外 `read_write` 不增加权限；manager 会在分发到后端前把它归一化掉 |
| `ReadWrite` | 仅 `read_only` | Accepted | 可用 | 通过对命中路径施加减法式写拒绝来实现 |
| `ReadWrite` | 仅 `deny` | Accepted | 可用 | 通过对命中路径施加 deny-read/write/execute ACL 来实现 |
| `ReadWrite` | `read_only + read_write` | Accepted | 可用 | `read_write` 冗余，会被归一化掉；`read_only` 仍会在对应路径下减掉写权限 |
| `ReadWrite` | `read_only + deny` | Accepted | 可用 | `deny` 比 `read_only` 更强；Windows 会把两者都下发成路径 ACL 调整 |
| `ReadOnly` | 无 | Accepted | 可用 | 全局只读模式 |
| `ReadOnly` | 仅 `read_only` | Accepted | 可用但冗余 | 默认已允许读、拒绝写；manager 会把这些条目归一化掉 |
| `ReadOnly` | 仅 `read_write` | Accepted | 可用 | 显式写 carve-out |
| `ReadOnly` | 仅 `deny` | Accepted | 可用 | 在默认可读范围里显式扣掉“不可读/不可写”的路径 |
| `ReadOnly` | `read_only + read_write` | Accepted | 可用 | `read_only` 冗余，会被归一化掉；`read_write` 提供写 carve-out |
| `ReadOnly` | `read_write + deny` | Accepted | 可用 | `deny` 可以进一步收紧写 carve-out |

Windows 额外说明：

- 在当前这台真实 Windows 机器上，上面文档化的 Windows 文件系统行现在都能跑通，而且 `ReadOnly + read_write`、`ReadWrite + read_only`、`ReadOnly + deny` 与 `ReadWrite + deny` 的 enforcement 跟进探针也都通过。
- 在这台机器上，2026-04-03 本地执行 `cargo run --quiet --bin ci_matrix_probe` 时，文档里的 Windows 文件系统形状每次 `manager.execute` 的 wall-clock 样本大致落在 17-24 秒之间。
- manager 侧仍然要求路径必须已存在，并会在平台分发前 canonicalize；之后 Windows 还会以大小写不敏感的方式再次清洗 ACL 输入，再应用访问调整。
- 网络行为和上面的文件系统矩阵是独立维度。当前真机网络结论单独列在下面，不和路径矩阵混在一起。

### Windows `network_access` 真机矩阵

下面这些行描述的是 `windows-matrix-investigation` 分支在当前这台机器上，于 2026-04-03
重新确认后的真机结果。它们才是这个分支 Windows 实际行为的主要依据；下面 GitHub
Hosted `windows-latest` 的结果仍然只作为历史观察，因为那个 runner 依旧受 WFP 限制。
这些行也比一般 API contract 更窄，因为 Windows 的 loopback 行为目前仍然依赖具体
probe 形状。

| `network_access` | probe 形状 | 实际结果 | 实际状态 | 说明 |
|---|---|---|---|---|
| `true` | 对默认网关上第一个可达 TCP 端口（`53` / `80` / `443`）做私网 outbound 探测 | `connect_ok` | 当存在可达私网目标时，这台机器上可用 | 由本地 `tests/network_access_control.rs` 套件验证；如果 probe 当时找不到可达默认网关目标，`ci_matrix_probe` 现在会输出 `skipped(no_reachable_default_gateway_target)`，而不是误报失败 |
| `true` | 连到“同一可执行文件内部持有的 listener”（`ci_matrix_probe --windows-net-probe`）的 loopback 探测 | `connect_ok` | 当前机器上可用 | 已用本地 `ci_matrix_probe` 重新确认；probe 现在会先启动 listener 再测试这一路径 |
| `true` | 通过 `windows_net_diag` 连接一个通用 host-side listener 的 loopback 探测 | `connect_failed` | 当前后端仍受限 | `tests/network_access_control.rs` 仍把它作为已知剩余限制记录 |
| `false` | 对同一个默认网关目标做私网 outbound 探测 | `connect_failed(... internet_client ...)` | 阻断行为可用 | 由本地 `tests/network_access_control.rs` 套件验证；这里是 fail-closed，不会静默降级 |
| `false` | 对同一可执行文件 listener 的 loopback 探测 | `connect_failed(... timed out ...)` | 阻断行为可用 | 已用本地 `ci_matrix_probe` 重新确认；关闭网络时 loopback 仍然被阻断 |

### macOS

| `default_access` | `path_permissions` 形状 | 后端结果 | 实际状态 | 说明 |
|---|---|---|---|---|
| `ReadWrite` | 无 | Accepted | 可用 | 全局可读写模式 |
| `ReadWrite` | 仅 `read_write` | Accepted | 可用但冗余 | 默认已全局可写，额外 `read_write` 不改变行为；manager 会在生成 SBPL 前把它归一化掉 |
| `ReadWrite` | 仅 `read_only` | Accepted | 可用 | 会在这些路径下拒绝写入 |
| `ReadWrite` | 仅 `deny` | Accepted | 可用 | 会对这些路径发出 `file-read*` 与 `file-write*` deny |
| `ReadWrite` | `read_only + read_write` | Accepted | 可用 | `read_write` 冗余，会被归一化掉；`read_only` 仍会在对应路径下拒绝写入 |
| `ReadWrite` | `read_only + deny` | Accepted | 可用 | `deny` 比 `read_only` 更强；两者都会以减法式 SBPL 规则发出 |
| `ReadOnly` | 无 | Accepted | 可用 | 全局只读模式 |
| `ReadOnly` | 仅 `read_only` | Accepted | 可用但冗余 | `read_only` 相对全局只读默认策略不增加限制；manager 会把它归一化掉 |
| `ReadOnly` | 仅 `read_write` | Accepted | 可用 | 写 carve-out 会针对 canonicalize 后的路径发出 |
| `ReadOnly` | 仅 `deny` | Accepted | 可用 | 在默认可读范围上再叠加每路径读/写 deny |
| `ReadOnly` | `read_only + read_write` | Accepted | 可用 | `read_only` 冗余，会被归一化掉；`read_write` 提供写 carve-out |
| `ReadOnly` | `read_write + deny` | Accepted | 可用 | `deny` 可以进一步收紧写 carve-out |

macOS 额外前提：

- manager 现在会在生成 SBPL 之前，把所有已存在的 policy 路径 canonicalize，并对缺失或无法 canonicalize 的条目直接返回 `SandboxError::InvalidRequest`。
- 当前 API 不再提供严格的全局 allowlist / `NoAccess` 模式；macOS 只支持“全局只读”或“全局读写”再叠加路径覆盖。

---

## GitHub-hosted runner 观测

上面的矩阵描述的是平台 contract。GitHub Actions 的结果只是这个 contract 之上的观测层，
不能直接替代 contract 本身。

截至 2026 年 4 月 2 日，当前公开策略模型下一个关键的三平台全绿 CI run 是：

- [`23893105166`](https://github.com/canxin121/procwarden/actions/runs/23893105166)，`windows-matrix-investigation` 分支，标题 "Allow Linux host-capability skips in readonly overlay test"

之前对 Linux/macOS 调查仍然有参考价值的历史全绿 run：

- [`23849870506`](https://github.com/canxin121/procwarden/actions/runs/23849870506)，`master` 分支，标题 "Clarify Linux and macOS matrix caveats"
- [`23845006394`](https://github.com/canxin121/procwarden/actions/runs/23845006394)，`master` 分支，标题 "fix: align macos noaccess matrix with CI"

这些 run 说明了什么：

- `ubuntu-latest` 当前能跑通 Linux 的 CI 套件，但 hosted-runner probe 明确报告了 `linux.overlay_subtractive=unavailable`。
- 换句话说，Linux 里那个“`ReadWrite` + 生效的 `read_only` overlay”行，在 GitHub Hosted Ubuntu 上当前会以 `SandboxError::Unavailable` fail-closed；只有不依赖 overlay 的 Linux 形状能在这个 runner 上稳定通过。
- 这仍然符合文档 contract：这些 Linux 行在具备能力的宿主上仍然受支持，但不能被改标成普遍“可用”，因为它们本来就依赖 user/mount namespace 支持。
- `macos-latest` 当前能跑通保留下来的 macOS 公共矩阵，也就是 `ReadOnly` / `ReadWrite` 默认策略加路径覆盖的这些行。
- 2026 年 4 月 1 日针对 `NoAccess` 的历史调查 run 在 `macos-latest` 上失败过，例如 [`23848403152`](https://github.com/canxin121/procwarden/actions/runs/23848403152)（分支 `macos-noaccess-investigation`）。这也是为什么该模式已经从公开 API 中移除，并且不再出现在当前矩阵里。
- 现在 CI 还会额外跑一个 hosted-runner probe（`cargo run --quiet --bin ci_matrix_probe`），并把结果写入 GitHub Actions step summary。
- 在 `windows-latest` 上，这个 probe 现在会记录当前公开 `deny` / `read_only` / `read_write` 路径模型下的 Windows 文件系统支持矩阵，以及按策略形状分组的 wall-clock timing 样本。这样后续 run 不只知道“能不能跑”，还能判断 hosted runner 上的性能是否已经慢到不适合实际使用。

### 历史 Windows hosted runner 结果（`windows-latest`，2026-04-02）

run [`23893105166`](https://github.com/canxin121/procwarden/actions/runs/23893105166)
记录了一个有参考价值的 hosted-runner 历史快照，但它发生在这个分支把
`network_access=true` 修到可运行之前。它对 `windows-latest` 的 WFP 可用性仍有参考价值，
但不能再直接当成当前 Windows contract：

| 探针维度 | 实际结果 | 解释 |
|---|---|---|
| 宿主进程是否已提权 | `windows.host_process_elevated=true` | runner 进程本身已经是管理员 |
| 当时的 `network_access=true` | `invalid_request` | 这是 2026-04-02 那个分支状态下的历史前置拒绝，不再代表当前分支行为 |
| 任意探测到的 `network_access=false` 策略形状 | `windows_error(FwpmEngineOpen0 failed: 50 ...)` | 宿主不支持 WFP 动态会话初始化，进程在真正启动前就失败 |
| enforcement 跟进探测 | `wfp_unavailable` | 没有发生降级；后端是 fail-closed，而不是带着更弱网络隔离继续跑 |
| 分策略 timing 样本 | `windows.timing.skipped_reason=wfp_unavailable` | 这里不存在“很慢但能用”的结论；这个 runner 对 Windows 后端来说实际上不可用 |

对这个历史 hosted-runner 快照，更准确的结论是：

- 应把它视为 `windows-latest` 的历史观测，而不是当前 Windows 后端 contract。
- 当时的限制因素是宿主的 WFP 可用性，不是本 crate 的路径权限矩阵实现。
- 由于该 runner 进程本身已经是管理员，因此那次运行里“先普通进程启动，再自动提权到防火墙 helper”这条回退路径不会被触发。
- 整个 `windows-latest` job 大约耗时 58 秒，但 hosted-runner diagnostics 这一步只耗时约 1 秒；没有证据表明策略执行是“很慢”，因为请求在 WFP 设置阶段就已经终止了。
- 如果要声明当前分支在 `windows-latest` 上的最新结果，仍然需要重新跑一轮新的 hosted-runner probe。

---

## 三平台对比

| 维度 | Linux | Windows | macOS |
|---|---|---|---|
| 主后端机制 | 进程内配置 Landlock + seccomp | AppContainer + ACL 覆盖 + WFP 过滤 | 系统 `sandbox-exec` + Seatbelt profile |
| 文件系统约束位置 | 内核（Landlock） | OS 隔离 + ACL 调整 | Seatbelt 策略（sandbox-exec） |
| 网络约束位置 | seccomp syscall 过滤 | WFP ALE 层过滤 | Seatbelt `network*` 规则过滤 |
| 本 crate 的路径预校验 | manager 先 canonicalize 已存在的 request/policy 路径，再交给内核执行 namespace/overlay 约束 | manager 先 canonicalize，再由 Windows 以大小写不敏感方式二次清洗 ACL 输入 | manager 先 canonicalize 已存在的 request/policy 路径，再生成 SBPL |
| 超时处理 | 进程组感知的超时 kill | 显式超时终止 + job 约束 | 复用共享超时执行器 |
| 后端依赖缺失行为 | N/A | 当 WFP 在宿主上不可用且 helper 回退不适用时 fail-closed | `sandbox-exec` 缺失时 fail-closed |

---

## 测试与 CI 状态

- GitHub Actions 在 `ubuntu-latest`、`macos-latest`、`windows-latest` 运行。
- CI 包含：
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --test policy_combination_matrix -- --nocapture`
  - `cargo test --workspace --all-targets -- --nocapture`
  - `cargo run --quiet --bin ci_matrix_probe`
  - 上传每个 hosted runner 的 `ci-matrix-probe-${os}` artifact

当前覆盖重点：

- `tests/policy_combination_matrix.rs`：覆盖 `default_access` / `path_permissions` 组合矩阵，包括 Linux 中由 overlay 支撑的 `ReadWrite + read_only`、Linux/macOS 的 `deny` 形状，以及 Linux 对“overlay target 必须已存在”的 fail-closed 覆盖。
- `tests/policy_access_consistency.rs`：覆盖主要默认策略模式的运行时行为，包括显式 `deny` 路径的 enforcement，以及一个 `ReadOnly + read_write + deny` 下“deny 祖先继续压过写 carve-out 子树”的 nested case。
- `tests/network_access_control.rs`：覆盖 Windows 真机下 `network_access == true` 时的私网 TCP 放行、对通用 host listener 的当前 loopback 限制，以及 `network_access == false` 时对 loopback / 私网 TCP 的阻断。
- `src/platform/macos.rs` 单元测试：覆盖 `ReadWrite` 与 `ReadOnly` 两类 SBPL 生成顺序。

---

## 备注

- `procwarden` 仅提供沙盒执行路径。
- 不支持的目标平台在编译阶段失败。
- 三个平台共享统一 policy 形状，但底层 enforcement 机制并不完全相同。
