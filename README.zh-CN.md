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
  - 每一项都包含 `path` 和访问级别 `access`
  - 构造函数：
    - `SandboxPathPermission::read_only(path)`
    - `SandboxPathPermission::read_write(path)`
    - `SandboxPathPermission::deny(path)`
- `default_access: SandboxAccess`
  - `NoAccess | ReadOnly | ReadWrite`
  - 表示未命中 `path_permissions` 时的默认访问策略
  - 具体路径规则（`read_only` / `read_write` / `deny`）会叠加覆盖默认策略
  - 若后端无法安全表达某些“减法覆盖”组合，会 fail-closed 返回 `SandboxError::InvalidRequest`，不会静默弱化策略
- `network_access: bool`

`SandboxCommandRequest` 包含：

- `command: Vec<String>`
- `cwd: PathBuf`
- `env: HashMap<String, String>`
- `timeout_ms: Option<u64>`

在进入平台后端前，manager 会先做：

1. 请求校验（`command` 非空、可执行 token 非空、`cwd` 必须存在且为目录）。
2. 策略 allow 路径校验（`ReadOnly` / `ReadWrite` 路径必须非空且当前存在，否则返回 `SandboxError::InvalidRequest`）。
3. 环境变量净化（移除高风险加载/注入变量，如 `LD_PRELOAD`、`LD_*`、`DYLD_*`、`BASH_ENV`、`ENV`、`BASH_FUNC_*`）。

---

## 快速使用示例

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

Linux 文件系统限制在 `pre_exec` 中设置，但当前后端实际上分成两条执行路径：

- `default_access == ReadWrite`
  - 若不存在 `ReadOnly` / `NoAccess` 覆盖路径，则保持文件系统默认可访问。
  - 若存在 `ReadOnly` 或 `NoAccess` 覆盖路径，则通过私有 mount namespace 中的 bind-mount overlay 实现覆盖。
  - 所有 overlay 目标路径都必须已经存在，否则返回 `SandboxError::InvalidRequest`。
  - 若宿主环境无法创建所需的 user/mount namespace，则返回 `SandboxError::Unavailable`，不会静默弱化策略。
- `default_access == ReadOnly` 且不存在 `NoAccess`（`deny`）覆盖路径：
  - 安装 Landlock ruleset。
  - 提供全局读权限，并通过 `read_write` 路径提供显式写 carve-out。
- `default_access == ReadOnly` 且存在任意 `NoAccess`（`deny`）覆盖路径：
  - 先安装 deny bind-mount overlay，再安装 Landlock ruleset，用于提供全局只读和显式写 carve-out。
  - 所有被 deny 的 overlay 目标路径都必须已经存在。
  - 若宿主环境无法创建所需的 user/mount namespace，则返回 `SandboxError::Unavailable`。
- `default_access == NoAccess`
  - 安装 Landlock allowlist，只允许显式声明的可读/可写根路径。
  - 非重叠 `deny` 仍可接受，但通常是冗余的，因为默认本来就是拒绝。
  - 若 `allow` 与 `deny` 路径重叠，则会在 Landlock 生效前，先对这些重叠的 deny 路径安装 deny bind-mount overlay。
  - 所有需要 overlay 的重叠 deny 目标路径都必须已经存在。
  - 若需要这些重叠 deny overlay，但宿主环境无法创建所需的 user/mount namespace，则返回 `SandboxError::Unavailable`。
  - allowlist 除了业务目标路径外，还必须覆盖启动目标命令及其 loader/interpreter 所需的运行时可读根路径。

后端内部映射关系：

- `default_read_access = (default_access != NoAccess)`
- `default_write_access = (default_access == ReadWrite)`
- `readable_roots = path_permissions 中 access ∈ {ReadOnly, ReadWrite}`
- `writable_roots = path_permissions 中 access == ReadWrite`

Landlock 路径下的规则细节：

- 若 `default_read_access` 为 true，则对 `"/"` 授予读权限。
- 否则仅对 `readable_roots` 授予读权限。
- 始终对 `/dev/null` 授予读写权限（保证常见进程 I/O 兼容）。
- 对 `writable_roots` 授予读写权限。

在实践中，`default_access == NoAccess` 往往还需要把 `/bin`、`/usr/bin`、`/lib`、`/lib64`、`/usr/lib`、`/usr/lib64`、`/usr/libexec` 等运行时根路径加入 allowlist，尤其是当命令通过 `/bin/sh`、解释器或动态链接可执行文件启动时。

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
2. 从 policy 构建 allow/deny 路径计划。
3. 对 allow/deny 路径做校验和清洗。
4. 解析可执行文件路径。
5. 创建 AppContainer 上下文（SID/profile）。
6. 当当前进程非管理员时，请求一次 UAC 提权，并启动一个统一提权 helper 管理 ACL + 可选网络阻断生命周期。
7. 若当前已是管理员，则在当前进程内走原生 ACL/WFP 设置路径。
8. 对 AppContainer SID 应用 ACL 访问计划（原生路径或统一提权 helper 路径）。
9. 以 AppContainer 安全能力启动目标进程。
10. 捕获输出并处理超时。

### 路径安全校验实现

Windows allow/deny 路径通过 `ensure_safe_allow_path` 校验：

- 路径必须存在。
- 进行 canonicalize 与大小写不敏感去重（ASCII case-insensitive）。

### ACL 计划实现

policy 按“默认 + 覆盖”转换为 ACL 计划：

- `allow_readonly_paths = read_only_paths`
- `allow_readwrite_paths = read_write_paths`
- `deny_readwrite_paths = denied_paths`（NoAccess）
- 当 `default_access == ReadWrite` 时，`read_only_paths` 还会作为 deny-write 覆盖路径生效

随后：

- 对 `deny_readwrite_paths` 增加 deny read/write/execute ACE。
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

若 WFP 因权限/环境限制失败（`ERROR_ACCESS_DENIED` / `ERROR_NOT_SUPPORTED`），后端会默认自动发起管理员提权（UAC），并通过提权 helper 安装临时防火墙阻断规则。

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
  - `ReadWrite`：对显式 `read_only` 路径生成 `file-write*` deny；对显式 `deny` 路径生成 `file-read*` 与 `file-write*` deny。
  - `ReadOnly`：先发出全局 `(deny file-write*)`，再加入显式 `read_write` carve-out allow，最后再追加显式 `deny` 路径规则，保证 deny 仍然能覆盖 carve-out。
  - `NoAccess`：先发出全局 `(deny file-read*)` 与 `(deny file-write*)`，再加入显式读/写 allowlist carve-out，最后再追加显式 `deny` 路径规则，保证 deny 仍然能覆盖重叠的 allowlist。

每条路径规则会同时输出 `(literal "...")` 与 `(subpath "...")` 条件。

在实践中，macOS 上的路径规则应先做 canonicalize，再构造 `SandboxPathPermission`。这可以避免 `/var/...` 与 `/private/var/...` 之类别名路径不一致，导致规则看起来正确但 Seatbelt 实际匹配不到真实路径。

---

## Linux/macOS 实际可用矩阵

下面两张表把两个策略维度拆开写：

- `default_access`：未命中 `path_permissions` 时的默认策略
- `path_permissions`：显式路径覆盖规则（`read_only`、`read_write`、`deny`）
- 命令启动所需的运行时前提与矩阵本身分开考虑：在 `NoAccess` 下，普通命令通常还需要额外放行可执行文件、loader/解释器以及可用工作目录对应的运行时根路径。

其中“Accepted”表示后端接受该请求形状；“可用”表示当前可以作为稳定文档 contract 依赖；“有条件可用”表示还依赖额外的宿主/运行时前提；“依赖宿主能力”表示策略形状本身受支持，但 Linux 宿主还必须具备所需的 mount-namespace 能力；“有条件可用 + 依赖宿主能力”表示这两类前提都同时存在。

### Linux

| `default_access` | `path_permissions` 形状 | 后端结果 | 实际状态 | 说明 |
|---|---|---|---|---|
| `ReadWrite` | 无 | Accepted | 可用 | 全局可读写模式 |
| `ReadWrite` | 仅 `read_write` | Accepted | 可用但冗余 | 默认已全局可写，额外 `read_write` 不增加权限 |
| `ReadWrite` | 仅 `read_only` | Accepted | 依赖宿主能力 | 通过 mount-namespace overlay 实现；目标路径必须已存在 |
| `ReadWrite` | 仅 `deny` | Accepted | 依赖宿主能力 | 同上 |
| `ReadWrite` | `read_only + deny` | Accepted | 依赖宿主能力 | 同上 |
| `ReadOnly` | 无 | Accepted | 可用 | 全局只读模式 |
| `ReadOnly` | 仅 `read_only` | Accepted | 可用但冗余 | 默认已允许读、拒绝写 |
| `ReadOnly` | 仅 `read_write` | Accepted | 可用 | 显式写 carve-out |
| `ReadOnly` | 仅 `deny` | Accepted | 依赖宿主能力 | deny 路径通过 overlay 实现，写权限默认仍由 Landlock 控制 |
| `ReadOnly` | `read_only + read_write` | Accepted | 可用 | `read_only` 冗余，`read_write` 提供写 carve-out |
| `ReadOnly` | 任意包含 `deny` 的形状 | Accepted | 依赖宿主能力 | 包括 `read_write + deny` 和 `read_only + read_write + deny`；deny 路径通过 overlay 实现 |
| `NoAccess` | 无 | Accepted | 对普通命令通常不可用 | 普通动态链接命令仍需要运行时可读根路径才能正常启动 |
| `NoAccess` | 仅 `read_only` | Accepted | 有条件可用 | 显式只读 allowlist；若命令需要运行时根路径也必须一并放行 |
| `NoAccess` | 仅 `read_write` | Accepted | 有条件可用 | 显式读写 allowlist；同样受 bootstrap 前提约束 |
| `NoAccess` | `read_only + read_write` | Accepted | 有条件可用 | 典型 allowlist 模式；同样受 bootstrap 前提约束 |
| `NoAccess` | 在任意非重叠 allowlist 上再加非重叠 `deny` | Accepted | 有条件可用 | 通常是冗余的，因为默认本来就是 deny |
| `NoAccess` | allow 与 `deny` 重叠 | Accepted | 有条件可用 + 依赖宿主能力 | 重叠 deny 路径通过 overlay 实现；既需要运行时根路径，也需要 namespace 能力 |

Linux 额外前提：

- 任何需要 deny/read-only bind overlay 的 Linux 策略形状，在宿主不支持所需 user/mount namespace（`CLONE_NEWUSER`/`CLONE_NEWNS`，或等价 `CAP_SYS_ADMIN`）时，都会返回 `SandboxError::Unavailable`。
- `NoAccess` 在实践中通常还需要显式放行 `/bin`、`/usr/bin`、`/lib`、`/lib64`、`/usr/lib`、`/usr/lib64`、`/usr/libexec` 等运行时根路径。

### macOS

| `default_access` | `path_permissions` 形状 | 后端结果 | 实际状态 | 说明 |
|---|---|---|---|---|
| `ReadWrite` | 无 | Accepted | 可用 | 全局可读写模式 |
| `ReadWrite` | 仅 `read_write` | Accepted | 可用但冗余 | 默认已全局可写，额外 `read_write` 不改变行为 |
| `ReadWrite` | 仅 `read_only` | Accepted | 使用 canonicalized 路径时可用 | 会在这些路径下拒绝写入 |
| `ReadWrite` | 仅 `deny` | Accepted | 使用 canonicalized 路径时可用 | 会在这些路径下拒绝读写 |
| `ReadWrite` | `read_only + deny` | Accepted | 使用 canonicalized 且非重叠路径时可用 | macOS 上常见的减法覆盖场景 |
| `ReadOnly` | 无 | Accepted | 可用 | 全局只读模式 |
| `ReadOnly` | 仅 `read_only` | Accepted | 可用但冗余 | `read_only` 相对全局只读默认策略不增加限制 |
| `ReadOnly` | 仅 `read_write` | Accepted | 使用 canonicalized 路径时可用 | 写 carve-out 依赖 policy 路径与 Seatbelt 看到的 canonical path 一致 |
| `ReadOnly` | 仅 `deny` | Accepted | 使用 canonicalized 路径时可用 | 对选中路径拒绝读写；同样依赖 canonicalize |
| `ReadOnly` | `read_only + read_write` | Accepted | 使用 canonicalized 路径时可用 | `read_only` 冗余，`read_write` 提供写 carve-out |
| `ReadOnly` | `read_write + deny` | Accepted | 使用 canonicalized 且非重叠路径时可用 | “可写 carve-out + deny 路径”；显式 deny 规则会在 carve-out 之后发出 |
| `ReadOnly` | `read_only + read_write + deny` | Accepted | 使用 canonicalized 且非重叠路径时可用 | 同上 |
| `NoAccess` | 无 | Accepted | 对普通命令通常不可用 | 命令本身及其运行时 bootstrap 路径也会被一起拒绝 |
| `NoAccess` | 仅 `read_only` | Accepted | 仅保证形状被接受；必须在目标 macOS 和目标命令上单独验证 | 在 GitHub Actions `macos-15-arm64` 上，即使加入 canonicalized runtime roots，普通 `/bin/sh` / `/bin/cat` 也不能在 `NoAccess` 下稳定 bootstrap |
| `NoAccess` | 仅 `read_write` | Accepted | 仅保证形状被接受；必须在目标 macOS 和目标命令上单独验证 | 当前 macOS CI 观察到相同 bootstrap 问题 |
| `NoAccess` | `read_only + read_write` | Accepted | 仅保证形状被接受；必须在目标 macOS 和目标命令上单独验证 | 后端接受 allowlist 形状，但当前 macOS CI 不能支撑“普通动态命令可运行”的结论 |
| `NoAccess` | 在任意非重叠 allowlist 上再加非重叠 `deny` | Accepted | 仅保证形状被接受；必须在目标 macOS 和目标命令上单独验证 | 通常本就冗余，因为默认就是 deny；当前 macOS CI 仍无法证明普通命令能 bootstrap |
| `NoAccess` | allow 与 `deny` 重叠 | Accepted | 仅保证形状被接受；必须在目标 macOS 上实测 | 后端会把显式 deny 放在 allowlist 之后，但当前 macOS CI 不足以支持“普通命令可运行且重叠优先级稳定”这一结论 |

macOS 额外前提：

- 路径型策略只有在 policy 里的路径与 Seatbelt 实际看到的 canonical path 一致时才可靠，例如 `/private/var/...` 而不是未解析别名的 `/var/...`。
- 当前 CI 观察下，macOS `NoAccess` 比 Linux 更不稳定：在 GitHub Actions `macos-15-arm64` 上，即使加入 canonicalized runtime-root allowlist，普通 `/bin/sh` / `/bin/cat` 仍不能干净 bootstrap。
- 因此 macOS 上的 `NoAccess` 目前只能保守表述为“后端接受这种策略形状”；若要宣称某个组合“可运行”，必须拿目标 macOS 版本和目标命令单独实测。

---

## 三平台对比

| 维度 | Linux | Windows | macOS |
|---|---|---|---|
| 主后端机制 | 进程内配置 Landlock + seccomp | AppContainer + ACL 覆盖 + WFP 过滤 | 系统 `sandbox-exec` + Seatbelt profile |
| 文件系统约束位置 | 内核（Landlock） | OS 隔离 + ACL 调整 | Seatbelt 策略（sandbox-exec） |
| 网络约束位置 | seccomp syscall 过滤 | WFP ALE 层过滤 | Seatbelt `network*` 规则过滤 |
| 本 crate 的路径预校验 | 较少，更多由内核策略生效 | 先严格校验再应用 ACL | 路径作为参数传给 runner |
| 超时处理 | 进程组感知的超时 kill | 显式超时终止 + job 约束 | 复用共享超时执行器 |
| 后端依赖缺失行为 | N/A | N/A | `sandbox-exec` 缺失时 fail-closed |

---

## 测试与 CI 状态

- GitHub Actions 在 `ubuntu-latest`、`macos-latest`、`windows-latest` 运行。
- CI 包含：
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace --all-targets -- --nocapture`

当前覆盖重点：

- `tests/policy_combination_matrix.rs`：覆盖 `default_access` / `path_permissions` 组合矩阵，包括 Linux 中由 overlay 支撑的 `ReadWrite` / `ReadOnly + deny` / `NoAccess + 重叠 deny` 组合、Linux 上可运行的 `NoAccess` allowlist 组合，以及 macOS 上 `NoAccess` 的 shape-acceptance 覆盖。
- `tests/policy_access_consistency.rs`：覆盖主要默认策略模式的运行时行为，包括 Linux `NoAccess` bootstrap 回归测试，以及在 macOS CI 上运行时的 `ReadOnly + read_write + deny` 组合行为。
- `tests/network_access_control.rs`：覆盖 `network_access == false` 时对 loopback 与外部 TCP 的阻断。
- `src/platform/macos.rs` 单元测试：覆盖 `ReadWrite`、`ReadOnly`、`NoAccess` 三类 SBPL 生成顺序。

---

## 备注

- `procwarden` 仅提供沙盒执行路径。
- 不支持的目标平台在编译阶段失败。
- 三个平台共享统一 policy 形状，但底层 enforcement 机制并不完全相同。
