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

Linux 文件系统限制在 `pre_exec` 中通过 Landlock 设置：

- `default_access == ReadWrite`
  - 若不存在 `ReadOnly` / `NoAccess` 覆盖路径，则跳过 Landlock 文件系统限制配置。
  - 若存在 `ReadOnly` / `NoAccess` 覆盖路径，Linux 会返回 `SandboxError::InvalidRequest`（fail-closed），因为 Landlock 无法在“默认全可写”上安全表达减法覆盖规则。
- `default_access == ReadOnly` 且存在任意 `NoAccess`（`deny`）覆盖路径：
  - Linux 会返回 `SandboxError::InvalidRequest`（fail-closed）。
  - 原因：Landlock 是 allowlist 模型，无法从“全局可读”中减去某个被拒绝子树。
- `default_access == NoAccess` 但存在重叠的 `allow` 与 `deny` 路径范围：
  - Linux 会返回 `SandboxError::InvalidRequest`（fail-closed）。
  - 非重叠 `deny` 仍可接受（在默认拒绝下本质是冗余规则）。
- 其他情况：
  - 创建并安装 Landlock ruleset。
  - 按策略推导出的读/写根路径授予权限。

后端内部映射关系：

- `default_read_access = (default_access != NoAccess)`
- `default_write_access = (default_access == ReadWrite)`
- `readable_roots = path_permissions 中 access ∈ {ReadOnly, ReadWrite}`
- `writable_roots = path_permissions 中 access == ReadWrite`

规则细节：

- 若 `default_read_access` 为 true，则对 `"/"` 授予读权限。
- 否则仅对 `readable_roots` 授予读权限。
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
- `deny` 路径先生成显式的 `file-read*` 与 `file-write*` deny 规则
- 再映射默认权限：
  - `ReadWrite`：默认可写，但受显式 read-only/deny 路径规则约束
  - `ReadOnly`：先加入可写 carve-out，再追加 `(deny file-write*)`
  - `NoAccess`：先加入可读/可写 carve-out，再追加 `(deny file-read*)` 与 `(deny file-write*)`

每条路径规则会同时输出 `(literal "...")` 与 `(subpath "...")` 条件。

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

- 全平台共享矩阵：`tests/cross_platform_unified_matrix.rs` 在所有 OS 目标运行同一套策略校验（CLI + Python + Node，深度 1/2/3 子进程链路、父/子路径作用域、loopback 联网允许/阻断）。
- Linux：大量真实运行集成矩阵（策略组合、父/子/孙进程链路、联网开关、压力、超时、路径边界）。
- Windows：围绕 AppContainer 策略/路径安全的覆盖，并在“基线可连 loopback”条件下校验禁网阻断。
- macOS：除 SBPL profile 编译与 fail-closed 外，在运行条件满足时增加 loopback 禁网集成校验。

---

## 备注

- `procwarden` 仅提供沙盒执行路径。
- 不支持的目标平台在编译阶段失败。
- 三个平台共享统一 policy 形状，但底层 enforcement 机制并不完全相同。
