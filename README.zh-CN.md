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
- `global_access: SandboxAccess`
  - `NoAccess | ReadOnly | ReadWrite`
- `network_access: bool`

`SandboxCommandRequest` 包含：

- `command: Vec<String>`
- `cwd: PathBuf`
- `env: HashMap<String, String>`
- `timeout_ms: Option<u64>`

在进入平台后端前，manager 会先做：

1. 请求校验（`command` 非空、可执行 token 非空、`cwd` 必须存在且为目录）。
2. 环境变量净化（移除高风险加载/注入变量，如 `LD_PRELOAD`、`LD_*`、`DYLD_*`、`BASH_ENV`、`ENV`、`BASH_FUNC_*`）。

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

---

## Linux 后端（Landlock + seccomp）

实现入口：`src/platform/linux.rs`

### 文件系统沙盒实现

Linux 文件系统限制在 `pre_exec` 中通过 Landlock 设置：

- `global_access == ReadWrite`
  - 跳过 Landlock 文件系统限制配置。
- 其他情况：
  - 创建并安装 Landlock ruleset。
  - 按策略推导出的读/写根路径授予权限。

后端内部映射关系：

- `full_disk_read_access = (global_access != NoAccess)`
- `full_disk_write_access = (global_access == ReadWrite)`
- `readable_roots = path_permissions 中 access ∈ {ReadOnly, ReadWrite}`
- `writable_roots = path_permissions 中 access == ReadWrite`

规则细节：

- 若 `full_disk_read_access` 为 true，则对 `"/"` 授予读权限。
- 否则仅对 `readable_roots` 授予读权限。
- 始终对 `/dev/null` 授予读写权限（保证常见进程 I/O 兼容）。
- 对 `writable_roots` 授予读写权限。

### 网络沙盒实现

当 `network_access == false` 时，在 `pre_exec` 安装 seccomp 过滤器：

- 拒绝核心网络 syscall（`connect`、`accept`、`bind`、`listen`、`send*`、`recv*`、`setsockopt` 等）。
- 拒绝 `ptrace`。
- `socket` / `socketpair` 仅允许 `AF_UNIX`。

### Linux 后端说明

- 该后端直接依赖内核级约束（Landlock + seccomp）。
- 如果 Landlock 返回 `NotEnforced`，则执行失败。

---

## Windows 后端（AppContainer + ACL + 环境硬化）

实现入口：`src/platform/windows/mod.rs`

### 高层执行流程

1. 规范化部分环境默认值（如 `/dev/null` 风格值映射到 `NUL`、设置非交互 pager 默认值）。
2. 若 `network_access == false`，执行网络相关环境硬化。
3. 从 policy 构建 allow/deny 路径计划。
4. 对 allow/deny 路径做校验和清洗。
5. 创建 AppContainer 上下文（SID/profile）。
6. 对 AppContainer SID 应用 ACL 访问计划。
7. 以 AppContainer 安全能力启动目标进程。
8. 捕获输出并处理超时。

### 路径安全校验实现

Windows allow/deny 路径通过 `ensure_safe_allow_path` 校验：

- 路径必须存在。
- 拒绝危险命名空间（`\\.\`、`\??\`、`\\?\GLOBALROOT...`）。
- 通过 Win32 handle API 解析最终路径。
- 拒绝 reparse point。
- 拒绝 symlink。
- 进行 canonicalize 与大小写不敏感去重（ASCII case-insensitive）。

路径安全默认行为（固定）：

- allowlist 路径始终拒绝 reparse point。
- allowlist 路径允许 UNC。

### ACL 计划实现

policy 转换为 ACL 计划：

- 若 `global_access == ReadWrite`：本层不额外附加 allow/deny ACL 覆盖。
- 其他情况：
  - `allow_paths = readable_paths`（ReadOnly + ReadWrite）
  - `deny_paths = denied_paths`（NoAccess）

随后：

- 对 `deny_paths` 增加 deny-write ACE。
- 对 `allow_paths` 增加 allow ACE。
- 用 rollback 对象跟踪并在结束时撤销。

### 进程创建与约束

通过 AppContainer 相关属性创建进程（`CreateProcessW` 属性列表）：

- `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`（AppContainer SID）
- `PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY`（限制子进程策略）
- `PROC_THREAD_ATTRIBUTE_JOB_LIST`（job 对象 + kill-on-close）

### Windows 的网络行为

当 `network_access == false` 时，当前 crate 在 Windows 使用环境层硬化：

- 强制代理变量指向 blackhole。
- 强制常见工具链离线配置（pip/npm/cargo/git 相关）。
- 在临时 deny-bin 目录生成失败 stub（`ssh`、`scp`、`sftp`、`ftp`、`telnet`、`nc`、`ncat`），并前置到 `PATH`。
- 调整 `PATHEXT` 顺序，优先命中 stub 脚本。

当前 crate 在 Windows 未额外安装独立 syscall 级网络过滤器。

---

## macOS 后端（外部 virtualization runner）

实现入口：`src/platform/macos.rs`

macOS 后端将底层约束委托给外部 runner 二进制。

### runner 解析

- 默认路径：`/usr/local/bin/procwarden-macos-runner`
- 可通过环境变量覆盖：`PROCWARDEN_MACOS_RUNNER`

如果 runner 不存在，执行会 fail-closed，返回 `SandboxError::Unavailable`。

### 策略序列化到 runner 参数

crate 会把 policy 转为命令行参数：

- 网络：`--allow-network` / `--deny-network`
- 全局权限：`--global-rw` / `--global-ro` / `--global-none`
- 路径范围：
  - `--ro-path <path>`
  - `--rw-path <path>`
  - `--deny-path <path>`
- 执行参数：
  - `--timeout-ms <n>`（若设置）
  - `--cwd <path>`
  - `--` 后接目标命令

因此 macOS 上的低层沙盒强度取决于 runner 的实现细节。

---

## 三平台对比

| 维度 | Linux | Windows | macOS |
|---|---|---|---|
| 主后端机制 | 进程内配置 Landlock + seccomp | AppContainer + ACL 覆盖 + 环境硬化 | 外部 virtualization runner |
| 文件系统约束位置 | 内核（Landlock） | OS 隔离 + ACL 调整 | 由 runner 决定 |
| 网络约束位置 | seccomp syscall 过滤 | 环境层硬化（以及 AppContainer 基线隔离） | 由 runner 决定 |
| 本 crate 的路径预校验 | 较少，更多由内核策略生效 | 先严格校验再应用 ACL | 路径作为参数传给 runner |
| 超时处理 | 进程组感知的超时 kill | 显式超时终止 + job 约束 | 复用共享超时执行器 |
| 后端依赖缺失行为 | N/A | N/A | runner 缺失时 fail-closed |

---

## 测试与 CI 状态

- GitHub Actions 在 `ubuntu-latest`、`macos-latest`、`windows-latest` 运行。
- CI 包含：
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace --all-targets -- --nocapture`

当前覆盖重点：

- Linux：大量真实运行集成矩阵（策略组合、父/子/孙进程链路、联网开关、压力、超时、路径边界）。
- Windows：围绕 AppContainer 策略与路径安全行为的编译 + 集成覆盖。
- macOS：crate 内覆盖 runner 协议与 fail-closed 行为；更深层沙盒能力取决于 runner。

---

## 备注

- `procwarden` 仅提供沙盒执行路径。
- 不支持的目标平台在编译阶段失败。
- 三个平台共享统一 policy 形状，但底层 enforcement 机制并不完全相同。
