# procwarden（中文文档）

- English README: [README.md](./README.md)

`procwarden` 是一个跨平台 Rust 进程沙盒 crate，用统一的策略模型在 Linux、macOS 和 Windows 上执行命令。

公开入口只有一个：

- `SandboxManager::execute(&SandboxCommandRequest, &SandboxPolicy)`

## 5 分钟上手

使用 `procwarden` 可以按 4 步理解：

1. 先选默认文件系统模式。
2. 再加显式路径覆盖规则。
3. 决定是否允许网络。
4. 调用 `SandboxManager::execute` 运行。

实用经验：

- 想要“默认更安全，只放开少数可写目录”，优先用 `SandboxDefaultAccess::ReadOnly`
- 想要“默认正常可写，只收紧少数路径”，用 `SandboxDefaultAccess::ReadWrite`

路径覆盖规则的含义：

- `SandboxPathPermission::read_write(path)`：这个路径可写
- `SandboxPathPermission::read_only(path)`：这个路径可读但不可写
- `SandboxPathPermission::deny(path)`：这个路径不可读也不可写

示例：

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

几个实用提醒：

- `env` 是显式传入的，`procwarden` 不会自动继承父进程环境变量
- 如果命令依赖 PATH 查找，请至少把 `PATH` 传进去
- 如果程序需要可写临时目录，请先创建目录，再把它加到 `read_write`

## 使用前必须知道的规则

- `cwd` 必须已经存在，而且必须是目录
- 每个 `path_permissions` 路径都必须已经存在
- 所有路径会在分发到后端前先做 canonicalize
- 冗余规则会在执行前自动归一化
- `deny` 祖先路径下面，不能再用子路径重新放开权限
- `timeout_ms` 会杀掉超时进程，并把超时退出码统一为 `124`
- `network_access = false` 表示“阻断 IP 网络”，不是“只阻断公网”

## 文件系统实际可用矩阵

下面这些表只讨论文件系统策略：

- `default_access`：未命中 `path_permissions` 时的默认行为
- `path_permissions`：显式路径覆盖规则

状态说明：

- `可用`：已经验证，预期可正常工作
- `可用但冗余`：后端接受，但 manager 归一化后，这条额外规则不会改变实际行为

### Linux

2026-04-04 在本地 Linux 机器上重新验证，环境为：

- `Linux 6.17.0-19-generic`
- 非 root 用户
- `kernel.unprivileged_userns_clone=1`
- `user.max_user_namespaces=479289`

Linux 的关键点在于：有些行本机可用，但要在别的 Linux 上复现同样结果，仍然要满足明确条件，所以条件逐行列出。

| `default_access` | `path_permissions` 形状 | 本机 Linux 实际状态 | 想在别的 Linux 上得到同样结果，需要满足的条件 |
|---|---|---|---|
| `ReadWrite` | 无 | 可用 | 无 |
| `ReadWrite` | 仅 `read_write` | 可用但冗余 | 无 |
| `ReadWrite` | 仅 `read_only` | 可用 | 需要 user/mount namespace 支持（`CLONE_NEWUSER` + `CLONE_NEWNS`，或等价 `CAP_SYS_ADMIN`） |
| `ReadWrite` | 仅 `deny` | 可用 | 需要 user/mount namespace 支持（`CLONE_NEWUSER` + `CLONE_NEWNS`，或等价 `CAP_SYS_ADMIN`） |
| `ReadWrite` | `read_only + read_write` | 可用但冗余 | 与 `ReadWrite + read_only` 相同；`read_write` 会被归一化掉 |
| `ReadWrite` | `read_only + deny` | 可用 | 需要 user/mount namespace 支持（`CLONE_NEWUSER` + `CLONE_NEWNS`，或等价 `CAP_SYS_ADMIN`） |
| `ReadOnly` | 无 | 可用 | 无 |
| `ReadOnly` | 仅 `read_only` | 可用但冗余 | 无 |
| `ReadOnly` | 仅 `read_write` | 可用 | 无 |
| `ReadOnly` | 仅 `deny` | 可用 | 需要 user/mount namespace 支持（`CLONE_NEWUSER` + `CLONE_NEWNS`，或等价 `CAP_SYS_ADMIN`） |
| `ReadOnly` | `read_only + read_write` | 可用 | 无。`read_only` 会被归一化掉 |
| `ReadOnly` | `read_write + deny` | 可用 | 需要 user/mount namespace 支持（`CLONE_NEWUSER` + `CLONE_NEWNS`，或等价 `CAP_SYS_ADMIN`） |

Linux 额外条件：

- 任何依赖减法 overlay 的行，还要求目标路径本身已经存在
- 如果 namespace 能力不够，会 fail-closed，返回 `SandboxError::Unavailable`

### macOS

2026-04-04 通过 GitHub Actions `macos-latest` 重新验证，run 为 `23970597090`。

macOS 共享条件：

- `/usr/bin/sandbox-exec` 必须存在；如果不用默认路径，则 `PROCWARDEN_MACOS_SANDBOX_EXEC` 必须指向有效替代路径

| `default_access` | `path_permissions` 形状 | 当前 macOS runner 上的实际状态 |
|---|---|---|
| `ReadWrite` | 无 | 可用 |
| `ReadWrite` | 仅 `read_write` | 可用但冗余 |
| `ReadWrite` | 仅 `read_only` | 可用 |
| `ReadWrite` | 仅 `deny` | 可用 |
| `ReadWrite` | `read_only + read_write` | 可用 |
| `ReadWrite` | `read_only + deny` | 可用 |
| `ReadOnly` | 无 | 可用 |
| `ReadOnly` | 仅 `read_only` | 可用但冗余 |
| `ReadOnly` | 仅 `read_write` | 可用 |
| `ReadOnly` | 仅 `deny` | 可用 |
| `ReadOnly` | `read_only + read_write` | 可用 |
| `ReadOnly` | `read_write + deny` | 可用 |

macOS 额外条件：

- 既有 policy 路径会先 canonicalize，再生成 SBPL 规则
- `/var/...` 和 `/private/var/...` 这类既有别名路径，会在入口处先归一化

### Windows

最新文件系统矩阵基于 2026-04-03 的真实 Windows 机器验证。

这个表只讨论文件系统。Windows 上 `network_access = false` 是另外一个更依赖宿主环境的问题，单独放到下面的网络说明里。

| `default_access` | `path_permissions` 形状 | 最新已验证 Windows 真机上的实际状态 |
|---|---|---|
| `ReadWrite` | 无 | 可用 |
| `ReadWrite` | 仅 `read_write` | 可用但冗余 |
| `ReadWrite` | 仅 `read_only` | 可用 |
| `ReadWrite` | 仅 `deny` | 可用 |
| `ReadWrite` | `read_only + read_write` | 可用 |
| `ReadWrite` | `read_only + deny` | 可用 |
| `ReadOnly` | 无 | 可用 |
| `ReadOnly` | 仅 `read_only` | 可用但冗余 |
| `ReadOnly` | 仅 `read_write` | 可用 |
| `ReadOnly` | 仅 `deny` | 可用 |
| `ReadOnly` | `read_only + read_write` | 可用 |
| `ReadOnly` | `read_write + deny` | 可用 |

Windows 额外条件：

- 上面的结果来自真实 Windows 机器，不是 GitHub-hosted runner
- 既有路径会先在 manager 层 canonicalize，再在 ACL 应用前做一次 Windows 风格清洗

## 网络说明

- Linux：`network_access = false` 通过 seccomp 阻断 IP 网络，包括 loopback、内网和外网
- macOS：`network_access = false` 会映射为 Seatbelt 的 `(deny network*)`
- Windows：`network_access = false` 是最依赖宿主环境的一条。最新已验证的真实 Windows 机器上它是可用的，但如果宿主没有可用的 WFP 路径或 helper 回退路径，执行会 fail-closed，而不是静默放行网络

## 在你自己的机器上复测

如果你要在自己的宿主上重跑当前矩阵，直接执行：

```bash
cargo test --test policy_combination_matrix -- --nocapture
cargo test --workspace --all-targets -- --nocapture
cargo run --quiet --bin ci_matrix_probe
```
