# procwarden（中文文档）

- English README: [README.md](./README.md)

`procwarden` 是一个跨平台 Rust 进程沙盒 crate，用统一的文件系统和网络策略在 Linux、macOS 和 Windows 上执行命令。

公开入口：

- `SandboxManager::execute(&SandboxCommandRequest, &SandboxPolicy)`

## 快速上手

使用 `procwarden` 可以按 5 个决定来理解：

1. 显式构造环境变量。
2. 先选默认文件系统模式。
3. 再选网络模式。
4. 最后只加真正需要的路径覆盖规则。
5. 调用 `SandboxManager::execute` 运行。

实用默认值：

- `SandboxDefaultAccess::ReadOnly`：默认最安全，适合“只放开少量可写路径”。
- `SandboxDefaultAccess::ReadWrite`：适合“默认按普通进程运行，只收紧少量路径”。

路径覆盖规则的含义：

- `SandboxPathPermission::read_write(path)`：这个路径可写
- `SandboxPathPermission::read_only(path)`：这个路径可读但不可写
- `SandboxPathPermission::deny(path)`：这个路径不可读也不可写

网络模式的含义：

- `SandboxNetworkMode::Disabled`：阻断 IP 网络
- `SandboxNetworkMode::OutboundOnly`：允许出站 IP 流量，阻断入站 IP 流量
- `SandboxNetworkMode::Bidirectional`：不再由 procwarden 施加网络方向限制

示例：

```rust
use std::collections::HashMap;

use procwarden::{
    SandboxCommandRequest, SandboxDefaultAccess, SandboxManager, SandboxNetworkMode,
    SandboxPathPermission, SandboxPolicy,
};

let manager = SandboxManager::new();

let mut env = HashMap::new();
if let Ok(path) = std::env::var("PATH") {
    env.insert("PATH".to_string(), path);
}

let policy = SandboxPolicy {
    default_access: SandboxDefaultAccess::ReadOnly,
    network_mode: SandboxNetworkMode::Disabled,
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

实用规则：

- `procwarden` 不会自动继承父进程环境变量。
- 如果命令依赖查找，请至少传入 `PATH`。
- 如果程序需要可写临时目录，请先创建目录，再把它加入 `read_write`。
- 如果某条规则和默认模式等价，manager 会把这条冗余规则归一化掉。
- `cwd` 和所有 `path_permissions` 路径都必须已经存在。
- 路径会在后端分发前先 canonicalize。
- `deny` 祖先路径下面，不能再用子路径重新放开权限。
- `timeout_ms` 会杀掉超时进程，并把超时退出码统一为 `124`。
- `SandboxNetworkMode::Disabled` 表示“阻断 IP 网络”，不是“只阻断公网”。

## 支持矩阵

下面只保留会改变实际行为的组合。

共享说明：

- `ReadOnly + read_only` 是冗余的，会被归一化掉。
- `ReadWrite + read_write` 是冗余的，会被归一化掉。

### 文件系统

| 平台 | `ReadOnly` | `ReadOnly + read_write` | `ReadOnly + deny` | `ReadWrite` | `ReadWrite + read_only` | `ReadWrite + deny` | 条件 |
|---|---|---|---|---|---|---|---|
| Linux | 可用 | 可用 | 有条件可用 | 可用 | 有条件可用 | 有条件可用 | 2026-04-04 已在本地 `Linux 6.17.0-19-generic` `x86_64` 重新验证。任何真正的减法规则（`deny`，或者 `ReadWrite` 下的 `read_only`）都依赖 user/mount namespace 支持（`CLONE_NEWUSER` + `CLONE_NEWNS`，或等价 `CAP_SYS_ADMIN`），而且目标路径必须已经存在。能力不足时会 fail-closed，返回 `SandboxError::Unavailable`。 |
| macOS | 有条件可用 | 有条件可用 | 有条件可用 | 有条件可用 | 有条件可用 | 有条件可用 | 需要 `/usr/bin/sandbox-exec`；如果不用默认路径，则 `PROCWARDEN_MACOS_SANDBOX_EXEC` 必须指向有效替代路径。 |
| Windows | 可用 | 可用 | 可用 | 可用 | 可用 | 可用 | 通过 AppContainer 加 ACL 变更实现。请在真实 Windows 主机上验证，不要只把 `windows-latest` 当成结论。既有路径会先 canonicalize，再在 ACL 应用前做一次清洗。 |

### 网络

| 平台 | `Disabled` | `OutboundOnly` | `Bidirectional` | 条件 |
|---|---|---|---|---|
| Linux | 可用 | 可用 | 可用 | 2026-04-04 已在本地重新验证。`Disabled` 会阻断 loopback、内网和外网 IP 网络；`OutboundOnly` 允许出站连接，同时阻断 listener 建立。受限模式依赖 `x86_64` 或 `aarch64` 上的 seccomp 支持；不满足时会 fail-closed。 |
| macOS | 有条件可用 | 有条件可用 | 有条件可用 | 需要 `/usr/bin/sandbox-exec`；如果不用默认路径，则 `PROCWARDEN_MACOS_SANDBOX_EXEC` 必须指向有效替代路径。`Disabled` 会映射为 `(deny network*)`；`OutboundOnly` 会映射为 `(deny network-bind)` 加 `(deny network-inbound)`。 |
| Windows | 有条件可用 | 有条件可用 | 有条件可用 | 通过 AppContainer 和网络过滤实现。`Disabled` 在 WFP 或 elevated helper 路径不可用时会 fail-closed。`OutboundOnly` 和 `Bidirectional` 依赖 elevated firewall helper。当前主要验证的是私网出站路径；loopback 在当前后端上仍然依赖宿主环境，所以 Windows 的网络控制要视为“有条件”，尤其是 loopback 和 listener 行为。 |

## 在你自己的机器上复测

```bash
cargo test --test policy_combination_matrix -- --nocapture
cargo test --test network_mode_control -- --nocapture
cargo test --workspace --all-targets -- --nocapture
cargo run --quiet --bin ci_matrix_probe
```

Windows 还建议额外执行：

```bash
cargo test --test windows_network_mode_control -- --nocapture
```
