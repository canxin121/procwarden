# procwarden（中文文档）

- English README: [README.md](./README.md)

`procwarden` 是一个跨平台 Rust 进程沙盒 crate，用统一的文件系统和网络策略在 Linux、macOS 和 Windows 上执行命令。

公开入口：

- `SandboxManager::execute(&SandboxCommandRequest, &SandboxPolicy)`

## 快速上手

使用 `procwarden` 可以按 5 个决定来理解：

1. 显式构造环境变量。
2. 先选默认文件系统模式。
3. 再选网络策略。
4. 最后只加真正需要的路径覆盖规则。
5. 调用 `SandboxManager::execute` 运行。

实用默认值：

- `SandboxDefaultAccess::ReadOnly`：默认最安全，适合“只放开少量可写路径”。
- `SandboxDefaultAccess::ReadWrite`：适合“默认按普通进程运行，只收紧少量路径”。

路径覆盖规则的含义：

- `SandboxPathPermission::read_write(path)`：这个路径可写
- `SandboxPathPermission::read_only(path)`：这个路径可读但不可写
- `SandboxPathPermission::deny(path)`：这个路径不可读也不可写

网络策略的快捷选择：

- `SandboxNetworkPolicy::disabled()`：阻断 IP socket 创建，并阻断 `connect` / `bind` / `listen` / `accept`
- `SandboxNetworkPolicy::outbound_only()`：允许出站 IP 连接，阻断 listener 建立
- `SandboxNetworkPolicy::bidirectional()`：允许 coarse helper 形状，不再由 procwarden 施加方向限制

简单示例：

```rust
use std::collections::HashMap;

use procwarden::{
    SandboxCommandRequest, SandboxDefaultAccess, SandboxManager, SandboxNetworkPolicy,
    SandboxPathPermission, SandboxPolicy,
};

let manager = SandboxManager::new();

let mut env = HashMap::new();
if let Ok(path) = std::env::var("PATH") {
    env.insert("PATH".to_string(), path);
}

let policy = SandboxPolicy {
    default_access: SandboxDefaultAccess::ReadOnly,
    network_policy: SandboxNetworkPolicy::disabled(),
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

Linux 自定义网络策略示例：

```rust
use procwarden::SandboxNetworkPolicy;

let linux_outbound_ipv4_only = SandboxNetworkPolicy {
    allow_unix: true,
    allow_ipv4: true,
    allow_ipv6: false,
    allow_connect: true,
    allow_bind: false,
    allow_listen: false,
    allow_accept: false,
};
```

Linux 字段的含义：

- `allow_unix`、`allow_ipv4`、`allow_ipv6`：控制 socket family 是否允许创建
- `allow_connect`、`allow_bind`、`allow_listen`、`allow_accept`：控制对应 syscall 是否允许

必须明确的边界：

- Linux 目前支持的细粒度控制，是 socket family 创建，以及 `connect` / `bind` / `listen` / `accept` 这几个 syscall 级别的控制。
- 它还不是 IP / 端口 / CIDR 级防火墙。
- macOS 和 Windows 目前只支持上面的三个 helper 形状。其他自定义 `SandboxNetworkPolicy` 会 fail-closed，返回 `SandboxError::Unavailable`。

实用规则：

- `procwarden` 不会自动继承父进程环境变量。
- 如果命令依赖查找，请至少传入 `PATH`。
- 如果程序需要可写临时目录，请先创建目录，再把它加入 `read_write`。
- 如果某条规则和默认模式等价，manager 会把这条冗余规则归一化掉。
- `cwd` 和所有 `path_permissions` 路径都必须已经存在。
- 路径会在后端分发前先 canonicalize。
- `deny` 祖先路径下面，不能再用子路径重新放开权限。
- `timeout_ms` 会杀掉超时进程，并把超时退出码统一为 `124`。

## 支持矩阵

### 文件系统

| 平台 | 状态 | 条件 |
|---|---|---|
| Linux | 可用 | 2026-04-07 已在本地 `Linux 6.17.0-20-generic` `x86_64` 重新验证。任何真正的减法规则（`deny`，或者 `ReadWrite` 下的 `read_only`）都依赖 user/mount namespace 支持（`CLONE_NEWUSER` + `CLONE_NEWNS`，或等价 `CAP_SYS_ADMIN`），而且目标路径必须已经存在。能力不足时会 fail-closed，返回 `SandboxError::Unavailable`。 |
| macOS | 有条件可用 | 需要 `/usr/bin/sandbox-exec`；如果不用默认路径，则 `PROCWARDEN_MACOS_SANDBOX_EXEC` 必须指向有效替代路径。 |
| Windows | 有条件可用 | 通过 AppContainer 加 ACL 变更实现。请在真实 Windows 主机上验证，不要只把 `windows-latest` 当成结论。既有路径会先 canonicalize，再在 ACL 应用前做一次清洗。 |

### 网络

| 平台 | `disabled()/outbound_only()/bidirectional()` | 自定义 `SandboxNetworkPolicy` | 条件 |
|---|---|---|---|
| Linux | 可用 | 可用 | 2026-04-07 已在本地重新验证。现在本地测试已经覆盖 `allow_unix`、`allow_ipv4`、`allow_ipv6`、`allow_connect`、`allow_bind`、`allow_listen`、`allow_accept`。当前 Linux 支持是 syscall 级，不是 IP / 端口 / CIDR 匹配。 |
| macOS | 有条件可用 | 不支持，fail-closed | 需要 `/usr/bin/sandbox-exec`；如果不用默认路径，则 `PROCWARDEN_MACOS_SANDBOX_EXEC` 必须指向有效替代路径。自定义细粒度网络策略会被明确拒绝。 |
| Windows | 有条件可用 | 不支持，fail-closed | 通过 AppContainer 和网络过滤实现。`disabled()` 在 WFP 或 elevated helper 路径不可用时会 fail-closed。`outbound_only()` 和 `bidirectional()` 会申请客户端 loopback exemption，`bidirectional()` 还可能启动服务端 loopback helper；但实际 loopback 和 listener 行为仍然依赖宿主环境与具体可执行文件。自定义细粒度网络策略会被明确拒绝。 |

## 在你自己的机器上复测

```bash
cargo test --test linux_network_policy_control -- --nocapture
cargo test --test network_mode_control -- --nocapture
cargo test --test policy_combination_matrix -- --nocapture
cargo test --workspace --all-targets -- --nocapture
cargo run --quiet --bin ci_matrix_probe
```

Windows 还建议额外执行：

```bash
cargo test --test windows_network_mode_control -- --nocapture
cargo test --test windows_network_mode_control debug_current_host_windows_network_matrix -- --ignored --nocapture
```
