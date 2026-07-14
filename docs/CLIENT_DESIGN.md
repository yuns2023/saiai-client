# SAIAI V2 Client Design

## 目标

SAIAI V2 让用户通过 `saiai claude` 或 `saiai codex` 启动对应官方客户端，并在首次使用时只配置所选产品。CLI 与 Desktop 共享同一个 Rust core 和同一份 schema-2 状态。

V2 的约束是：

- Claude 与 Codex 都是可选产品；
- 两个产品共用一个 Gateway URL，但各自保存凭据；
- 初始化、重新初始化和 revoke 均以产品为边界；
- 所有启动参数以独立进程参数传递，不通过 shell 拼接；
- 状态提交是事务性的，读取启动信息时持有对应 generation lease；
- 不提供旧 schema 或其他模式的迁移器。

发布 wrapper 只安装经过 manifest 校验的 V2 binary，不接收凭据、不创建 V2 状态。替换不同的现有 binary 时只保留一份 `saiai-previous` 回退副本；这不是配置迁移，core 仍不会检查原有客户端目录。

## 首次使用

交互式启动遵循按需初始化：

```text
saiai claude
  -> 尚未配置 Claude 时，询问 Gateway URL（如尚未保存）和 Claude Key
  -> 验证 bootstrap 的 Claude capability
  -> 提交 Claude 的隔离环境
  -> 启动 Claude Code

saiai codex
  -> 尚未配置 Codex 时，询问 Gateway URL（如尚未保存）和 Codex Key
  -> 验证 bootstrap 的 Codex 与 Responses capability
  -> 提交 Codex 的隔离环境
  -> 启动 Codex
```

非交互环境必须明确选择产品，并通过标准输入提供凭据：

```text
saiai setup claude --base-url <gateway-url> --api-key-stdin
saiai setup codex --base-url <gateway-url> --api-key-stdin
```

如果另一产品已经保存 Gateway，后续 setup 可以省略 `--base-url`。传入不同 Gateway 时必须拒绝，直到全部 V2 状态被 revoke。

## 状态模型

schema 2 只描述 V2 自己管理的状态：

- `config.json` 保存共享 Gateway、各产品 credential reference 和 generation reference；
- 凭据文件按产品独立保存，并要求当前用户私有权限；
- generation 目录保存该产品的干净客户端 home；
- state 目录保存 lease、runtime 和非敏感诊断数据。

平台目录：

| 平台 | Config | Data | State |
| --- | --- | --- | --- |
| Windows | `%LOCALAPPDATA%\SAIAI\config` | `%LOCALAPPDATA%\SAIAI\data` | `%LOCALAPPDATA%\SAIAI\state` |
| macOS | `~/Library/Application Support/SAIAI/config` | `~/Library/Application Support/SAIAI/data` | `~/Library/Application Support/SAIAI/state` |
| Linux | `$XDG_CONFIG_HOME/saiai` 或 `~/.config/saiai` | `$XDG_DATA_HOME/saiai` 或 `~/.local/share/saiai` | `$XDG_STATE_HOME/saiai` 或 `~/.local/state/saiai` |

V2 应用目录由平台标准目录发现确定，不跟随 Claude 或 Codex 的 client-home 环境变量。损坏或不受支持的 V2 状态通过 `saiai revoke --all` 清理后重新初始化。

## 产品隔离

Claude setup 生成独立的 settings、onboarding state 和每安装实例 CA。启动时，本地代理仅使用该实例的证书材料，并把 Claude Code 指向对应的隔离 home。

Codex setup 生成独立 `config.toml`，使用 Responses API；Gateway 报告 WebSocket capability 时才启用对应配置。Codex Key 只在子进程环境中提供。

一个产品重新初始化时可以提交新的 generation，而正在运行的旧 generation 由 lease 保持到子进程退出。对正在使用的 generation 执行相关 revoke 必须失败且不得先改变已提交配置。

## Revoke

- `saiai claude revoke` 只撤销 Claude。
- `saiai codex revoke` 只撤销 Codex。
- `saiai revoke --all` 清理所有 V2-owned config、data 和 state。
- 未配置产品执行 revoke 是正常的幂等操作。

清理时只允许删除通过严格 V2 前缀验证的 generated paths。配置提交失败时，已隔离的路径必须回滚；提交后的残余清理可以安全重试。

## Desktop 边界

Tauri WebView 只调用四个用途明确的命令：读取状态、初始化一个产品、运行 doctor 和 revoke。WebView 不拥有 shell、文件系统、HTTP、store 或 opener 插件权限，也不直接联系 Gateway。

Desktop 与 CLI 调用相同的 core，因此不能维护第二套 setup 状态。浏览器模式仅提供 UI 演示，不读取或写入机器状态。

Gateway 初始化协议见 [GATEWAY_BOOTSTRAP.md](GATEWAY_BOOTSTRAP.md)。
