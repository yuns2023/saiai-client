# SAIAI Client

SAIAI Client 是面向 Claude Code 与 Codex 的全新 V2-only 本地客户端。它提供命令行入口和 Tauri 2 桌面界面，让两个产品按需初始化、使用彼此独立的凭据，并在平台标准目录中维护隔离状态。

当前版本为 Preview，配置 schema 固定为 2。这个公开项目不包含旧模式实现，也不迁移旧配置。

## 安装 Preview

CLI Release 使用六个平台资产和一个带 SHA-256/size 的 manifest。以 `0.9.0` 为例，Windows PowerShell 可以直接从同一 tag 安装：

```powershell
$tag = "saiai-v0.9.0"
$env:SAIAI_DOWNLOAD_BASE = "https://github.com/yuns2023/saiai-client/releases/download/$tag"
irm "https://raw.githubusercontent.com/yuns2023/saiai-client/$tag/scripts/saiai-cli/setup.ps1" | iex
Invoke-Saiai
Remove-Item Env:SAIAI_DOWNLOAD_BASE
```

Linux 或 macOS：

```bash
tag=saiai-v0.9.0
curl -fsSL "https://raw.githubusercontent.com/yuns2023/saiai-client/${tag}/scripts/saiai-cli/setup.sh" \
  | SAIAI_DOWNLOAD_BASE="https://github.com/yuns2023/saiai-client/releases/download/${tag}" bash
```

当相同 bundle 已镜像到 Gateway 后，安装命令可以缩短为 `irm https://api.saiai.top/saiai-cli/setup.ps1 | iex; Invoke-Saiai` 或 `curl -fsSL https://api.saiai.top/saiai-cli/setup.sh | bash`。不要在 Gateway 尚未发布匹配 manifest 时混用两个来源。

安装器只安装二进制，不接收 API Key，也不初始化产品。若目标位置已有不同的 `saiai`，会一次性保留为 `saiai-previous`（Windows 为 `saiai-previous.exe`），便于 Preview 回退。

安装完成时，安装器会打印带绝对路径的下一步命令；第一次使用请直接执行该命令，不依赖当前终端是否已刷新 `PATH`。之后新开的终端可直接使用 `saiai claude` 或 `saiai codex`。

当前 Preview 尚未配置 Windows/macOS 正式代码签名，系统可能显示未知发布者提示；请只使用本仓 tag 与对应 manifest，正式发布前会另行建立签名和更新密钥流程。

Windows 的安装、按产品初始化、PATH、更新和 revoke 完整流程见
[Windows 使用指南](docs/WINDOWS.md)。

## 使用方式

先安装你实际要使用的官方客户端，然后运行对应入口：

```text
saiai claude
saiai codex
```

某个产品第一次启动时，SAIAI 只询问该产品需要的 API Key。第一个完成初始化的产品还会确定共享 Gateway URL；之后初始化另一产品时复用该地址，但使用自己的 Key。

需要显式初始化时，可以使用：

```text
saiai setup claude
saiai setup codex
```

常用维护命令：

```text
saiai doctor
saiai claude revoke
saiai codex revoke
saiai revoke --all
saiai ui
```

- Claude 与 Codex 都是可选产品，未配置其中一个不是错误。
- 单产品 revoke 不影响另一产品；`revoke --all` 清理全部 V2 状态。
- Gateway 或本地状态异常时，先运行 `saiai doctor`，不要把包含凭据的文件粘贴到公开问题中。

## 设计边界

- Native client 将 API Key 交给本地 Rust 处理，提交后清除 UI 临时值，并且不通过状态、doctor 或 Desktop IPC 结果返回。
- 初始化只调用不产生模型用量的 Gateway bootstrap 端点。
- Claude 使用每次安装生成的本地 CA；项目不分发共享 CA 私钥。
- 配置、数据和运行状态存放在平台标准应用目录中。
- schema 2 状态不提供迁移器；无法验证的状态通过 `saiai revoke --all` 后重新初始化。

详细设计见 [客户端设计](docs/CLIENT_DESIGN.md)，Gateway 实现方见 [bootstrap contract](docs/GATEWAY_BOOTSTRAP.md)。

## 并行体验说明

Preview 期间，旧模式只保留在私有旧仓中供并行体验。两个项目各自维护状态；本仓不会读取、导入或兼容旧模式。公开 V2 binary 本身不包含旧命令；如安装前已有旧 binary，可用安装器保留的 `saiai-previous` 显式启动它。是否停用旧模式不影响本仓的 V2 contract。

## 仓库结构

```text
tools/saiai-core/       V2 状态、凭据和初始化事务
tools/saiai-cli/        V2 命令行入口与客户端启动逻辑
tools/saiai-desktop/    Tauri 2 + Vue 桌面界面
docs/                   公开设计与 Gateway contract
```

Desktop 的开发说明见 [tools/saiai-desktop/README.md](tools/saiai-desktop/README.md)。贡献代码前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)；安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。

## License

本项目使用 [MIT License](LICENSE)。
