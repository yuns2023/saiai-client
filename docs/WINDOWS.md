# Windows 使用指南（SAIAI 1.1.21）

SAIAI `1.1.21` 为 Claude Code 和 VSCode 提供用户级本地代理，不要求管理员权限。

## 一键配置 Claude Code

在 PowerShell 中运行 WebUI 为当前 Key 生成的命令：

```powershell
irm https://api.saiai.top/saiai-cli/setup.ps1 | iex; Invoke-Saiai 'https://api.saiai.top' 'YOUR_API_KEY'
```

该 wrapper 同时支持 Windows PowerShell 5.1 和 PowerShell 7；它以兼容的原生命令
行方式调用已验证的 `saiai.exe`，不会依赖仅存在于新版 .NET 的参数 API。

脚本根据 `PROCESSOR_ARCHITECTURE` / `PROCESSOR_ARCHITEW6432` 选择 x86_64 或
ARM64 资产，验证 manifest、size 和 SHA-256。默认安装位置是
`%LOCALAPPDATA%\SAIAI\bin\saiai.exe`，并加入用户 PATH。

该命令安装、初始化并启动本地代理。相同版本再次执行时只获取 manifest，跳过
二进制下载，然后替换 Base URL/Key 并刷新代理。发现新版本时，安装器会先
下载并验证新二进制，再停止正在运行的旧代理、替换文件并启动新版本。

配置完成后直接运行 `claude` 或使用 VSCode Claude Code。常用管理命令：

```powershell
saiai start
saiai stop
saiai status
saiai logs
saiai restart
saiai doctor
saiai update
```

## 路径和 CA

默认 Claude 文件：

- `%USERPROFILE%\.claude\settings.json`
- `%USERPROFILE%\.claude.json`
- `%USERPROFILE%\.claude\.credentials.json`
- `%USERPROFILE%\.claude\saiai-ca.crt`
- `%USERPROFILE%\.claude\saiai-ca.key`

设置 `CLAUDE_CONFIG_DIR` 时，Claude settings、state、credentials 和 CA 都跟随
该目录。代理配置和 Key 则独立位于 `%USERPROFILE%\.saiai\config.json`；可用
`SAIAI_HOME` 改变其目录，且不受 `CLAUDE_CONFIG_DIR` 影响。每位用户独立生成
CA；私钥只保存在本机，不包含在 release 中。

初始化会移除冲突的认证/provider/model/proxy/CA 环境变量、`oauthAccount` 和旧
`.credentials.json`，同时保留不相关配置。`CLAUDE_STREAM_IDLE_TIMEOUT_MS=600000`
保持固定。

## Codex CLI

```powershell
irm https://api.saiai.top/saiai-cli/setup.ps1 | iex; Invoke-Saiai init-codex 'https://api.saiai.top/v1' 'YOUR_API_KEY'
```

该命令包含当前 Gateway 和 API Key，会写入 `%USERPROFILE%\\.codex`，或
`CODEX_HOME` 指定的目录；它在 `%USERPROFILE%\.saiai` 准备本地代理配置和独立
安装 CA，并将当前随机 loopback 端口、`SSL_CERT_FILE` 和 `NO_PROXY` 同步到
`CODEX_HOME/.env`。不会修改 Claude 配置，并会启动或刷新受管本地代理。
它会备份后清理旧直连 provider/base URL 与 API-key-only auth，将根 provider 设为
内置 `openai`，不保留 `model_providers.OpenAI` 历史兼容别名。占位状态使用 Codex
的 `chatgptAuthTokens` 外部 token 模式，避免 Codex 把合成 refresh token 发往
OpenAI；已有真实 ChatGPT OAuth 会保留。SAIAI 不会新增、覆盖或删除根 `model`、
`review_model`、推理强度或模型上下文预算。`saiai codex` 支持 PATH 中的原生
`codex.exe`，也支持 npm 安装生成的 `codex.cmd`；npm 布局会由 SAIAI 解析后直接
通过 `node.exe` 运行官方 launcher。`saiai vscode` 仍可用于不重新传入 Gateway/Key
的配置修复；它会重新写入 Codex 专属 `.env`，并将
`features.respect_system_proxy` 设为 `false`，避免 WinHTTP 的 `DIRECT` 决策覆盖
`.env` 中的 loopback 代理；它不修改 Windows 系统环境变量。完成后重启 VSCode。

## 更新与回退

当前二进制与 manifest 哈希相同时不会重复下载。首次替换不同二进制时保留
`saiai-previous.exe`。如需人工回退，应先执行 `saiai stop`，再恢复备份并重新
启动；用户配置文件自身也会留下带时间戳的备份。

重复执行同一初始化命令且二进制、Gateway/Key/监听地址/CA 均未变化时，会保留健康的
后台代理进程，不会为配置文件的幂等重写而中断已有连接。安装新二进制、更新代理运行
时配置或发现代理不健康时，才会停止并启动新的 Windows 后台进程。

WebUI 只提供 Codex CLI，不提供 WebSocket 专用页签。由于命令包含 API Key，Key 会出现在
剪贴板、PowerShell 历史和进程参数中；SAIAI 程序自身不会打印 Key。
