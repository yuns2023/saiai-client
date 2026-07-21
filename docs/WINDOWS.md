# Windows 使用指南（SAIAI 1.1.3）

SAIAI `1.1.3` 为 Claude Code 和 VSCode 提供用户级本地代理，不要求管理员权限。

## 一键配置 Claude Code

在 PowerShell 中运行 WebUI 为当前 Key 生成的命令：

```powershell
irm https://api.saiai.top/saiai-cli/setup.ps1 | iex; Invoke-Saiai 'https://api.saiai.top' 'YOUR_API_KEY'
```

脚本根据 `PROCESSOR_ARCHITECTURE` / `PROCESSOR_ARCHITEW6432` 选择 x86_64 或
ARM64 资产，验证 manifest、size 和 SHA-256。默认安装位置是
`%LOCALAPPDATA%\SAIAI\bin\saiai.exe`，并加入用户 PATH。

该命令安装、初始化并启动本地代理。相同版本再次执行时只获取 manifest，跳过
二进制下载，然后替换 Base URL/Key 并刷新代理。

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

WebSocket 模式在末尾加 `--websockets`。配置写入 `%USERPROFILE%\.codex`，或
`CODEX_HOME` 指定的目录；Codex 初始化不会启动 Claude 本地代理。

## 更新与回退

当前二进制与 manifest 哈希相同时不会重复下载。首次替换不同二进制时保留
`saiai-previous.exe`。如需人工回退，应先执行 `saiai stop`，再恢复备份并重新
启动；用户配置文件自身也会留下带时间戳的备份。

命令直接包含 API Key，因此 Key 会出现在剪贴板、PowerShell 历史和进程参数
中；这是 WebUI 一键配置路径的明确取舍。SAIAI 程序自身不会打印 Key。
