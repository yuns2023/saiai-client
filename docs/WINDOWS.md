# Windows 使用指南（SAIAI 1.0.0）

SAIAI `1.0.0` 是全局配置工具，不需要管理员权限、后台服务、本地代理或 CA。

## 一键配置 Claude Code

在 PowerShell 中运行 WebUI 为当前 Key 生成的命令：

```powershell
irm https://api.saiai.top/saiai-cli/setup.ps1 | iex; Invoke-Saiai 'https://api.saiai.top' 'YOUR_API_KEY'
```

脚本根据 `PROCESSOR_ARCHITECTURE` / `PROCESSOR_ARCHITEW6432` 选择 x86_64 或
ARM64 资产，验证 manifest、size 和 SHA-256。默认安装位置是
`%LOCALAPPDATA%\SAIAI\bin\saiai.exe`，并加入用户 PATH。

相同版本再次执行时只获取 manifest，跳过二进制下载，然后重新写入配置。因此
Gateway 地址或 Key 变更时可以直接重复执行同一形式的命令。

配置完成后直接运行：

```powershell
claude
```

VSCode Claude Code 使用同一份用户级配置。不要再运行 `saiai claude`；1.0.0
没有隔离 home 或启动器。

## 路径

默认 Claude 文件：

- `%USERPROFILE%\.claude\settings.json`
- `%USERPROFILE%\.claude.json`
- `%USERPROFILE%\.claude\.credentials.json`

设置 `CLAUDE_CONFIG_DIR` 时，settings、state、credentials 和旧 CA 清理都位于
该目录。设置文件使用原子替换；现有文件改变前会留下私有备份。

## Codex CLI

```powershell
irm https://api.saiai.top/saiai-cli/setup.ps1 | iex; Invoke-Saiai init-codex 'https://api.saiai.top/v1' 'YOUR_API_KEY'
```

WebSocket 模式在末尾加 `--websockets`。配置写入 `%USERPROFILE%\.codex`，或
`CODEX_HOME` 指定的目录。

## 更新与回退

当前二进制与 manifest 哈希不同时，wrapper 才下载新文件。首次替换不同版本时
保留 `saiai-previous.exe`。如需要人工回退，可先关闭正在运行的该二进制，再用
备份覆盖 `saiai.exe`；回退不会自动恢复用户配置文件，配置文件自身已有带时间戳
的备份。

命令中直接包含 API Key，因此 Key 会出现在剪贴板、PowerShell 历史和进程参数
中；这是 WebUI 一键配置路径的明确取舍。SAIAI 程序本身不会打印 Key。
