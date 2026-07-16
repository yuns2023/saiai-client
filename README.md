# SAIAI Client

SAIAI Client `1.0.1` 是一个纯配置客户端。它把 SAIAI Gateway 地址和 API Key
写入 Claude Code 或 Codex CLI 的全局配置；不启动本地代理，不创建隔离 home、
generation、CA 或常驻服务。

## 一键配置

WebUI 会生成已经包含当前 Gateway 地址和 API Key 的一行命令。macOS / Linux
形式如下：

```bash
curl -fsSL https://api.saiai.top/saiai-cli/setup.sh | bash -s -- 'https://api.saiai.top' 'YOUR_API_KEY'
```

PowerShell：

```powershell
irm https://api.saiai.top/saiai-cli/setup.ps1 | iex; Invoke-Saiai 'https://api.saiai.top' 'YOUR_API_KEY'
```

命令可以反复执行。Base URL 或 Key 改变时会覆盖 SAIAI 管理的值并保留无关
配置。由于一键命令直接包含 Key，Key 会出现在剪贴板、终端命令和 shell 历史
中；客户端自身不会把 Key 打印到输出。

wrapper 每次只下载很小的 `manifest.json`。如果本机二进制 SHA-256 已等于
manifest 中的当前版本，就跳过二进制下载，但仍会重新应用配置。

## Claude Code 行为

Claude 初始化写入用户级 `settings.json`：

- `ANTHROPIC_BASE_URL`
- `CLAUDE_CODE_OAUTH_TOKEN`
- `CLAUDE_STREAM_IDLE_TIMEOUT_MS=600000`
- 当前 SAIAI 功能开关

写入时会移除会覆盖认证、provider、model、proxy 和 CA 的冲突环境变量，移除
`.claude.json` 中的 `oauthAccount`，备份后删除 `.credentials.json` 以及旧的
`saiai-ca.crt`。其他 JSON 字段和机器本地身份值保持不变。

默认路径是 `~/.claude/settings.json`、`~/.claude.json` 和
`~/.claude/.credentials.json`。设置 `CLAUDE_CONFIG_DIR` 时，以上文件全部跟随该
目录。配置完成后直接运行 `claude`，VSCode 中的 Claude Code 也读取同一份全局
配置；不再使用 `saiai claude`。

可执行以下命令检查配置，Key 值不会显示：

```bash
saiai doctor
```

## Codex CLI

```bash
saiai init-codex https://api.saiai.top/v1 YOUR_API_KEY
saiai init-codex https://api.saiai.top/v1 YOUR_API_KEY --websockets
```

该命令合并 `~/.codex/config.toml` 和 `~/.codex/auth.json`，保留不属于 SAIAI
管理范围的字段。

## 发布资产

固定的六个二进制资产名为：

- `saiai-linux-x86_64`
- `saiai-linux-aarch64`
- `saiai-macos-x86_64`
- `saiai-macos-aarch64`
- `saiai-windows-x86_64.exe`
- `saiai-windows-aarch64.exe`

Linux 资产使用静态 musl，避免旧发行版上的 GLIBC 版本错误。release 还包含
`manifest.json` 与三个 wrapper。详细行为见
[客户端设计](docs/CLIENT_DESIGN.md) 和 [Windows 指南](docs/WINDOWS.md)。

## 本地验证

```bash
cargo fmt --manifest-path tools/saiai-cli/Cargo.toml --check
cargo test --locked --manifest-path tools/saiai-cli/Cargo.toml
bash scripts/saiai-cli/test-setup-wrappers.sh
python3 scripts/saiai-cli/verify-release.py
```
