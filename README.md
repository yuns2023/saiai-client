# SAIAI Client

SAIAI Client `1.1.4` 使用托管本地代理模式。Claude Code 和 VSCode 通过用户
级 `saiai` 代理访问 Gateway；Codex CLI 仍使用直接配置。客户端不创建隔离
home 或 generation。

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

命令会完成安装、初始化并启动用户级本地代理，可以反复执行。Base URL 或 Key
改变时会覆盖 SAIAI 管理的值、保留无关配置并刷新服务。由于一键命令直接包含
Key，Key 会出现在剪贴板、终端命令和 shell 历史中；客户端自身不会把 Key
打印到输出。

wrapper 每次只下载很小的 `manifest.json`。如果本机二进制 SHA-256 已等于
manifest 中的当前版本，就跳过二进制下载，但仍会重新应用配置。Windows
上替换新版本时，wrapper 会在下载和验证完成后停止旧代理，释放可执行文件锁，
再安装并启动新版本。

## Claude Code 本地代理

Claude 初始化写入用户级 `settings.json`：

- `CLAUDE_CODE_OAUTH_TOKEN`
- `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`
- `NODE_EXTRA_CA_CERTS`
- `CLAUDE_STREAM_IDLE_TIMEOUT_MS=600000`
- 当前 SAIAI 功能开关

写入时会移除会覆盖认证、provider、model、proxy 和 CA 的冲突环境变量，移除
`.claude.json` 中的 `oauthAccount`，并在备份后删除 `.credentials.json`。其他
JSON 字段和机器本地身份值保持不变。客户端为每个用户生成独立 CA；私钥只以
用户私有权限保存在本机，不会进入 release 或日志。

代理仅监听 loopback。`api.anthropic.com:443` 由本地代理终止 TLS 并转发到
Gateway；其他 HTTP `CONNECT` 请求以任意目标、任意 TCP 端口直接建立隧道，
因此可由本机 TUN、Fake-IP 和用户自己的出站规则继续处理。

默认路径是 `~/.claude/settings.json`、`~/.claude.json` 和
`~/.claude/.credentials.json`、`~/.claude/saiai-ca.crt` 和
`~/.claude/saiai-ca.key`。设置 `CLAUDE_CONFIG_DIR` 时，这些 Claude 配置、状态、
credentials 和 CA 文件全部跟随该目录。代理配置和 Key 独立保存于
`~/.saiai/config.json`；可用 `SAIAI_HOME` 改变其目录，且不受
`CLAUDE_CONFIG_DIR` 影响。配置完成后直接运行 `claude`，VSCode 中的 Claude
Code 也读取同一份配置。

常用管理命令：

```bash
saiai start
saiai stop
saiai status
saiai logs
saiai restart
saiai update
```

直接执行 `saiai` 可以前台运行代理，`saiai --verbose` 会显示请求级诊断日志。
Linux 优先使用 `systemd --user`；root、容器或无登录会话环境没有可用的 user
bus 时，`saiai start` 会自动改用脱离终端的托管后台进程。后一模式会跨 shell
持续运行，但宿主重启或进程异常退出后需要再次执行 `saiai start`。

可执行以下命令检查代理、配置和 Gateway 健康状态，Key 值不会显示：

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
