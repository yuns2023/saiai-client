# SAIAI Client

SAIAI Client `1.1.21` 使用托管本地代理模式。Claude Code 和 VSCode 通过用户
级 `saiai` 代理访问 Gateway；`init-codex`、Codex CLI、Codex VSCode 扩展和
Desktop 使用同一套 OAuth/local-proxy 配置。客户端不创建隔离 home 或 generation。

## 一键配置

Codex WebUI 会生成包含当前 Gateway 地址和 API Key 的一行短命令。macOS / Linux
形式如下：

```bash
curl -fsSL https://api.saiai.top/saiai-cli/setup.sh | bash -s -- init-codex 'https://api.saiai.top/v1' 'YOUR_API_KEY'
```

PowerShell：

```powershell
irm https://api.saiai.top/saiai-cli/setup.ps1 | iex; Invoke-Saiai init-codex 'https://api.saiai.top/v1' 'YOUR_API_KEY'
```

命令会完成安装、初始化并启动用户级本地代理，可以反复执行；它会替换受管 Base URL
和 Key，清理旧的直连 provider，写入 OAuth/local-proxy `auth.json` 与 `.env`，并
保留无关配置。`.env` 的 loopback 端口始终取自当前
`~/.saiai/config.json`，不再遗留固定 `19908`。由于命令包含 Key，Key 会出现在
剪贴板、终端命令和 shell 历史中；客户端自身不会把 Key 打印到输出。WebUI 只提供
Codex CLI，不提供 WebSocket 专用页签；即使旧页面仍传入 `--websockets`，它也只是
兼容接受，代理默认同时支持 Responses HTTP 和 WebSocket。

Claude Code 仍可使用带 Base URL/Key 的兼容初始化命令。

wrapper 每次只下载很小的 `manifest.json`。如果本机二进制 SHA-256 已等于
manifest 中的当前版本，就跳过二进制下载，但仍会重新应用配置。Windows
上替换新版本时，wrapper 会在下载和验证完成后停止旧代理，释放可执行文件锁，
再安装并启动新版本。

重复初始化不会无条件打断已有代理：当本次未替换二进制、Gateway/Key/监听地址/CA
等代理运行时配置未变化，且受管服务与当前 loopback 监听均健康时，CLI 只更新用户
配置文件并保留现有代理进程。配置变化、二进制替换、服务未运行或监听不可达时才会
启动或刷新服务。

## Claude Code 本地代理

Claude 初始化写入用户级 `settings.json`：

- `CLAUDE_CODE_OAUTH_TOKEN`
- `http_proxy` / `https_proxy` / `all_proxy`
- `NODE_EXTRA_CA_CERTS`
- `CLAUDE_STREAM_IDLE_TIMEOUT_MS=600000`
- 当前 SAIAI 功能开关

写入时会移除会覆盖认证、provider、model、proxy 和 CA 的冲突环境变量，代理配置使用
小写环境变量名以优先于 Linux/WSL shell 中遗留的大写代理变量；移除
`.claude.json` 中的 `oauthAccount`，并在备份后删除 `.credentials.json`。其他
JSON 字段和机器本地身份值保持不变。客户端为每个用户生成独立 CA；私钥只以
用户私有权限保存在本机，不会进入 release 或日志。

代理仅监听 loopback。`api.anthropic.com:443` 和 Codex 使用的
`api.openai.com:443` 由本地代理终止 TLS 并转发到 Gateway；其他 HTTP `CONNECT`
请求以任意目标、任意 TCP 端口直接建立隧道，因此可由本机 TUN、Fake-IP 和用户
自己的出站规则继续处理。

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

OAuth/local-proxy 模式（第一阶段）使用：

```bash
saiai codex
saiai codex -- app-server --stdio
saiai vscode
saiai desktop codex
```

`saiai codex` 只在 Codex 子进程中设置 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 和
`CODEX_CA_CERTIFICATE`。Linux 通过子进程参数启用 Codex 的
`features.respect_system_proxy`；Windows/macOS 则明确关闭该特性，使 Responses
HTTP/WS 使用子进程代理环境，避免 WinHTTP/SystemConfiguration 返回 `DIRECT` 后
绕过本地代理。它不会修改用户
shell、系统环境变量或把这个开关写入 `config.toml`。启动前会备份并清理
生效 `CODEX_HOME` 中的第三方 `base_url`、provider 和 WebSocket 开关，将根
provider 恢复为官方内置 `openai`，且不保留旧直连 SAIAI provider 或历史线程兼容
别名。备份文件使用同目录的 `.bak-<timestamp>` 后缀。

SAIAI 合成登录态不能认证官方 hosted Apps MCP，因此 launcher 默认仅在该 Codex
子进程中设置 `features.apps=false`，避免出现与模型请求无关的 `codex_apps` 451
启动告警。用户显式传入同名 feature 覆盖时，以用户参数为准。
Codex 默认还会向 `ab.chatgpt.com` 发送 Statsig OTEL 指标；该非模型端点在部分网络
不可达，所以 launcher 同样只对子进程设置 `otel.metrics_exporter="none"`。这不会
改变 Responses 请求，用户显式传入该配置时仍以用户值为准。

第一阶段接受 `auth_mode = "chatgpt"` 或 `auth_mode = "chatgptAuthTokens"` 且存在
access-token 形状的状态；若用户从未登录，launcher 会创建只对本地代理有意义的
`chatgptAuthTokens` 占位状态，Gateway 仍是实际认证边界。该模式明确告诉 Codex
token 由外部宿主提供，Codex 不得拿合成状态访问 OpenAI OAuth refresh endpoint。
占位状态包含供本地 app-server 展示登录态所需的无签名 ID token 形状，但不能通过
OpenAI 校验；绕过本地代理时不会成为可用凭证。
`OPENAI_API_KEY` 不参与认证。代理转发 Codex 的 Responses HTTP/WebSocket 请求时
保留原始路径、请求体、帧和客户端标识头，只在发往 SAIAI Gateway 的边界替换
Gateway 认证。

launcher 会直接运行 PATH 中的原生 Codex 可执行文件。Linux 官方安装器刚把
`~/.local/bin` 写入 shell profile、但当前终端尚未刷新 PATH 时，也会回退查找
`~/.local/bin/codex`。Windows 同时支持 PATH 中的原生 `codex.exe`，以及 npm 常见的
`codex.cmd` + `node_modules/@openai/codex/bin/codex.js` 布局；后者通过 `node.exe`
安全启动，不依赖 `cmd.exe` 展开参数。

`init-codex` 已为 Codex VSCode 扩展写入同一 `CODEX_HOME/.env`。若需在不重新
提供 Gateway/Key 的情况下修复或刷新扩展配置，也可以执行：

```bash
saiai vscode
```

该命令会重复应用相同的 OAuth/local-proxy 配置：清理同一 `CODEX_HOME` 中冲突的
provider/base URL，创建或保留本地代理 OAuth 状态，并在 Codex 专属 `.env` 中写入
当前 loopback 代理、`SSL_CERT_FILE` 和
`NO_PROXY`；同时按平台在 Codex 配置中写入 `features.respect_system_proxy`：
Linux 为 `true`，Windows/macOS 为 `false`。它不会
修改 shell 或操作系统环境变量，也不会写入第三方 `base_url`。配置完成后重启
VSCode（或 reload window），继续正常使用官方 Codex 扩展。若用户显式配置了 VSCode
的 `http.proxy`，该值可能优先于 Codex `.env`，需要移除冲突值。

`saiai desktop codex` 使用现有 ChatGPT OAuth `auth.json` 的副本启动隔离的 Desktop
`CODEX_HOME`，不会修改原始 Codex 目录。Linux 下还会在 SAIAI 管理目录创建独立
NSS 数据库并导入本地 CA，避免修改系统信任库；首次使用需要系统已有
`certutil`（`libnss3-tools`）。Desktop 的 OAuth/CA/代理环境由 launcher 注入，
不会写入系统环境变量。隔离的 Desktop 全局状态会预置“已完成首次项目引导”并确保
所有可用权限模式在 composer 中可见；后者只控制 selector 可见性，不会选择模式、
修改 approval/sandbox 或授予 Full Access。`init-codex` 也会对正常 `CODEX_HOME`
应用同一幂等修复，修改既有状态前先备份并保留其他字段。

在 Linux，`saiai init-codex` 还会把安装 CA 更新到当前用户的
`~/.pki/nssdb` 中唯一的 `saiai-local-proxy` 条目，帮助直接启动的官方 Desktop
建立 CA 信任。它不改系统信任库，也没有系统弹窗；但会影响该用户共享此 NSS
数据库的应用，命令会明确说明该操作。没有 `certutil` 时，CLI/VSCode 仍可使用，
Desktop 请使用 `saiai desktop codex`。`saiai doctor codex` 会报告该条目是否存在。
Desktop 的 Statsig `/v1/initialize` 和登录后 bootstrap 由本地 sidecar 以同一最小
payload 闭环，只启用 Codex 内置翻译消息所需的 i18n layer；它们不发送到 Gateway 或
Statsig，也不携带 SAIAI Key、合成账户、Cookie 或请求体。macOS 不会写入 Keychain：官方
App 从 Dock、Finder 或 `open -a` 直接启动时不能继承 launcher 的叶证书 SPKI pin，若要让它
信任 SAIAI 本地 CA，必须由当前用户通过 macOS 的授权交互把该 CA 设为登录 Keychain 的信任根。
这不是可由 `init-codex` 静默完成的操作。未完成该用户授权时，使用无 Keychain、无系统代理修改的
`saiai desktop codex`；它只对本次 Desktop 进程传入当前 SAIAI 叶证书的 SPKI pin，而不会放宽
其他证书校验。Windows 的 AppX broker 则不能继承该进程级 pin：`saiai desktop codex`
会在官方 App 存活期间暂时设置当前用户的 loopback 系统代理和 SAIAI 根证书；重复启动以
generation lease 交接，旧 watcher 不会清理新会话的 CA。退出后恢复启动前的代理并清理仅由
SAIAI 加入的根证书。`saiai doctor codex` 会明确报告 direct App 的前置条件。

官方应用的可执行文件和壳层仍显示为“ChatGPT”，但 SAIAI Desktop 当前只支持 Codex。
`saiai desktop chatgpt`、Claude 与 Gemini target 都会明确拒绝。不要把官方应用左栏的
普通 ChatGPT 会话、语言、设置或插件界面当作 SAIAI 已支持的功能：这些控制面没有
历史/偏好持久化合同，也不是 Codex Responses 验证的一部分。`saiai desktop codex`
通过 `codex://threads/new` 激活 Codex；如果用户在官方 UI 中手动切回 ChatGPT，结果
不受支持。

`init-codex` 不再提供 API-key 直连 Gateway 模式：输入的 Key 只保存在
`SAIAI_HOME/config.json`，由 loopback proxy 在 Gateway 边界使用。它会备份后清理
旧 `config.toml` provider/base URL 和 API-key-only `auth.json`，并创建本地 OAuth
占位（已有真实 ChatGPT OAuth 会保留）。根模型选择、推理强度、上下文预算和执行安全
设置不由 SAIAI 改写。

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
