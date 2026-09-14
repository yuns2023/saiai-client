# SAIAI Client

SAIAI Client `1.1.13` 使用托管本地代理模式。Claude Code 和 VSCode 通过用户
级 `saiai` 代理访问 Gateway；Codex CLI 通过 `saiai codex`、Codex VSCode 扩展
通过一次性的 `saiai vscode` 配置使用同一用户级代理，
旧的 `init-codex` 直接配置方式继续兼容。客户端不创建隔离
home 或 generation。

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
和 Key，保留无关配置。由于命令包含 Key，Key 会出现在剪贴板、终端命令和 shell
历史中；客户端自身不会把 Key 打印到输出。WebUI 只提供 Codex CLI，不提供
WebSocket 专用页签。

Claude Code 仍可使用带 Base URL/Key 的兼容初始化命令。

wrapper 每次只下载很小的 `manifest.json`。如果本机二进制 SHA-256 已等于
manifest 中的当前版本，就跳过二进制下载，但仍会重新应用配置。Windows
上替换新版本时，wrapper 会在下载和验证完成后停止旧代理，释放可执行文件锁，
再安装并启动新版本。

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
saiai desktop
# alias:
saiai chatgpt
```

该命令只在 Codex 子进程中设置 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 和
`CODEX_CA_CERTIFICATE`。Linux 通过子进程参数启用 Codex 的
`features.respect_system_proxy`；Windows/macOS 则明确关闭该特性，使 Responses
HTTP/WS 使用子进程代理环境，避免 WinHTTP/SystemConfiguration 返回 `DIRECT` 后
绕过本地代理。它不会修改用户
shell、系统环境变量或把这个开关写入 `config.toml`。启动前会备份并清理
生效 `CODEX_HOME` 中的第三方 `base_url`、provider 和 WebSocket 开关，将根
provider 恢复为官方内置 `openai`。为兼容旧版 `init-codex` 创建的历史线程，
配置会额外保留一个固定的 `model_providers.OpenAI` 别名；它只指向
`https://api.openai.com/v1`、使用 `responses` 和 `requires_openai_auth`，不会
保留旧的 Gateway、env_key 或其他用户字段。这样旧线程可以继续解析 provider，
而请求仍经由 local-proxy；新线程仍使用内置 `openai`。备份文件使用同目录的
`.bak-<timestamp>` 后缀。

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

Codex VSCode 扩展不是 `saiai codex` 的子进程，因此首次使用前执行：

```bash
saiai vscode
```

该命令备份并清理同一 `CODEX_HOME` 中冲突的 provider/base URL，创建本地代理 OAuth
占位状态，并在 Codex 专属 `.env` 中写入 loopback 代理、`SSL_CERT_FILE` 和
`NO_PROXY`；同时按平台在 Codex 配置中写入 `features.respect_system_proxy`：
Linux 为 `true`，Windows/macOS 为 `false`。它不会
修改 shell 或操作系统环境变量，也不会写入第三方 `base_url`。配置完成后重启
VSCode（或 reload window），继续正常使用官方 Codex 扩展。若用户显式配置了 VSCode
的 `http.proxy`，该值可能优先于 Codex `.env`，需要移除冲突值。

`saiai desktop` 使用现有 ChatGPT OAuth `auth.json` 的副本启动隔离的 Desktop
`CODEX_HOME`，不会修改原始 Codex 目录。Linux 下还会在 SAIAI 管理目录创建独立
NSS 数据库并导入本地 CA，避免修改系统信任库；首次使用需要系统已有
`certutil`（`libnss3-tools`）。Desktop 的 OAuth/CA/代理环境由 launcher 注入，
不会写入系统环境变量。隔离的 Desktop 全局状态会预置“已完成首次项目引导”，
因此不会每次启动都要求选择职业/个性化设置；这只影响 SAIAI 管理的 Desktop
profile，不会改写原始 Codex 配置。

桌面入口按产品 target 组织：`saiai desktop codex` 和
`saiai desktop chatgpt` 使用当前 OpenAI Desktop adapter；`saiai desktop claude`
与 `saiai desktop gemini` 已预留为独立 adapter 入口，当前会明确提示尚未实现。
未来产品接入只需增加各自的 executable/config/auth/proxy/model/readiness adapter，
共享 local-proxy、CA、profile、日志和进程生命周期管理。

普通 ChatGPT Chat 默认使用固定的美国太平洋时区。也可以按次启动覆盖：

```bash
SAIAI_CHATGPT_TIMEZONE=America/Los_Angeles saiai chatgpt
```

该变量只作用于 Desktop 子进程，必须是本机存在的 IANA zoneinfo 名称；未设置时
默认使用 `America/Los_Angeles`。如果需要恢复系统时区，可设置
`SAIAI_CHATGPT_TIMEZONE=system`。它不会改变 Codex CLI/VSCode 的 Responses 请求，
也不会修改系统环境或 Gateway 请求体。

`saiai chatgpt` 默认转发普通 ChatGPT Chat 的明确 allowlist（包括
`/backend-api/files/download/{file_id}` 与 `/backend-api/estuary/content` 图片/文件资产解析）到 Gateway 的独立
`/chatgpt/backend-api/*` ingress，不做 Responses 协议转换。紧急排障时可仅对代理
进程设置 `SAIAI_CHATGPT_CHAT_PASSTHROUGH=0` 关闭该路径；Gateway 端仍需显式启用
普通 Chat，并在计费不可用时默认拒绝最终模型请求。

旧的 API-key 初始化命令暂时保持兼容：

```bash
saiai init-codex https://api.saiai.top/v1 YOUR_API_KEY
```

该命令合并 `~/.codex/config.toml` 和 `~/.codex/auth.json`，保留不属于 SAIAI
管理范围的字段；同时在独立的 `SAIAI_HOME` 中创建或更新本地代理配置和安装 CA，
因此同一次初始化后可以直接运行 `saiai codex`。它不会修改 Claude 配置或自动启动
代理；`saiai codex` 会在需要时启动代理。旧直连 Provider 保留传入的 `/v1`，
本地代理配置则移除末尾 `/v1` 后再转发客户端原始 `/v1/*` 路径，避免产生
`/v1/v1/*`。已有有效代理 CA、监听地址和普通 Chat
开关会保留，只替换本次指定的 Gateway 和 Key。launcher 只在 `auth.json` 的旧
API Key 与当前 SAIAI 配置 Key 完全一致时把它升级为本地代理 OAuth 占位；不同的
API Key 和真实 OAuth 都不会被覆盖。Codex 0.149.0+ 使用自定义 Provider 时会写入
`requires_openai_auth = true`，并将全局默认值设置为 `gpt-5.6-sol`、评审模型
`gpt-5.4` 和 `model_reasoning_effort = "xhigh"`。执行权限相关的
`sandbox_mode`、`approval_policy` 和 `dangerously_bypass_approvals_and_sandbox`
不属于 SAIAI CLI 管理范围：已有值会原样保留，初始化不会自动启用全盘访问、关闭审批或绕过安全检查。

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
