# SAIAI managed local-proxy client design

## 目标

`saiai` 为 Claude Code、VSCode 和新的 `saiai codex` 启动路径提供用户级托管本地
代理，同时保留旧的 Codex CLI 直接配置。WebUI 的一行命令完成安装、配置并启动代理；用户也可以用
`saiai start/stop/status/logs/restart` 管理服务，或直接运行 `saiai` 使用前台模式。

稳定边界：

- 代理只监听 loopback，默认 `127.0.0.1:19908`。
- 不创建隔离 home 或 generation，也不调用 Gateway bootstrap。
- 初始化、doctor 和 release 验证不发送模型请求。
- 同一命令可重复执行；新 Base URL/Key 覆盖旧值。
- 无关用户配置和机器身份值必须保留。
- 每个用户使用独立生成的 CA；release 中不得包含 CA 私钥。

## Claude 配置

Claude 路径解析遵守 `CLAUDE_CONFIG_DIR`。未设置时使用：

- `~/.claude/settings.json`
- `~/.claude.json`
- `~/.claude/.credentials.json`
- `~/.claude/saiai-ca.crt`
- `~/.claude/saiai-ca.key`

代理配置和 Key 使用独立的 `SAIAI_HOME`，默认写入
`~/.saiai/config.json`。改变 `CLAUDE_CONFIG_DIR` 不会移动代理配置；改变
`SAIAI_HOME` 也不会移动 Claude 配置、状态、credentials 或 CA。

初始化会先解析并备份已有配置，然后：

1. 保留无关的 settings/state 字段。
2. 移除认证、云 provider、模型、旧 proxy 和 CA 冲突环境变量。
3. 写入 `CLAUDE_CODE_OAUTH_TOKEN`、loopback proxy（使用小写的
   `http_proxy` / `https_proxy` / `all_proxy` / `no_proxy`）、
   `NODE_EXTRA_CA_CERTS` 和 `CLAUDE_STREAM_IDLE_TIMEOUT_MS=600000`。
4. 移除 settings/state 中的 `oauthAccount`，备份后删除
   `.credentials.json`。
5. 复用有效的用户 CA；CA 缺失或损坏时备份旧文件并生成新 CA 对，私钥权限为
   `0600`。
6. 原子写入代理配置，Base URL 和 Key 在重复初始化时直接替换。

`saiai doctor` 同时检查当前 shell、shell 启动文件、Linux `systemd --user`
环境以及 `settings.json` 中的代理变量。代理配置以小写键为 canonical；发现
大写或其他值（包括 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` 和对应小写键）
可能覆盖本地代理时会明确提示用户清理后再启动 Claude Code。

本地代理终止 `api.anthropic.com` 和 Codex 使用的 `api.openai.com` 本机 TLS，
分别把允许的请求转发到配置的 Gateway；其他 `CONNECT` 请求作为任意目标和任意
TCP 端口的直接隧道处理，让系统 TUN、Fake-IP 和用户自己的出站规则接管实际流量。
它不提供 UDP 转发，也不处理明文 HTTP 的 absolute-form 请求。由于该接口不认证且
可访问任意目标，代理核心必须强制只监听 loopback，不能仅依赖初始化器生成的默认
地址。Gateway Key 由代理从私有配置读取，程序不会把 Key 打印到输出或请求日志。

## 用户服务

- Linux 优先使用 `systemd --user`。如果当前用户的 systemd user bus 不可用
  （常见于 root、容器和无登录会话），`start` 自动改用脱离终端的托管后台进程；
  `stop/status/logs/restart/doctor` 识别同一状态。状态文件记录 PID 与
  `/proc` 启动时间并复核隐藏 worker 参数，避免 PID 复用或 `exec` 后误杀其他
  进程。状态和日志权限为 `0600`。该 fallback 不提供跨宿主重启或崩溃自动拉起。
- macOS 使用用户 LaunchAgent；服务管理直接调用系统自带的 `/bin/launchctl`，
  日志跟随使用 `/usr/bin/tail`，不以不兼容的 GNU `--version` 参数探测命令。
- Windows 使用用户进程与 PID/日志状态文件，不要求管理员权限。

一键 wrapper 在 Claude 初始化成功后执行 `saiai start`。自动化测试或明确需要只
配置不启动时可设置 `SAIAI_SKIP_START=1`。Codex 初始化不会启动 Claude 代理。
发布前在 Intel 和 Apple Silicon macOS runner 上分别验证
`start/status/logs/restart/stop` 的真实 LaunchAgent 生命周期；两个 Linux 静态
资产也必须在强制 `systemctl --user` 失败的环境中完成同一套 fallback 生命周期。

## Codex 启动与配置

旧的 `init-codex <base_url> <api_key> [--websockets]` 继续保留兼容。新的
`saiai codex [-- <codex arguments>]` 是收敛方向：它遵守生效的 `CODEX_HOME`
（默认 `~/.codex`），不写入第三方 `base_url`，而是在启动的 Codex 子进程中设置
本地 HTTP 代理和 `CODEX_CA_CERTIFICATE`。当前 Codex 0.153.x 把读取系统代理放在
`features.respect_system_proxy` 后面，因此 launcher 同时注入等价的子进程命令行
覆盖；该开关不持久化到 `config.toml`，用户显式传入同名覆盖时保持用户参数。

在已安装 Codex、但尚未生成 OAuth `auth.json` 的环境中，`saiai codex` 会在目标
`CODEX_HOME` 中创建一个仅供本地代理使用的 ChatGPT OAuth 形状占位文件，然后完成
正常配置迁移。占位 token 不代表 provider 凭证，只有本地代理正在运行且由 Gateway
替换认证时才有意义；绕过本地代理会失败。该行为让首次启动不要求用户额外执行
官方登录流程。
占位状态包含一个无签名、固定 SAIAI 虚拟声明的 ID token，使 VSCode app-server 的
`account/read` 能返回本地登录态；它不能通过 OpenAI 签名校验，也不能在绕过本地代理
时作为 provider 凭证。`last_refresh` 使用当前时间，避免客户端把这个占位状态当成
需要主动刷新真实 OAuth token 的旧登录。

启动前会先完成只读预检，然后备份并清理主 `config.toml` 及 profile 配置中的
第三方 `base_url`、`model_providers` 覆盖，将根 provider 设置为
内置 `openai`。`auth.json` 的 `auth_mode = "chatgpt"` 和 OAuth `tokens` 原样保留；
第一阶段把 `OPENAI_API_KEY` 置为空值，API-key-only 登录会被拒绝。所有备份都写在
原目录下，命名为 `.bak-<timestamp>`。

本地代理对 `api.openai.com:443` 终止 TLS 后，将 `/v1/responses` 和 `/v1/models`
的 HTTP 与 WebSocket 请求转发到 Gateway。Codex 原始方法、路径、query、JSON body、
WebSocket 帧、User-Agent、`originator`、session/thread/request id 等头保持不变；
只有代理发往 Gateway 时的 `Authorization` 使用 SAIAI Key。代理仍只监听 loopback，
用户 shell 和系统环境不变。

Desktop 可能使用 `chatgpt.com/backend-api/codex/*` 而不是
`api.openai.com/v1/*`。代理现在识别这类 managed host，并将 Responses/models
路径映射到 Gateway 的 `/v1/*` ingress；业务 body 和客户端身份 header 仍保持。
Desktop/app-server 是否信任代理 CA 仍需独立验证，不能仅凭 CLI 的
`CODEX_CA_CERTIFICATE` child 环境变量推断。

当前 launcher 只覆盖由它直接启动的 Codex CLI 子进程。Codex Desktop 和 VSCode
扩展不是该子进程，不能因为共享 `CODEX_HOME` 就推断它们已继承代理/CA 环境。
Linux Desktop 现在有独立的 `saiai desktop`（`saiai chatgpt` 别名）启动路径：
它复制现有 OAuth `auth.json` 到 SAIAI 管理的隔离 `CODEX_HOME`，为 Electron/NSS
创建独立 CA 数据库，并向 Desktop 与 app-server 注入本地代理变量。它不修改
`/home/*/.codex*` 原目录或系统信任库。没有现有 OAuth `auth.json` 时，Desktop
launcher 会明确报错；CLI 的本地代理占位 OAuth 不等价于 Desktop 的已登录状态。
launcher 同时在隔离的 `.codex-global-state.json` 中标记首次项目引导已完成，
跳过启动时的职业/个性化问卷；原始用户状态不受影响。

普通 ChatGPT Chat 的固定时区是 Desktop 子进程设置，不是全局请求改写。默认值为
`America/Los_Angeles`，也可以设置 `SAIAI_CHATGPT_TIMEZONE` 覆盖；launcher 会校验
对应的 IANA zoneinfo 文件，
只向该 Electron 子进程设置 `TZ`，并移除控制变量本身；父 shell、系统环境和
原始 `CODEX_HOME` 均不变。Desktop 会据此生成 `timezone` 与
`timezone_offset_min`。设置 `SAIAI_CHATGPT_TIMEZONE=system` 可恢复系统真实时区。
该选项目前仅影响 ChatGPT Desktop 普通 Chat，不向 Codex Responses body 强行添加
未知字段，也不用于绕过服务端客户端策略。

VSCode 使用一次性的 `saiai vscode` 配置入口，之后用户仍正常启动 VSCode 和官方
Codex 扩展。该命令复用 CLI 的 OAuth 占位、第三方 provider/base URL 清理和备份
逻辑，在 `CODEX_HOME/.env` 中写入 loopback HTTP(S) proxy、`NO_PROXY` 和
`SSL_CERT_FILE`，并在 Codex 配置中持久启用 `features.respect_system_proxy`；它不
修改 shell 或系统环境变量，也不写第三方 `base_url`。官方扩展的 Codex app-server
会读取 `.env` 中的标准代理和 `SSL_CERT_FILE`。实测 Codex 0.153.4 从 `.env` 读取
代理和 `SSL_CERT_FILE` 后，HTTP 与 WebSocket 均到达隔离本地代理；仅把
`CODEX_CA_CERTIFICATE` 写入 `.env` 则不足以建立信任，因此 IDE 路径固定使用标准
TLS 变量，CLI 子进程路径继续使用 `CODEX_CA_CERTIFICATE`。显式 VSCode
`http.proxy` 可能覆盖扩展子进程的代理变量，命令输出会提示移除冲突设置。

当前验证覆盖 Linux 官方扩展/app-server 的进程、OAuth 文件、HTTP(S) proxy、CA
信任和 WebSocket 握手路径；真正发布前仍需在 Windows/macOS runner 上验证对应
路径与用户服务生命周期。

## 更新短路径

三个 wrapper 以 `manifest.json` 为版本权威：

```text
installed hash == manifest hash
  -> 不下载二进制 -> 重新初始化 -> 刷新代理服务

installed hash != manifest hash
  -> 下载并校验 -> 原子替换二进制 -> 初始化并启动服务
```

manifest contract 为：

```json
{
  "manifest_schema": 1,
  "client_mode": "local-proxy",
  "configuration_schema_version": 1
}
```

wrapper、manifest 和六个平台二进制构成不可变 release bundle。Linux 二进制使用
静态 musl，避免旧发行版和树莓派上的 GLIBC 版本依赖。Gateway 只从当前激活目录
提供这一完整 bundle，默认下载源由可信公开 origin 动态渲染。
