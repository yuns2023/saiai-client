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
本地 HTTP 代理和 `CODEX_CA_CERTIFICATE`。Linux launcher 通过子进程命令行启用
`features.respect_system_proxy`。Windows/macOS 必须反向设置为 `false`：Codex 的
平台 resolver 优先采用 WinHTTP/IE 或 SystemConfiguration 结果，当系统返回 `DIRECT`
时不会再读取子进程 `HTTP_PROXY`/`HTTPS_PROXY`；transport-default 的
reqwest/Tungstenite 才会读取这些
变量。该开关不写入 CLI 的 `config.toml`，用户显式传入同名覆盖时保持用户参数。
同理，合成 SAIAI 身份不能认证官方 hosted Apps MCP，launcher 默认对子进程设置
`features.apps=false`，避免非模型控制面产生 `codex_apps` 451；显式用户覆盖仍优先。
Codex 0.146.0、0.153.4 和 0.154.0 默认使用 `ab.chatgpt.com` 作为 Statsig OTEL
metrics exporter。SAIAI 网络下该非模型端点可能不可达，因此 launcher 默认对子进程
设置 `otel.metrics_exporter="none"`；不改写持久配置，显式用户覆盖仍优先。

`init-codex` 在保留旧 `config.toml`/`auth.json` 直连配置的同时，也会在独立的
`SAIAI_HOME` 中创建本地代理配置和安装 CA，使同一次 WebUI 初始化之后可以直接运行
`saiai codex`。该兼容初始化不修改 Claude 配置，也不启动代理；launcher 按需启动。
旧直连 Provider 继续使用传入的 `/v1` Base URL；写入本地代理配置时只移除末尾
`/v1`，再透传客户端原始 `/v1/*` 路径，禁止形成 `/v1/v1/*`。
若已有有效的 SAIAI 代理配置，它复用原 CA、监听地址和普通 Chat 开关，只替换
Gateway 与 Key，避免破坏已经配置好的 Claude/ChatGPT 代理信任。随后 launcher
只在旧 `auth.json.OPENAI_API_KEY` 与当前 SAIAI 配置 Key 完全一致时把该旧初始化
状态升级为本地代理 OAuth 占位；不同的 API Key 或真实 ChatGPT OAuth 原样保留，
不做模糊识别。

在已安装 Codex、但尚未生成 OAuth `auth.json` 的环境中，`saiai codex` 会在目标
`CODEX_HOME` 中创建一个仅供本地代理使用的 ChatGPT OAuth 形状占位文件，然后完成
正常配置迁移。占位 token 不代表 provider 凭证，只有本地代理正在运行且由 Gateway
替换认证时才有意义；绕过本地代理会失败。该行为让首次启动不要求用户额外执行
官方登录流程。
占位状态使用 Codex 原生的 `auth_mode = "chatgptAuthTokens"`：它表示 token 由外部
宿主提供，不允许 Codex 将合成 refresh token 发往 OpenAI。占位状态包含一个无签名、
固定 SAIAI 虚拟声明的 ID token，使 VSCode app-server 的
`account/read` 能返回本地登录态；它不能通过 OpenAI 签名校验，也不能在绕过本地代理
时作为 provider 凭证。占位 refresh token 为空，`last_refresh` 仅用于保持 Codex
token 数据结构完整；禁止刷新由 auth mode 本身保证。

启动前会先完成只读预检，然后备份并清理主 `config.toml` 及 profile 配置中的
第三方 `base_url`、provider 覆盖，将根 provider 设置为内置 `openai`。为恢复
旧版 `init-codex` 创建的历史线程，清理后仅保留一个受管的
`model_providers.OpenAI` 兼容别名：它固定指向 `https://api.openai.com/v1`，使用
`wire_api = "responses"` 和 `requires_openai_auth = true`，不保留旧 Gateway、
`env_key`、静态 token 或其他用户字段。新线程仍使用内置 `openai`，旧线程的
provider ID 则通过该别名解析并继续经由 local-proxy。用户已有的真实
`auth_mode = "chatgpt"` OAuth `tokens` 原样保留；
SAIAI 创建或升级的占位状态使用 `auth_mode = "chatgptAuthTokens"`。第一阶段把
`OPENAI_API_KEY` 置为空值，API-key-only 登录会被拒绝。所有备份都写在原目录下，
命名为 `.bak-<timestamp>`。

启动器优先解析 PATH 中的原生 Codex。Linux 额外识别官方安装器默认的
`~/.local/bin/codex`，即使当前 shell 尚未重新加载 profile；Windows 同时识别原生
`codex.exe` 和 npm 的 `codex.cmd` 布局，npm 情况直接以 `node.exe` 运行官方
JavaScript launcher，避免 Rust `Command` 无法直接执行 `.cmd`。

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
Linux、macOS 和 Windows Desktop 现在有独立的 `saiai desktop`（`saiai chatgpt`
别名）启动路径。Linux 和显式 `SAIAI_DESKTOP_BIN` 的普通可执行文件使用隔离的
`CODEX_HOME`/user-data 和进程级代理/CA。官方 macOS `com.openai.codex` bundle 与
Windows `OpenAI.Codex_*!App` 包则按官方客户端相同的 `codex://threads/new` 协议
激活；协议激活由 LaunchServices/AppX broker 完成，不能继承 launcher 的临时环境，
因此这两条路径使用正常 Codex home 中的受管 `.env`、OAuth 占位和
`respect_system_proxy=false`，与 VSCode 路径共享无系统环境修改的代理合同。

Desktop 启动入口按产品 target 解析：`saiai desktop codex`、
`saiai desktop chatgpt`、`saiai desktop claude` 和 `saiai desktop gemini`。
当前 Codex/ChatGPT target 复用已验证的 OpenAI Desktop adapter；Claude/Gemini
target 先返回明确的 adapter 未实现错误。后续产品接入应实现独立 adapter，描述
可执行文件发现、认证/配置目录、profile/onboarding、TLS/代理继承、模型目录和
UI readiness；这些差异不应继续堆进一个 OpenAI 专用 launcher 分支。代理进程、
CA、profile 生命周期、日志和 doctor 检查属于共享 Desktop runtime。

macOS 会校验 bundle identifier、OpenAI Team ID `2DC432GLL2` 和 codesign，并在
激活前先请求应用正常退出，必要时才终止该 bundle 内的旧进程；进程退出后等待
LaunchServices 稳定，并用 `open -n -a` 有界重试，避免紧接退出发生 `-600`。
Windows 通过稳定的 StartApps AppID 和 AppX
InstallLocation 识别包，只停止该安装目录中的 `ChatGPT`/`Codex` 进程。两者随后
通过 `codex://` 打开当前 workspace，并确认包进程实际出现，不能再把内部 launcher
stub 的零退出码当作 UI 启动成功。它们不修改系统代理、Keychain 或系统环境。

Linux/普通可执行文件仍会把现有 OAuth `auth.json` 复制到 SAIAI 管理的隔离
`CODEX_HOME`，为 Electron/NSS 创建独立 CA 数据库（Linux），并在隔离的
`.codex-global-state.json` 中标记首次项目引导已完成。官方包路径在正常 Codex home
写入相同 onboarding 状态。没有可用 OAuth/占位 `auth.json` 时 launcher 会明确报错。

普通 ChatGPT Chat 的固定时区是 Desktop 子进程设置，不是全局请求改写。默认值为
`America/Los_Angeles`，也可以设置 `SAIAI_CHATGPT_TIMEZONE` 覆盖；launcher 会校验
对应的 IANA zoneinfo 文件，
只向该 Electron 子进程设置 `TZ`，并移除控制变量本身；父 shell、系统环境和
原始 `CODEX_HOME` 均不变。Desktop 会据此生成 `timezone` 与
`timezone_offset_min`。设置 `SAIAI_CHATGPT_TIMEZONE=system` 可恢复系统真实时区。
该选项目前仅影响 ChatGPT Desktop 普通 Chat，不向 Codex Responses body 强行添加
未知字段，也不用于绕过服务端客户端策略。

普通 Chat 协议的 Gateway 转发仍处于实验阶段，但客户端 allowlist 默认开启：
本地代理会把经过 allowlist 的
`/backend-api/f/conversation`、`conversation/init`、`f/conversation/prepare`、
`sentinel/chat-requirements/prepare`、`files/download/{file_id}` 和
`estuary/content` 路径转成带有 `/chatgpt/` 命名空间的 Gateway 路径。图片/文件
指针解析依赖 `files/download/{file_id}` 返回官方的
`download_url`/`retry`/`error` JSON，再通过 `estuary/content` 获取图片字节；这两类
control-plane/asset 请求不应被当作 Responses 或模型请求计费。`SAIAI_CHATGPT_CHAT_PASSTHROUGH=0`
仅作为当前代理进程的紧急关闭开关。
该路径不会把请求转换为 Responses；Gateway 仍以独立 feature flag 和计费保护决定
是否允许最终 Chat 模型请求。旧 Gateway 上普通 Chat 仍不可用，但现有 Desktop
Codex、CLI 和 VSCode 路径不受影响。

VSCode 使用一次性的 `saiai vscode` 配置入口，之后用户仍正常启动 VSCode 和官方
Codex 扩展。该命令复用 CLI 的 OAuth 占位、第三方 provider/base URL 清理和备份
逻辑，在 `CODEX_HOME/.env` 中写入 loopback HTTP(S) proxy、`NO_PROXY` 和
`SSL_CERT_FILE`，并按同一平台规则在 Codex 配置中写入
`features.respect_system_proxy`（Linux 为 `true`，Windows/macOS 为 `false`）；它不
修改 shell 或系统环境变量，也不写第三方 `base_url`。官方扩展的 Codex app-server
会读取 `.env` 中的标准代理和 `SSL_CERT_FILE`。实测 Codex 0.153.4 从 `.env` 读取
代理和 `SSL_CERT_FILE` 后，HTTP 与 WebSocket 均到达隔离本地代理；仅把
`CODEX_CA_CERTIFICATE` 写入 `.env` 则不足以建立信任，因此 IDE 路径固定使用标准
TLS 变量，CLI 子进程路径继续使用 `CODEX_CA_CERTIFICATE`。显式 VSCode
`http.proxy` 可能覆盖扩展子进程的代理变量，命令输出会提示移除冲突设置。

当前验证覆盖 Linux 官方扩展/app-server 的进程、OAuth 文件、HTTP(S) proxy、CA
信任和 WebSocket 握手路径。macOS runner 覆盖 LaunchAgent、Info.plist executable
解析和普通 Desktop 子进程合同；真实签名 `Codex.app` 的协议激活、TLS、登录控制面
和模型请求仍必须在隔离测试 Gateway 上实测。Windows runner 验证原生编译、普通
Desktop 子进程合同和 updater；真实 `OpenAI.Codex_*!App` 的协议激活、`.env`
加载、TLS、登录控制面和模型流量同样需要现场闭环。

Windows wrapper 替换已安装客户端时，先让客户端用 `/T /F` 停止其 PID 文件指向的
后台进程树，并等待该 PID 消失，再在安装目录内用原子 `File.Replace` 替换可执行
文件。目标存在时不使用 `Move-Item -Force`；替换失败时保留旧文件，并仅在更新前
确实运行过后台代理时尝试恢复它。

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
