# SAIAI managed local-proxy client design

## 目标

`saiai` 为 Claude Code、VSCode 和新的 `saiai codex` 启动路径提供用户级托管本地
代理，同时保留旧的 Codex CLI 直接配置。WebUI 的一行命令完成安装、配置并启动代理；用户也可以用
`saiai start/stop/status/logs/restart` 管理服务，或直接运行 `saiai` 使用前台模式。

稳定边界：

- 代理只监听 loopback。首次初始化会分配一个可用的随机 loopback 端口并持久化到
  `SAIAI_HOME/config.json`；重复初始化在端口仍由 SAIAI 管理时复用它，被其它进程占用
  时重新分配。
- 不创建隔离 home 或 generation，也不调用 Gateway bootstrap。
- 初始化、doctor 和 release 验证不发送模型请求。
- 同一命令可重复执行；新 Base URL/Key 覆盖旧值。
- 无关用户配置和机器身份值必须保留。
- 每个用户使用独立生成的 CA；release 中不得包含 CA 私钥。

## 1.1.34 发布候选边界

本候选包含可选 Claude 环境恢复启动器、Windows Desktop 安全实例检查修复，以及
默认 VSCode Codex 控制面配置，
保持 `local-proxy`、manifest schema 1 和 configuration schema 1，不改变正常 Claude
启动方式。合并主线、生成候选包和正式站激活是三个独立步骤；
本文不表示下载站已切换版本。完整包必须来自同一源码的
成功 Actions run，包含六个平台二进制、三种 wrapper 和 manifest；不混入手工开发资产。

本候选补齐 Desktop 26.930 版本化账户响应的成员角色和隐私标记，
通过官方解析器的离线验证。此项修复还需独立原生 UI 验收，不能据此宣称普通 Chat
或 imagegen 已通过。

Codex 0.160.0 的独立内置 `image_gen` 使用
`/backend-api/codex/images/generations` 和 `/backend-api/codex/images/edits`。
代理将其分别路由到 Gateway 的 `/v1/codex/images/*`，保持 JSON、编码、query 和应用头；
Gateway 必须实现这两个原生端点并透传到选定 OAuth 账号。此路径不经过公开 Images API
到 Responses 的适配器，也不等同于普通 Chat 的文件下载流程。必须按兼容的完整
Server/Client 组合验收后激活，不能仅凭 schema 相同把本客户端提前部署到旧 Gateway。

本次候选保留已验证的 Codex HTTP/WS 重复应用头与原始 query/body 透传修复，
补上隔离实验开关下普通 Chat 的原生模型目录路径。Gateway 必须同时支持该精确
目录路由；这项实验能力不改变正常 Codex 入口或普通 Chat 的验收范围。

Desktop 的历史保全、MCP 就绪和交互窗口验收必须单独记录，app-server 自动测试不等于
完整原生界面验收。普通 Chat、ChatGPT 侧栏和设置不在支持范围内，不作为已实现能力。
打正式标签前须通过精确源码的完整 CI；测试站和生产激活前须分别记录精确
manifest/文件哈希、验收结果及完整旧包回滚路径，并获得相应授权。

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
它不提供 UDP 转发；对普通目标的明文 HTTP absolute-form 请求按直接代理处理，
不得误送入 OpenAI/Anthropic 的 TLS MITM 路由。由于该接口不认证且
可访问任意目标，代理核心必须强制只监听 loopback，不能仅依赖初始化器生成的默认
地址。Gateway Key 由代理从私有配置读取，程序不会把 Key 打印到输出或请求日志。

### 可选的 Claude 环境恢复启动器

`saiai claude [-- <claude arguments>]` 用于用户 shell 或系统继承环境存在旧
Base URL、认证或 proxy/CA 配置时启动官方 Claude Code。它不是新的默认入口：正常
`claude`、初始化、一键 wrapper、用户服务与 VSCode 流程保留原样。

启动器先解析官方 Claude 可执行文件、读取已有 SAIAI Claude 路由并校验本地 CA，
确保 loopback 代理运行；然后只在 Claude 子进程中替换环境：

- Base URL 固定为官方 `https://api.anthropic.com`，流量经现有本地代理转到
  SAIAI Gateway，不直接把 Gateway URL 写入 Claude。
- `CLAUDE_CODE_OAUTH_TOKEN` 使用已配置的 Claude 路由 Key；移除继承的
  `ANTHROPIC_AUTH_TOKEN`、API-key/descriptor、云 provider 等冲突来源。
- 设置大小写 HTTP/HTTPS/ALL proxy 和本地 NO_PROXY、`NODE_EXTRA_CA_CERTS`、
  `CLAUDE_STREAM_IDLE_TIMEOUT_MS=600000`，移除继承的旧 CA、mTLS 与跳过证书校验值。
- 保留原 `HOME`、`CLAUDE_CONFIG_DIR`、工作目录、模型选择及其他无关环境。

不调用初始化，不改写 settings、state 或 credentials，不创建隔离目录，不修改
父进程/系统环境，也不设置 `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST=1`、注入
`--settings` 或禁用 `apiKeyHelper`。用户/项目/managed settings 仍按官方规则生效；
若它们显式指定另一条路由或认证来源，本入口不会强制接管。
已有代理会复用；未运行时可以按现有服务逻辑启动，但不能用模型请求做预检。

Unix 使用进程替换以保留交互、退出码和信号行为；Windows 等待官方子进程并返回
其退出码。启动提示写入 stderr，避免污染 `-p --output-format json` 的 stdout。
Windows npm 安装通过 Node 直接运行已安装的官方 `cli.js`，不拼接用户参数到 shell。

发布校验按实际入口与行为区分此可选启动器和已撤回的 V2：仍禁止 V2 runtime、
bootstrap、旧 setup/revoke 等路径，同时要求现有 local-proxy/OAuth、子进程环境
隔离、原 profile/模型保留、参数透传及无凭据诊断输出。负向测试、子进程回归与
原初始化/服务测试共同约束该入口，不用放宽 manifest 或配置 schema 来绕过检查。
这些是开发候选的校验规则，不表示新增入口已发布或 Desktop 原生验收已完成。

## 用户服务

- Linux 优先使用 `systemd --user`。如果当前用户的 systemd user bus 不可用
  （常见于 root、容器和无登录会话），`start` 自动改用脱离终端的托管后台进程；
  `stop/status/logs/restart/doctor` 识别同一状态。状态文件记录 PID 与
  `/proc` 启动时间并复核隐藏 worker 参数，避免 PID 复用或 `exec` 后误杀其他
  进程。状态和日志权限为 `0600`。该 fallback 不提供跨宿主重启或崩溃自动拉起。
- macOS 使用用户 LaunchAgent；服务管理直接调用系统自带的 `/bin/launchctl`，
  日志跟随使用 `/usr/bin/tail`，不以不兼容的 GNU `--version` 参数探测命令。
- Windows 使用用户进程与 PID/日志状态文件，不要求管理员权限。

`init` 与 `init-codex` 都会在成功写入配置后启动或刷新同一个受管本地代理；因此
无论初始化前服务是否存活，都不会留下已停止的旧代理。自动化测试或明确需要只配置
不启动时可设置 `SAIAI_SKIP_START=1`。一键 wrapper 只调用原生命令，避免额外的第二次
服务重启。

重复运行且本次未替换 CLI 二进制时，初始化会比较最终代理运行时配置（Gateway、Key、
监听地址、CA 和 provider 路由）。若配置未变化、受管服务仍存活且当前 loopback
监听可连接，则保留原进程，不中断已建立的代理连接；只继续更新 Claude/Codex 的用户
配置。配置变化、wrapper 替换二进制、服务缺失或监听不可达时才刷新服务。该判断在
Linux、macOS 与 Windows 共用；各平台只在真正需要刷新时调用其 systemd/LaunchAgent/
后台进程实现。
发布前在 Intel 和 Apple Silicon macOS runner 上分别验证
`start/status/logs/restart/stop` 的真实 LaunchAgent 生命周期；两个 Linux 静态
资产也必须在强制 `systemctl --user` 失败的环境中完成同一套 fallback 生命周期。

## Codex 启动与配置

`init-codex <base_url> <api_key> [--websockets]` 是 Codex 的标准 OAuth/local-proxy
初始化入口；`--websockets` 仅为旧 WebUI 命令形状保留，代理本身默认支持 HTTP 与
WebSocket。`saiai codex [-- <codex arguments>]` 遵守生效的 `CODEX_HOME`
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

`init-codex` 在独立的 `SAIAI_HOME` 中创建或更新本地代理配置和安装 CA，并同步
`CODEX_HOME/.env` 的 loopback port、`SSL_CERT_FILE` 和 `NO_PROXY`，使同一次 WebUI
初始化后可直接启动 CLI 与 VSCode app-server。Linux 还会将安装 CA 刷新到当前用户
`~/.pki/nssdb` 的唯一 `saiai-local-proxy` 条目，以让直接启动的 Electron Desktop
信任 loopback MITM；这不写系统信任库，也不触发系统弹窗。该用户级信任会影响同一
用户使用该 NSS 数据库的应用，因此命令输出会明确披露它；缺少 `certutil`
（`libnss3-tools`）时，CLI/VSCode 初始化照常完成，但直接 Desktop 必须改用
`saiai desktop codex`。它不修改 Claude 配置，并会启动或刷新受管本地代理。输入
URL 可以带或不带末尾 `/v1`；本地代理配置只记录 Gateway root，避免转发时形成
`/v1/v1/*`。
初始化会备份后清理旧的 `config.toml` `base_url`、自定义 provider 与 API-key-only
auth；根 provider 固定为内置 `openai`，不保留 `model_providers.OpenAI` 历史线程
兼容别名。SAIAI 不管理根 `model`、`review_model`、`model_reasoning_effort` 或模型
上下文预算。有效的用户 CA、监听地址和既有兼容字段会复用，只替换 Gateway 与 Key；
已有真实 ChatGPT OAuth 原样保留，API-key-only auth 会迁移为本地代理 OAuth 占位。

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
token 数据结构完整；禁止刷新由 auth mode 本身保证。Desktop 显示的账户邮箱是
 `saiai-local-proxy@example.invalid`，仅表示本地代理身份，不是用户的真实邮箱。

启动前会先完成只读预检，然后备份并清理主 `config.toml` 及 profile 配置中的
第三方 `base_url`、provider 覆盖，将根 provider 设置为内置 `openai`。不再保留
旧直连 provider 或其历史线程兼容别名。用户已有的真实
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
WS 应用头的同名多值按原顺序保留，不用后一个值覆盖前一个值。WS 与 HTTP
采用相同的 Gateway 鉴权边界，移除入站 Cookie 并替换 Authorization；连接与
长度等逐跳字段由各段传输处理。WS 上游未启用压缩 codec，因此不透传
`Sec-WebSocket-Extensions`。101 返回中的安全应用头和同名多值也原样保留，
握手 accept/framing 由本地连接重建，Cookie/鉴权等敏感返回头不回传。
请求中的 `Connection` 指定的逐跳头在本地代理这一跳移除，避免丢弃
`Connection` 后把对应的头误当作应用头继续发送。HTTP/WS 均覆盖此边界。
这些规则用合成凭据、本地 WS 握手及 Server 的可选官方二进制逐跳测试验证。
代理发往 Gateway 时的 `Authorization` 使用 SAIAI Key。代理仍只监听 loopback，
用户 shell 和系统环境不变。

Desktop 可能使用 `chatgpt.com`、`chat.openai.com` 或 `ab.chatgpt.com` 的
`/backend-api/codex/*`，而不是 `api.openai.com/v1/*`。代理将这些 managed host 的 Responses/models
路径映射到 Gateway 的 `/v1/*` ingress；业务 body 和客户端身份 header 仍保持。
Desktop/app-server 的 CA 信任必须独立验证，不能仅凭 CLI 的
`CODEX_CA_CERTIFICATE` child 环境变量推断。Linux ChatGPT Desktop 26.901.51231 /
Codex app-server 0.153.4 已实测：用户 NSS 导入后账户控制面从 CA 错误恢复。Desktop
还会向 `ab.chatgpt.com/v1/initialize` 发送 Statsig beta-eligibility 请求；它不是
Gateway 的 OpenAI `/v1/initialize` 契约，也不是模型流量。本地代理只对精确的
`POST /v1/initialize` 返回版本化的本地 Statsig bootstrap，并在
`/backend-api/wham/statsig/bootstrap` 返回同一 payload。该 payload 只启用 Codex
已内置消息包所需的 `72216192.enable_i18n`，不启用其他 hosted experiment，不携带
SAIAI Key，也不把合成账户、Cookie 或请求体发往 Statsig/Gateway；非 POST 和超过
1 MiB 的请求会被拒绝。账户 sidecar 同时覆盖带 `/backend-api` 前缀和新版 Electron
直接请求的 `/accounts/optimized/check`、`/wham/accounts/check` 与
`/wham/statsig/bootstrap`；账户条目返回
`workspace_backend_origin=NO_CONSTRAINT` 和
`account_routing_override=NO_CONSTRAINT`，满足 Codex app-server 0.155+ 的工作区路由
发现合同，同时保留当前有效 ChatGPT origin，不施加区域路由。新版 Desktop 的
`/backend-api/accounts/check/v4-2023-04-27` 必须返回版本化账户集合，不能用
HTTP 200 加空对象代替：Renderer 会读取 `account_ordering.map`，形状错误时仍会
出现 “ChatGPT hit a snag”。Desktop 26.930 的完整成员信息解析还要求
`account_id`、`account_user_id`、`account_user_role`、`structure`、`plan_type`
和布尔型 `is_zdr`；本地响应须与已有 wham 的个人账户角色和隐私标记一致。
不得把
成功的账户查询或目录加载宣称为完整 Desktop 模型支持；未做模型请求的验证前，
`saiai desktop codex` 仍是受支持的隔离回退路径。

Client 候选包发布前可运行
`scripts/saiai-cli/probe-installed-codex-desktop.py`。它在 Windows/macOS 测试机上
复制已安装官方 Desktop 随附的 app-server 到临时目录，以隔离的
`HOME`/`CODEX_HOME`/`SAIAI_HOME`、临时 CA、合成登录和 loopback Gateway 验证
`initialize`、`getAuthStatus` 与 `account/read`。探针不启动 turn，不发送模型请求，也不改写用户现有
Codex/SAIAI 配置；结果只保留版本、二进制哈希和脱敏控制面状态。它不运行
Electron Renderer，不能证明主窗口正常。候选包还须在目标 Windows 用户的交互式
会话中启动已安装的官方 Desktop，确认主窗口加载、无 Renderer 异常；同时记录实际
AppX 包版本、候选二进制哈希和脱敏结果。不要用 SSH Session 0 截图、成功的
`/v1/models` 或 `account/read` 代替这一步。系统升级可能直接删除旧 AppX 包，
先确认可恢复路径，不要假设本机仍能回退旧版。

当前 launcher 只覆盖由它直接启动的 Codex CLI 子进程。Codex Desktop 和 VSCode
扩展不是该子进程，不能因为共享 `CODEX_HOME` 就推断它们已继承代理/CA 环境。
Linux、macOS 和 Windows Desktop 现在有独立的 `saiai desktop codex` 启动路径。
Linux、macOS 和显式 `SAIAI_DESKTOP_BIN` 的普通可执行文件使用隔离的
`CODEX_HOME`/user-data 和进程级代理/CA。对于官方 macOS `com.openai.codex` bundle，
launcher 先以隔离 home、loopback 代理和当前 SAIAI 叶证书的 SPKI pin 启动 bundle
executable，再用 `codex://threads/new` 激活窗口；pin 仅适用于该子进程，不会修改
Keychain、系统代理或系统环境。Windows `OpenAI.Codex_*!App` 必须通过 AppX broker
激活，直接运行 WindowsApps 中的主程序会失去包身份。Windows launcher 将当前
workspace 的 `codex://threads/new` URL、loopback proxy 以及 SPKI pin 作为激活参数
传入。Windows 商店版使用包默认 Electron user-data；通知回复等系统再次激活不会携带
SAIAI 的启动参数，必须复用同一数据目录和已有的代理进程，否则会另起未代理的窗口并
把本地占位令牌送到 ChatGPT，得到 401。broker 不继承 launcher 的子进程环境，因此 Windows
商店版使用当前用户的标准 Codex profile；启动前要求该 profile 的受管 `.env` 与当前
代理和 CA 一致，不能保证自定义 `CODEX_HOME` 或子进程时区覆盖。Linux、macOS 与
普通可执行文件仍使用隔离 Codex profile：从普通 profile 复制真实 OAuth 前检查
可解析 JWT 的 `exp`；已过期的 access token 不复制，也不触发 refresh，而在隔离
profile 中使用外部 `chatgptAuthTokens` 占位状态。普通 profile 的原始凭据文件保持不变。
Windows 正常启动不修改 HKCU 系统代理、Windows 系统环境或
`CurrentUser\Root`；若检测到旧版本遗留的 proxy lease，只按 marker 所有权恢复旧值、
删除该 lease 安装的证书并移除 marker。
Linux 隔离启动器改写子进程 `HOME` 以避免复用正常 Codex state。若当前 X11 会话未
导出 `XAUTHORITY`，它仅把调用用户现有且可读的 `~/.Xauthority` 路径传给该子进程；
不会复制、修改或写入该文件。这样 Electron 仍可连接已有 X server，而隔离 home、
Codex state 和 user-data 保持独立。

Desktop 当前只接受 `saiai desktop codex`。官方应用的壳层仍可能显示“ChatGPT”以及
其左栏，但普通 ChatGPT 会话、历史、语言、设置、插件和图片/文件 UI 不属于 SAIAI
Desktop 合同。Desktop 26.924 的通知页会对 `/notifications/settings` 的返回值直接调用
`settings.map()`；通用 `200 {}` 会使 Renderer 显示“ChatGPT hit a snag”，HTTP 501
则令页面持续加载重试。本地代理对该精确路径（含 `/backend-api` 前缀）的 GET 返回
`{"settings":[]}`，表示本地身份没有托管 ChatGPT 通知类别；修改请求仍返回 501，
不会伪造或接受通知偏好。`saiai desktop chatgpt`、Claude 和 Gemini target 都会明确拒绝。Codex
启动器一律用 `codex://threads/new` 激活，并把模型目录、Responses HTTP/WS 与登录
控制面作为独立验证面。后续产品接入必须实现独立 adapter，描述可执行文件发现、认证/
配置目录、profile/onboarding、TLS/代理继承、模型目录和 UI readiness；这些差异不应
继续堆进一个 OpenAI 专用 launcher 分支。代理进程、CA、profile 生命周期、日志和
doctor 检查属于共享 Desktop runtime。

隔离实验开关 `SAIAI_CHATGPT_CHAT_PASSTHROUGH=1` 的普通 Chat allowlist 包括
`/backend-api/models`，映射到 Gateway 的 `/chatgpt/backend-api/models`，保留原始
query 并透传原生目录内容。它与 Codex `/backend-api/codex/models` 是不同协议，
不得互换或从 Codex 目录合成普通 Chat 选项。该实验路径需要可调度的 OpenAI OAuth
账号；只有 API-key 账号时应明确失败且不占用其并发槽。这个精确目录修复不表示
普通 Chat 的全部界面、账号能力与图片工具已经完成验收。

macOS 会校验 bundle identifier、OpenAI Team ID `2DC432GLL2` 和 codesign，并在
激活前先请求应用正常退出，必要时才终止该 bundle 内的旧进程；进程退出后等待
LaunchServices 稳定，并用 `open -n -a` 有界重试，避免紧接退出发生 `-600`。
Windows 通过稳定的 StartApps AppID、AppX InstallLocation、Store 发布者及实际
签名识别包。开发中的 packaged 启动路径不再强制停止现有 Desktop：先检查同一
用户/交互会话的真实窗口、PID/启动时间、签名包版本、标准 `.codex`、本地代理、
CA 摘要和进程启动 SPKI 参数，再与受管启动记录及运行代理的公开 SPKI 绑定核对。
匹配则复用；未知、隐藏、旧版本、证书变化或记录不完整的实例要求用户正常
`File > Quit` 后重试，不静默重启、收养或改写其配置。正在运行但代理不可用时
也不会自动重启代理来重新绑定该窗口。
锁和不含 Key/OAuth 凭据的 schema-1 实例记录位于 Windows Known Folder 的
`LocalAppData/SAIAI/desktop-runtime`，对当前用户限制 ACL，所有 `SAIAI_HOME`
共用此锁。缺失的 runtime 目录在创建时显式指定当前用户 SID 和不继承的私有 ACL，
避免管理员令牌的默认组所有者导致冷启动误拒绝；既有外来所有者和 reparse point
仍拒绝，不能把管理员组成员资格当成实例所有权。ACL 写入使用 .NET 的
`Directory.SetAccessControl`，只更新受管所有者和访问规则，不使用会要求
`SeSecurityPrivilege` 的 PowerShell `Set-Acl`；普通权限终端不需要提权。
目录权限初始化失败独立报告，不再误报为运行中 Desktop 的实例复用拒绝。
其 Windows PowerShell 子进程独立初始化 `PSModulePath`，不继承调用方 PowerShell 7
的模块搜索路径；这不修改父进程或 Windows 系统环境。
只在确认冷启动窗口后写入记录；
复用不重写记录或用户历史。冷启动仍通过 `codex://threads/new` 打开当前 workspace；
已验证的实例复用只发送相同的 proxy/SPKI 激活参数，不再次发送新建对话链接，以保留
当前页面并避免重复排队的文件夹信任弹窗。不自动信任文件夹，用户仍自行取消或确认。
Windows
激活返回的临时 broker PID 不作为成功依据，成功要求真实签名窗口及其启动身份
保持一致。该改动尚未发布，替代激活实验通过不等于新客户端已完成原生验收；
仍需新候选的冷启动/复用/未知实例无副作用、实际通知/协议路由与原历史回归。
macOS 经 LaunchServices、Windows 冷启动经包 AppID 激活打开当前 workspace，并确认主程序
实际出现，不能把内部 launcher stub 的零退出码当作 UI 启动成功。它们不修改系统代理、
Keychain、Windows 用户根证书或系统环境。

`saiai desktop` 的 Linux/macOS/普通可执行文件会把现有 OAuth `auth.json` 复制到 SAIAI
管理的隔离 `CODEX_HOME`，为 Electron/NSS 创建独立 CA 数据库（Linux），并在隔离的
`.codex-global-state.json` 中标记首次项目引导已完成。macOS 不会从 Linux NSS 推导
Keychain 行为，也不会静默安装用户信任根：2026-09-15 在 macOS 15.3.1 / ChatGPT Desktop
26.908.70816 的现场验证中，非交互 `security add-trusted-cert` 被 macOS 以“需要用户交互”
拒绝；没有该信任根的 direct `open -a ChatGPT` 在 15 秒启动观测中未到达 Codex 模型目录。相同环境的
`saiai desktop codex` 以进程级 SPKI pin 启动后到达了模型目录（未发送模型请求）。因此 direct
官方 App 仅在用户已明确授权登录 Keychain 信任 SAIAI CA 时才可能成立，且仍需按版本现场验证；
否则支持的无弹窗路径是 `saiai desktop codex`。没有可用 OAuth/占位 `auth.json` 时 launcher
会明确报错。

`init-codex` 和 `saiai desktop codex` 都会幂等设置 Desktop 私有状态
`composer-permission-mode-visibility=true`，避免旧 Windows profile 隐藏可用权限模式；
该状态只控制 selector 可见性，不选择模式、不修改 approval/sandbox，也不授予 Full
Access。修改既有 Desktop state 前会备份，其他 atom 和用户状态保持不变。

普通 Chat 协议的现有 allowlist 只保留为未发布研究代码，不能当作 Desktop 产品支持。
它没有会话历史或语言偏好持久化合同，也不能因 Codex 的模型目录通过就推断可用。
支持入口拒绝 `saiai desktop chatgpt`，普通 Chat 后续若恢复必须独立完成账户、历史、
偏好、模型、资产、计费和多账户亲和性验证，不能与 Codex Desktop 共用“已支持”结论。

`init-codex` 默认配置 VSCode，不新增 launcher、模式选择或隔离用户目录；之后用户
仍正常启动 VSCode 和官方 Codex 扩展。已有 `saiai vscode` 仅保留为无需再次传入
Gateway/Key 的修复与刷新入口，不是新增的必选操作。两者复用 OAuth
占位、第三方 provider/base URL 清理和备份逻辑，在 `CODEX_HOME/.env` 中写入当前
loopback HTTP(S) proxy、`NO_PROXY` 和
`SSL_CERT_FILE`，并按同一平台规则在 Codex 配置中写入
`features.respect_system_proxy`（Linux 为 `true`，Windows/macOS 为 `false`）；它不
修改 shell 或系统环境变量，也不写第三方 `base_url`。官方扩展的 Codex app-server
会读取 `.env` 中的标准代理和 `SSL_CERT_FILE`，但扩展宿主自己的 Node HTTP 请求
不会因此继承该文件。实测 Codex 0.153.4 从 `.env` 读取
代理和 `SSL_CERT_FILE` 后，HTTP 与 WebSocket 均到达隔离本地代理；仅把
`CODEX_CA_CERTIFICATE` 写入 `.env` 则不足以建立信任，因此 IDE 路径固定使用标准
TLS 变量，CLI 子进程路径继续使用 `CODEX_CA_CERTIFICATE`。

默认初始化还检查已有标准 VSCode、portable 与 VSCode Server 用户设置目录。
Windows 运行时定位兼容传统安装目录及官方 `bin/code.cmd` 指向的版本化资源目录；
读取的是当前 launcher 的版本，不猜测残留版本或执行该批处理文件。
没有发现目录时不创建一个新的编辑器 profile，也不影响 Codex CLI 初始化。在写入
编辑器配置前，用已安装编辑器的 Node runtime 和 `@vscode/proxy-agent` 检查当前
SAIAI CA 是否被其证书加载器识别；该检查不启动 GUI、不改信任库、不读取 OAuth，
也不发送网络或模型请求。检查失败时不改 VSCode 设置，并明确报告编辑器配置未完成；
CLI 已完成的初始化保持可用。Linux NSS 的 Desktop 信任不能证明 Node 证书加载器
已信任 CA，不能绕过这项检查。自定义安装路径、未知证书加载器和新版变化应失败关闭，
不能通过 `http.proxyStrictSSL=false` 或 `NODE_TLS_REJECT_UNAUTHORIZED=0` 解决。

检查通过后，在原有 `settings.json` 中设置 `http.proxy`、`http.proxySupport=override`、
`http.fetchAdditionalSupport=true`、`http.systemCertificates=true`、
`http.systemCertificatesNode=false` 和 `http.proxyStrictSSL=true`。
缺失或空的 `http.noProxy` 会补为 localhost、本机 loopback 和 `.local`，避免扩展宿主
继承全局 `NO_PROXY=*` 而绕过已配置的代理；已有非空且不排除 Codex 的列表保持不变。
这使用编辑器原生机制覆盖扩展宿主控制面请求，不改官方扩展代码、shell 环境或系统代理。
原有 JSONC 注释、尾逗号、其他设置和历史目录保持不变；变更先备份，重复初始化无变更
时不重新写入。代理端口变化仅更新 SAIAI 注释标记仍与当前值一致的受管配置；已有不同的
显式代理、用户改过的受管代理、禁用 TLS 校验、排除 ChatGPT 的 `http.noProxy`、重复键、
无效 JSONC 和 symlink 设置均不被强行覆盖。多个配置文件在写入前统一预检。

这是 **VSCode 整体**的代理设置，不是仅限 Codex 的扩展设置；其他扩展会共享该路由。
SAIAI 现有非托管 HTTPS CONNECT 行为仍是直连隧道，不能据此宣称保留了用户原有上游
代理或所有扩展的网络语义。初始化输出必须披露影响范围；不能静默替换另一个显式代理。
初始化后要求完整退出并重新打开编辑器，窗口 reload 不能代替启动期环境与证书缓存刷新。
`doctor codex` 只读检查编辑器配置和同一证书加载器，不把这些检查当作真实 UI、MCP、
历史或模型请求的验收。

VSCode 1.140.0 / Codex 扩展 26.5930.51102 / app-server 0.160.0 的 macOS 原生
Node runtime 已验证本地控制面读取：加载器的传统模式识别安装 CA，经过本地代理的
账户检查和任务列表返回 200。该环境的 Node system-certificates 模式没有识别同一 CA，
因此固定使用已验证的传统加载器；不意味着更改系统信任，也不意味着所有版本完全兼容。
这仍是网络机制验证，不是完整 VSCode Webview 对照；默认流程候选在原生界面、历史、
MCP、其他扩展和 Linux/Windows 证书信任闭环完成前不得宣称全部验收或发布。

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

Windows 上正在运行的 `saiai.exe` 不能覆盖自身。`saiai update` 因此启动独立
helper，在原进程退出后自动替换、保留带时间戳的备份并按需刷新服务；用户不应运行
`.saiai-update-*.exe` 临时文件。命令只报告 `staged`，下一次 `saiai --version` 才是
替换完成的确认。

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

### Linux 随机数兼容性

Linux musl 资产通过 `scripts/saiai-cli/build-linux.sh` 构建。构建机需安装
`musl-tools` 和 `linux-libc-dev`；脚本只向 musl 暴露 Linux UAPI 头文件，
不混入宿主 glibc 头文件。AWS-LC 必须选中支持 `getrandom` 返回 `ENOSYS`
时回退到 `/dev/urandom` 的 Linux 实现。缺少 `linux/random.h` 会使其选择
无此回退的 `getentropy` 实现，可能导致 TLS 握手期间进程直接终止。

CI 和 release 对两种 Linux 架构运行 `test-linux-entropy.py`：仅在测试进程
及其子进程中用 seccomp 将 `getrandom` 返回值设为 `ENOSYS`，验证初始化、
后台代理、doctor 的本地 TLS 握手及服务生命周期。该测试不改变宿主策略，
不发送模型请求，也不代表已验证旧内核的所有系统调用兼容性。系统随机数源
必须正常可用；不得通过固定随机数、忽略失败或禁用 TLS 校验来规避错误。

Windows MSVC 的两种 release 目标使用 `/Brepro`，避免链接时间戳和调试标识
导致相同源码的 preview/tag 构建产生不同字节。正式 Release 的完整 manifest
必须与实机验证过的 preview 一致；哈希不同的构建不能复用验证凭据。
