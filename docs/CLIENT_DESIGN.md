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
只有代理发往 Gateway 时的 `Authorization` 使用 SAIAI Key。代理仍只监听 loopback，
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
发现合同，同时保留当前有效 ChatGPT origin，不施加区域路由。不得把
成功的账户查询或目录加载宣称为完整 Desktop 模型支持；未做模型请求的验证前，
`saiai desktop codex` 仍是受支持的隔离回退路径。

Client 候选包发布前可运行
`scripts/saiai-cli/probe-installed-codex-desktop.py`。它在 Windows/macOS 测试机上
复制已安装官方 Desktop 随附的 app-server 到临时目录，以隔离的
`HOME`/`CODEX_HOME`/`SAIAI_HOME`、临时 CA、合成登录和 loopback Gateway 验证
`initialize`、`getAuthStatus` 与 `account/read`。探针不启动 turn，不发送模型请求，也不改写用户现有
Codex/SAIAI 配置；结果只保留版本、二进制哈希和脱敏控制面状态。

当前 launcher 只覆盖由它直接启动的 Codex CLI 子进程。Codex Desktop 和 VSCode
扩展不是该子进程，不能因为共享 `CODEX_HOME` 就推断它们已继承代理/CA 环境。
Linux、macOS 和 Windows Desktop 现在有独立的 `saiai desktop codex` 启动路径。
Linux、macOS 和显式 `SAIAI_DESKTOP_BIN` 的普通可执行文件使用隔离的
`CODEX_HOME`/user-data 和进程级代理/CA。对于官方 macOS `com.openai.codex` bundle，
launcher 先以隔离 home、loopback 代理和当前 SAIAI 叶证书的 SPKI pin 启动 bundle
executable，再用 `codex://threads/new` 激活窗口；pin 仅适用于该子进程，不会修改
Keychain、系统代理或系统环境。Windows `OpenAI.Codex_*!App` 不再通过 AppX broker
启动第二套无法继承环境的进程；launcher 直接运行包内主程序，把当前 workspace 的
`codex://threads/new` URL 作为该子进程参数，并使用隔离的 `CODEX_HOME` 与 user-data。
从普通 Codex profile 复制真实 OAuth 前会在本地检查可解析 JWT 的 `exp`；已经过期的
access token 不会复制，也不会触发 refresh，而由 Desktop 隔离 profile 使用外部
`chatgptAuthTokens` 占位状态。普通 profile 的原始凭据文件保持不变。
loopback proxy、标准 TLS 环境和四个受管 OpenAI/ChatGPT 叶证书的 SPKI pin 只注入该
Desktop 进程树。正常启动不修改 HKCU 系统代理、Windows 系统环境或
`CurrentUser\Root`；若检测到旧版本遗留的 proxy lease，只按 marker 所有权恢复旧值、
删除该 lease 安装的证书并移除 marker。
Linux 隔离启动器改写子进程 `HOME` 以避免复用正常 Codex state。若当前 X11 会话未
导出 `XAUTHORITY`，它仅把调用用户现有且可读的 `~/.Xauthority` 路径传给该子进程；
不会复制、修改或写入该文件。这样 Electron 仍可连接已有 X server，而隔离 home、
Codex state 和 user-data 保持独立。

Desktop 当前只接受 `saiai desktop codex`。官方应用的壳层仍可能显示“ChatGPT”以及
其左栏，但普通 ChatGPT 会话、历史、语言、设置、插件和图片/文件 UI 不属于 SAIAI
Desktop 合同；`saiai desktop chatgpt`、Claude 和 Gemini target 都会明确拒绝。Codex
启动器一律用 `codex://threads/new` 激活，并把模型目录、Responses HTTP/WS 与登录
控制面作为独立验证面。后续产品接入必须实现独立 adapter，描述可执行文件发现、认证/
配置目录、profile/onboarding、TLS/代理继承、模型目录和 UI readiness；这些差异不应
继续堆进一个 OpenAI 专用 launcher 分支。代理进程、CA、profile 生命周期、日志和
doctor 检查属于共享 Desktop runtime。

macOS 会校验 bundle identifier、OpenAI Team ID `2DC432GLL2` 和 codesign，并在
激活前先请求应用正常退出，必要时才终止该 bundle 内的旧进程；进程退出后等待
LaunchServices 稳定，并用 `open -n -a` 有界重试，避免紧接退出发生 `-600`。
Windows 通过稳定的 StartApps AppID 和 AppX InstallLocation 识别包，只停止该安装
目录中的 `ChatGPT`/`Codex` 顶层进程；不会递归终止可能共享系统宿主的包内辅助进程。
macOS 经 LaunchServices、Windows 经直接子进程参数打开当前 workspace，并确认主程序
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

`init-codex` 已完成 VSCode 所需配置，之后用户正常启动 VSCode 和官方 Codex 扩展。
`saiai vscode` 保留为无需再次传入 Gateway/Key 的修复与刷新入口。两者复用 OAuth
占位、第三方 provider/base URL 清理和备份逻辑，在 `CODEX_HOME/.env` 中写入当前
loopback HTTP(S) proxy、`NO_PROXY` 和
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
