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
两者必须分别验证进程启动、OAuth 存储、HTTP(S) proxy、CA 信任和 WebSocket 行为；
在独立 capture 通过前，不对外声明 Desktop/VSCode Codex 已兼容。

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
