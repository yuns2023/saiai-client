# SAIAI managed local-proxy client design

## 目标

`saiai` 为 Claude Code 和 VSCode 提供用户级托管本地代理，同时保留 Codex CLI
直接配置。WebUI 的一行命令完成安装、配置并启动代理；用户也可以用
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

本地代理终止 `api.anthropic.com` 的本机 TLS，并把 Anthropic 请求转发到配置的
Gateway；其他 `CONNECT` 请求作为任意目标和任意 TCP 端口的直接隧道处理，让
系统 TUN、Fake-IP 和用户自己的出站规则接管实际流量。它不提供 UDP 转发，也不
处理明文 HTTP 的 absolute-form 请求。由于该接口不认证且可访问任意目标，代理
核心必须强制只监听 loopback，不能仅依赖初始化器生成的默认地址。Gateway Key
由代理从私有配置读取，程序不会把 Key 打印到输出或请求日志。

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

## Codex 配置

路径遵守 `CODEX_HOME`，默认是 `~/.codex`。客户端合并 `config.toml` 与
`auth.json`，保留不属于 SAIAI 的字段。OpenAI provider 使用 Responses API；
`--websockets` 可开启对应传输配置。

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
