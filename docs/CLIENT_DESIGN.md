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

路径解析遵守 `CLAUDE_CONFIG_DIR`。未设置时使用：

- `~/.claude/settings.json`
- `~/.claude.json`
- `~/.claude/.credentials.json`
- `~/.claude/saiai-ca.crt`
- `~/.claude/saiai-ca.key`
- `~/.saiai/config.json`

初始化会先解析并备份已有配置，然后：

1. 保留无关的 settings/state 字段。
2. 移除认证、云 provider、模型、旧 proxy 和 CA 冲突环境变量。
3. 写入 `CLAUDE_CODE_OAUTH_TOKEN`、loopback proxy、`NO_PROXY`、
   `NODE_EXTRA_CA_CERTS` 和 `CLAUDE_STREAM_IDLE_TIMEOUT_MS=600000`。
4. 移除 settings/state 中的 `oauthAccount`，备份后删除
   `.credentials.json`。
5. 复用有效的用户 CA；CA 缺失或损坏时备份旧文件并生成新 CA 对，私钥权限为
   `0600`。
6. 原子写入代理配置，Base URL 和 Key 在重复初始化时直接替换。

本地代理终止 `api.anthropic.com` 的本机 TLS，并把 Anthropic 请求转发到配置的
Gateway；其他代理流量保持直接隧道。Gateway Key 由代理从私有配置读取，程序
不会把 Key 打印到输出或请求日志。

## 用户服务

- Linux 使用 `systemd --user`。
- macOS 使用用户 LaunchAgent。
- Windows 使用用户进程与 PID/日志状态文件，不要求管理员权限。

一键 wrapper 在 Claude 初始化成功后执行 `saiai start`。自动化测试或明确需要只
配置不启动时可设置 `SAIAI_SKIP_START=1`。Codex 初始化不会启动 Claude 代理。

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
