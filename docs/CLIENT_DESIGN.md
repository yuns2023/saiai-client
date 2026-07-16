# SAIAI global-config client design

## 目标

`saiai` 是一次性配置工具，不是客户端启动器。用户执行 WebUI 提供的一行命令
后，直接使用官方 `claude`、VSCode Claude Code 或 `codex`。

稳定边界：

- 不创建本地代理、CA、常驻服务、隔离 home 或 generation。
- 不代理或捕获模型流量。
- 不调用 Gateway bootstrap，也不发送模型请求。
- 同一命令可重复执行；新 Base URL/Key 覆盖旧的 SAIAI 管理值。
- 无关用户配置和机器身份值必须保留。

## Claude 配置事务

路径解析遵守 `CLAUDE_CONFIG_DIR`。未设置时使用：

- `~/.claude/settings.json`
- `~/.claude.json`
- `~/.claude/.credentials.json`
- `~/.claude/saiai-ca.crt`（仅作为旧状态清理目标）

一次初始化按以下顺序完成：

1. 无跟随地检查目标；拒绝符号链接和非普通文件。
2. 在任何写操作前解析现有 `settings.json` 与 `.claude.json`。
3. 计算保留无关字段的新 JSON。
4. 为所有将改变的现有文件创建 `0600` 私有备份。
5. 使用同目录临时文件和原子替换提交 settings 与 state。
6. 删除已备份的 OAuth credentials 和旧 SAIAI CA。
7. 任一步失败时恢复本次已提交的文件。

`settings.json.env` 中由 SAIAI 管理的最终值包括 Gateway、OAuth token、
600000ms stream idle timeout 和当前功能开关。旧认证方式、云 provider、模型
覆盖、代理与 CA 变量会被移除，防止 Claude Code 再次从 settings 覆盖路由。

`.claude.json` 只移除 `oauthAccount` 并将 onboarding 标记为完成；其他字段保留。
程序不会把 Key 写入输出或错误信息。

## Codex 配置事务

路径遵守 `CODEX_HOME`，默认是 `~/.codex`。客户端先解析完整 TOML 和 JSON，
然后在一次备份/回滚事务中合并 `config.toml` 与 `auth.json`。OpenAI provider 使用
Responses API；`--websockets` 可重复开启或关闭对应字段。

## 更新短路径

三个 wrapper 以 `manifest.json` 为版本权威。它们先取得当前平台资产的 size 与
SHA-256：

```text
installed hash == manifest hash
  -> 不下载二进制 -> 直接执行配置

installed hash != manifest hash
  -> 下载并校验 -> 原子替换二进制 -> 执行配置
```

manifest contract 为：

```json
{
  "manifest_schema": 1,
  "client_mode": "global-config",
  "configuration_schema_version": 1
}
```

wrapper、manifest 和六个平台二进制构成一个不可变 release bundle。Gateway 只
负责从当前激活目录提供这些文件；wrapper 默认下载源由请求的公开 origin 动态
渲染。
