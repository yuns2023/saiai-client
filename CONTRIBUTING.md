# Contributing

感谢参与 SAIAI Client。当前稳定合约是 `local-proxy` schema 1：Claude 使用用户级
托管代理，Codex 使用直接配置。请保持二者的配置边界独立。

## 开始之前

1. 先搜索现有 Issue，确认问题尚未被讨论。
2. 安全漏洞请按 [SECURITY.md](SECURITY.md) 私密报告。
3. 对用户可见行为、状态格式或 Gateway 响应的修改，应先说明 contract 影响。
4. 不要提交真实凭据、证书私钥、日志、抓包、机器路径或内部网络信息。

## 本地开发

CLI 使用仓库固定的 Rust 1.97.0：

```bash
cargo fmt --manifest-path tools/saiai-cli/Cargo.toml --all -- --check
cargo test --manifest-path tools/saiai-cli/Cargo.toml
```

Desktop 需要 Node.js 20.19+、pnpm 10、仓库固定的 Rust 工具链和对应平台的 Tauri 2 系统依赖：

```bash
cd tools/saiai-desktop
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test:run
pnpm tauri:dev
```

避免使用真实 Gateway 和真实 API Key 做测试。Gateway 交互应使用本地 mock；测试凭据必须清楚标记为虚构值。

## Pull Request 要求

- 改动保持聚焦，并说明用户可见结果。
- 新行为包含相称的单元或集成测试。
- 本地代理、CA、manifest 或 wrapper 变化同步更新客户端设计与 release 测试。
- Desktop IPC 保持为少量、用途明确的命令，不增加通用 shell、文件系统或 HTTP 权限。
- 不回显 API Key，不把凭据放入 URL、进程参数或诊断输出。
- 不提交或分发共享 CA 私钥；测试使用运行时生成的临时 CA。
- 提交前检查格式、测试以及新增依赖的许可证和安全公告。

提交贡献即表示你同意按本仓库的 MIT License 授权该贡献。
