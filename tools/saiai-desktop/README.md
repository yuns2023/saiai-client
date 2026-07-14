# SAIAI Desktop V2 Preview

SAIAI Desktop 是 SAIAI V2-only 客户端的 Tauri 2 + Vue/Vite 界面。它通过少量类型化 IPC 命令调用同仓库的 `saiai-core`，与 CLI 使用相同的 schema-2 状态，不维护第二套配置。

当前功能：

- 只初始化用户选择的 Claude Code 或 Codex；
- 首个产品保存共享 Gateway，另一产品复用地址并使用独立 Key；
- 展示产品初始化状态、隔离 home 和有界的 `--version` 探测；
- 运行不含凭据的 doctor 与本地权限检查；
- 分别 revoke Claude、Codex，或清理全部 V2 状态；
- 通过认证、无模型用量的 bootstrap 验证 Key 能力；
- 以 core 事务提交所选产品的 generation 和 credential reference。

API Key 从 Vue 表单交给 Rust 后立即从前端状态清除，不会通过状态、日志、doctor 或 IPC 结果返回。

## 仓库路径

Desktop 位于公开仓库的 `tools/saiai-desktop`，core 位于相邻的 `tools/saiai-core`。`src-tauri/Cargo.toml` 的相对依赖 `../../saiai-core` 只指向本仓库，不需要额外源码目录。

从仓库根目录进入 Desktop：

```bash
cd tools/saiai-desktop
```

## 前置条件

- Node.js 20.19 或更新版本
- pnpm 10
- 仓库 `rust-toolchain.toml` 固定的 Rust 工具链
- [Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/) 中对应平台的系统依赖

Windows 开发需要 Microsoft C++ Build Tools 与 WebView2；macOS 需要 Xcode Command Line Tools。Linux 原生包请以 Tauri 官方清单为准。

## 开发

```bash
pnpm install --frozen-lockfile
pnpm tauri:dev
```

只预览 Vue 界面：

```bash
pnpm dev
```

普通浏览器中使用明确标记的 `browser-only` adapter。它只维护当前页面内的演示状态，不读取、写入或探测本机。

常用检查：

```bash
pnpm typecheck
pnpm test:run
pnpm build
```

`pnpm-lock.yaml` 已提交。不要使用真实 API Key 运行前端测试；Gateway 场景应使用本地 mock。

## Tauri 边界

前端只调用以下应用命令：

| Command | Input | Output |
| --- | --- | --- |
| `desktop_get_state` | none | `DesktopState` |
| `desktop_setup` | `{ input: { product, baseUrl, apiKey } }` | `ActionResult` |
| `desktop_doctor` | none | `DoctorReport` |
| `desktop_revoke` | `{ target: "claude" \| "codex" \| "all" }` | `ActionResult` |

`main` window 不授予 core/plugin permissions。应用没有通用 shell、opener、文件系统、HTTP 或 store 插件；进程与配置访问只存在于用途明确、逐项验证参数的 Rust 命令中。

发布 CSP 只允许 bundled content 与 Tauri IPC；开发 CSP 额外允许固定的本地 Vite HMR WebSocket。WebView 不直接联系 Gateway，网络验证和凭据存储均在 Rust 侧完成。

相关文件：

- `src-tauri/tauri.conf.json`
- `src-tauri/capabilities/main-ui.json`
- `src-tauri/src/lib.rs`
- `src/api/desktop.ts`

## 打包状态

Preview 版本为 `0.9.0-preview.1`，bundle identifier 为 `top.saiai.desktop`。Updater artifacts 当前关闭，macOS 本地 Preview 构建使用 ad-hoc signing。正式分发必须使用对应平台的发布签名；启用 updater 前必须先确定签名、密钥保管和回滚策略。

Linux Preview 有一个已知的上游依赖告警：Tauri 2 的 GTK3 链当前解析到 `glib 0.18.5`，受 [GHSA-wrw7-89jp-8q8g](https://github.com/advisories/GHSA-wrw7-89jp-8q8g) 影响。SAIAI 及当前解析的依赖源码没有直接调用告警涉及的 `VariantStrIter` API，但告警保持开启；Linux 包仅作为 Preview，不进入稳定版或自动更新渠道。Tauri 上游的现状见 [tauri#12048](https://github.com/tauri-apps/tauri/issues/12048) 与 [tauri#12564](https://github.com/tauri-apps/tauri/issues/12564)。Windows 和 macOS bundle 不包含这个仅限 GTK3 target 的依赖。

Desktop 与 CLI 可以作为独立 release assets 分发，但二者必须来自兼容的 V2 contract 版本。Desktop 可读取 CLI 已创建的状态，`saiai ui` 也可以打开已安装的 Desktop bundle。

客户端整体设计见 [../../docs/CLIENT_DESIGN.md](../../docs/CLIENT_DESIGN.md)，Gateway 能力发现协议见 [../../docs/GATEWAY_BOOTSTRAP.md](../../docs/GATEWAY_BOOTSTRAP.md)。
