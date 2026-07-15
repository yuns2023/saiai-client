# Windows 使用指南（V2 Preview 0.9.2）

本页适用于 SAIAI CLI V2 Preview `0.9.2`。公开 V2 客户端只维护 schema 2
状态，不读取、不导入旧模式配置。Windows Release 提供 AMD64 和 ARM64
二进制；PowerShell 安装器只安装 CLI，不初始化 Claude 或 Codex，也不接收
API Key。

## 1. 准备官方客户端

先安装实际要使用的官方客户端，并确保它位于 Windows `PATH` 中：

```powershell
Get-Command claude -ErrorAction SilentlyContinue
Get-Command codex -ErrorAction SilentlyContinue
```

只使用 Claude 时不需要安装 Codex，反之亦然。SAIAI 支持 PATH 中的原生
`claude.exe` / `codex.exe`，也支持标准 npm 安装生成的 `.cmd` 布局；npm
布局还必须保留对应包文件和可用的原生 `node.exe`。SAIAI 不会通过
`cmd.exe` 执行这些 shim。

## 2. 安装 SAIAI CLI

Gateway 已镜像匹配的 `0.9.2` bundle 时，可以在 PowerShell 中运行：

```powershell
irm https://api.saiai.top/saiai-cli/setup.ps1 | iex
Invoke-Saiai install
```

也可以固定到本仓的 `saiai-v0.9.2` Release。脚本、manifest 和二进制必须
来自同一个 tag：

```powershell
$tag = "saiai-v0.9.2"
$env:SAIAI_DOWNLOAD_BASE = "https://github.com/yuns2023/saiai-client/releases/download/$tag"
try {
    irm "https://raw.githubusercontent.com/yuns2023/saiai-client/$tag/scripts/saiai-cli/setup.ps1" | iex
    Invoke-Saiai install
}
finally {
    Remove-Item Env:SAIAI_DOWNLOAD_BASE -ErrorAction SilentlyContinue
}
```

安装器验证 manifest schema、bootstrap schema、文件大小和 SHA-256 后，默认
安装到：

```text
%LOCALAPPDATA%\SAIAI\bin\saiai.exe
```

它会把该目录加入当前进程和用户 `PATH`。安装完成时还会打印带绝对路径的
下一步命令；第一次使用建议直接复制该命令，例如：

```powershell
$saiai = Join-Path $env:LOCALAPPDATA "SAIAI\bin\saiai.exe"
& $saiai --version
& $saiai claude
```

如果使用了自定义 `SAIAI_INSTALL_DIR`，应以安装器实际打印的路径为准。新开
PowerShell 后通常可以直接运行 `saiai`；若仍提示找不到命令，先确认用户
`PATH` 已包含安装目录，不要重复初始化产品来修复 PATH。

## 3. 只初始化要使用的产品

日常推荐直接启动目标产品。第一次启动会先完成该产品的一次性初始化，然后
启动官方客户端：

```powershell
saiai claude
```

或：

```powershell
saiai codex
```

首次初始化会询问 Gateway URL（尚未保存时）以及当前所选产品的 API Key。
`saiai claude` 不会要求 Codex Key，`saiai codex` 也不会要求 Claude Key。

如需先初始化、暂不启动官方客户端，请明确写出产品：

```powershell
saiai setup claude --base-url https://api.saiai.top
saiai setup codex --base-url https://api.saiai.top
```

上面两条是二选一的示例，不要求同时执行。交互模式会隐藏 API Key 输入；
不要把 API Key 放进命令参数。自动化场景可以使用对应的
`--api-key-stdin`，并通过标准输入提供 Key。

Claude 和 Codex 使用各自独立的凭据与隔离 home，但共享一个 Gateway URL。
第一个产品完成初始化后，第二个产品可以省略 URL：

```powershell
saiai setup codex
```

如果另一个产品已经配置，SAIAI 会拒绝为当前产品指定不同的 Gateway。要让
整套 V2 状态切换到另一个 Gateway，请先停止正在运行的 Claude/Codex，执行
`saiai revoke --all`，再重新初始化需要的产品。

## 4. 检查和撤销

运行离线检查：

```powershell
saiai doctor
```

`doctor` 检查 schema-2 状态、受管文件、权限和 PATH 中的官方客户端，并显示
配置路径和 Gateway URL，但不会输出 API Key。只配置一个产品时，另一个产品
显示为 `unconfigured` 是正常状态。

只撤销一个产品：

```powershell
saiai claude revoke
saiai codex revoke
```

两条命令分别只删除对应产品的 V2 凭据和受管 home，不影响另一产品，也不
检查或修改普通 Claude/Codex home。未配置产品的 revoke 是幂等操作。

清理全部 V2-owned 状态：

```powershell
saiai revoke --all
```

V2 不迁移损坏或旧 schema 状态；遇到 doctor 报告整套状态不可验证时，使用
`revoke --all` 后重新初始化。若 revoke 报告产品正在运行，请先退出对应
Claude/Codex 进程再重试。

## 5. 更新与 Preview 签名说明

CLI `0.9.2` 没有 `saiai update` 命令。更新时先退出通过 SAIAI 启动的
Claude/Codex，再重新运行第 2 节的安装流程：

- 使用 Gateway 镜像时，脚本和 manifest 应来自同一个 Gateway origin；
- 使用 GitHub Release 时，同时把脚本 tag 和 `SAIAI_DOWNLOAD_BASE` 改成同一个
  新 tag；
- 不要把一个版本的脚本与另一个版本的 manifest/binary 混用。

安装器会重新验证候选文件并替换 CLI，不会改写现有 V2 产品状态。首次替换为
不同二进制时，默认安装目录会保留一份 `saiai-previous.exe`；它只是二进制
应急副本，不是状态迁移或跨 schema 兼容机制。

当前 Windows CLI 与 Desktop 都是未正式代码签名的 Preview，Windows 可能
显示“未知发布者”或由组织策略阻止运行。manifest 的 SHA-256 校验用于确认
下载文件与发布清单一致，不能替代 Authenticode 签名。只使用本仓正式 tag
及其匹配 manifest；如果设备策略不允许未签名程序，请不要绕过策略，等待
签名版本或按本仓源码自行审计构建。

PowerShell 安装器只安装 CLI。`saiai ui` 需要另行安装匹配的 Desktop Preview；
当前 Desktop updater artifacts 也未启用，因此 Desktop 更新同样不是自动流程。

## 常见问题

### `saiai` 不是可识别的命令

使用安装器输出的绝对路径运行，或新开一个 PowerShell，再检查：

```powershell
$bin = Join-Path $env:LOCALAPPDATA "SAIAI\bin"
$env:Path -split ';' | Where-Object { $_ -eq $bin }
```

### SAIAI 找不到 Claude 或 Codex

先在同一个 PowerShell 中确认 `Get-Command claude` 或 `Get-Command codex`。
如果是 npm 安装，修复标准包目录和 `node.exe`，然后运行 `saiai doctor`；不要
把客户端参数通过 `cmd.exe` 包装后再交给 SAIAI。

### 第二个产品提示 Gateway 冲突

两个产品必须共享同一 URL。省略第二个 setup 的 `--base-url` 以复用现有
Gateway；如果确实要整体换地址，执行 `saiai revoke --all` 后重新初始化。
