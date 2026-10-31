# 诊断路径

## 1. 最小设备与版本清单

只收集 OS 版本/架构、SAIAI 版本和二进制 SHA-256、Desktop 包版本/类型、
内置 app-server 版本、可执行文件路径别名及当前进程启动时间。
不采集机器名、序列号、用户名、完整进程命令行。

Windows 区分商店 AppX 与普通 exe；通过签名包信息定位实际安装，不把 PATH 上
的 `codex.exe` 当成 Desktop 内置版本。macOS 读取实际 bundle 的 Info.plist，
不要移动已签名 app-server。Linux 区分桌面快捷方式与 SAIAI 启动实例。
内置版本无法无副作用确定时写 unknown，不运行应用去猜。

检查当前工作目录、`SAIAI_HOME`、`CODEX_HOME` 与实例归属，路径只保留别名。
自定义环境可能拥有独立的端口、CA 和进程；不能固定假定默认端口或默认目录。
只记录代理是否 loopback、端口、CA 公共证书 SHA-256/有效期、配置与进程是否匹配。
不读取 CA 私钥。

## 2. 启动仍要求登录

按顺序查已有证据：

1. 用户是否实际通过 `saiai desktop codex` 启动，还是普通图标/通知唤醒旧实例？
2. GUI、app-server 和初始化所用 profile 是否同一实例？不把存在 `auth.json`
   等同于 UI 已登录。不删除真实 OAuth 或强写占位 token。
3. 进程是否使用正确代理、CA/SPKI 和配置目录？分别标注“配置声明”
   与“实际进程观察”；无权限读取进程状态就保留未知。
4. 既有 app-server 日志或已存在的控制面结果是否表明 `account=null`？
   只记录 `null/non-null/unknown`、认证模式及错误码，不输出账户对象。
   不为验证这个问题连接客户真实 app-server 发 RPC：身份读取也可能刷新凭据或联网。
5. 登录提示是否伴随证书错误、直连 401、profile 解析失败或未知实例拒绝？
   确认最早错误，再分析后续取消/连接重置。

平台相关假设必须核对客户版本：

- Windows AppX 通过 broker 激活，不能假定继承 shell 的环境；
  标准 profile、受管实例记录、proxy/SPKI 与实际窗口必须一致。
  不要求客户以管理员运行，不修改 ACL，也不按名称批量杀进程。
- macOS/Linux 可能使用受管隔离 profile/user-data；
  普通图标启动和 SAIAI launcher 不是同一入口。
- 已运行实例可能保留旧代理/证书。报告可建议保存草稿后正常退出再验证，
  但诊断阶段不自行重启，不把重启当作根因。

## 3. 普通 Chat 不能用

先确认是普通 Chat 还是 Work/Codex。路由名只是版本相关的线索：

| 面 | 已有日志中的典型线索 | 不能据此推断 |
|---|---|---|
| Work/Codex | Responses、Codex 模型目录、app-server | 普通 Chat 已支持 |
| 普通 Chat | conversation/init、prepare、f/conversation | Responses 协议相同 |
| 身份/设置 | account、profiles、settings | 模型调用成功 |
| 附件/图片 | 上传、files/download、estuary/content | 生成和下载均完成 |

保留 HTTP 方法、经过模板化的路径、状态码、结构化错误类型和时间。
去掉 query/fragment、签名下载地址、设备 proof、Cookie 和所有正文。
路径中的 conversation/file/account ID 变为稳定的本报告别名。
从同一失败链区分：

- 未进入代理：启动入口、实例复用、环境继承或绕过代理。
- TLS 失败：定位是 GUI、app-server、本地代理还是上游拒绝证书；
  不关闭验证，不将所有 10053/10054 归咎于 CA。
- 本地 501/unsupported：精确方法/路径与客户端适配不匹配。
- 401：记录发生的 hop，不凭状态码推断 Key 已失效。
- init/prepare 的 HTML 403：可疑浏览器/设备校验拒绝；
  不能判定为 OAuth 登录失败，不能伪造 proof 或建议绕过。
- 429：区分后台更新连接容量与模型并发/额度；没有结构化证据时不猜。
- HTTP 200 后流错误：记录是否有完成事件；不能报告成功。
- Work 可用但 Chat 不可用：可能是独立路由、Gateway 开关、价格配置、
  OAuth 账号资格或上游校验。客户侧不能验证的交给管理员，别直接修 CLI。

Gateway 与上游归因必须有对应 hop 的证据；客户端一个错误页不足以定责。
不向客户索要管理员密钥、后台数据库或私有 Ops。

## 4. 内置浏览器、Chrome 或 Computer Use 不可用

典型表现：模型说“技能说明存在，但执行工具没出现在当前会话中”，或设置页把
Chrome/电脑操作显示为“已被你的组织停用，或在你所在地区不可用”。
这三项都要 Desktop 给会话挂上本机 `node_repl`/`cua_repl` 工具才能执行。

按顺序查已有证据：

1. SAIAI 版本是否包含 Client PR #141（main `b6ea474` 之后的版本）？更早的版本
   本地 Statsig 应答不含操控 gate，Desktop 不会为会话挂上这些工具，属于已知限制，
   不是客户配置错误。
2. `config.json` 的 `desktop_browser_use` 是否为 `false`，或代理进程继承了
   `SAIAI_DESKTOP_BROWSER_USE=0`？只记录取值，不改配置。
3. Desktop 日志中 `browser_use_availability_resolved` 的 `available`/`reason`
   （`statsig-disabled` 表示 gate 未开启）。
4. 新会话日志是否出现 `MCP client for node_repl failed to start ... os error 3`？
   这通常是 `<CODEX_HOME>/config.toml` 里早期写入的 `cua_node\<hash>` 路径已失效；
   gate 开启后 Desktop 重启时会按当前运行时重写，诊断阶段不手动修改。

不要为了验证而让模型实际操作浏览器或桌面；Chrome 操控还需要客户自己装好扩展并在
浏览器中授权。

## 5. 安全提取与下一步

使用平台已有的 JSON/TOML 解析能力在本地生成允许字段；没有可靠解析器就跳过，
不要用宽泛正则抽取 token、执行未知脚本或把源文件发给模型解析。
命令的 stdout/stderr 和异常信息同样须经过过滤。动态错误消息只返回分类，
例如 `tls_certificate_rejected`、`config_parse_failed`、`http_403`；无法分类用 unknown。
不计算/导出 token 或用户消息哈希。

报告可保留用于管理员关联的 request ID，但必须确认它是请求标识、不是凭据；
无法确认时用别名，客户在私下向管理员提供原值。省略邮箱、IP、业务域名、
项目路径和文档内容；目标用 `<GATEWAY>` / `<PROVIDER>`。

如果证据指向 CLI，维护者应在规范 Client 仓库根据报告构造合成凭据/loopback
mock 回归。仓库的 `scripts/saiai-cli/probe-installed-codex-desktop.py` 可供维护者
评估，客户诊断不自动下载或执行它。mock 通过不能替代真实 GUI/平台验收。
