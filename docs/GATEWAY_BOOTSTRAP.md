# Gateway Bootstrap Contract

本文定义 SAIAI V2 客户端初始化时使用的公开 Gateway contract。Bootstrap 只验证当前 API Key 的路由能力，不调用模型端点，也不应产生模型用量。机器可读版本见 [`contracts/bootstrap-v2.json`](../contracts/bootstrap-v2.json)。

## Request

给定用户输入的 Gateway base URL，客户端移除末尾 `/` 后追加固定路径：

```http
GET /api/v1/client/bootstrap HTTP/1.1
Authorization: Bearer <product-api-key>
```

- 请求没有 body。
- 每次 setup 使用当前所选产品的 Key。
- 客户端不跟随重定向。
- 客户端绕过环境代理执行 bootstrap，连接超时为 10 秒、总超时为 20 秒。
- 生产 Gateway 应使用 HTTPS。Base URL 可以包含部署前缀路径，但不能包含账号密码、query、fragment 或 API Key。

例如 base URL 为 `https://gateway.example.com/tenant` 时，请求路径为：

```text
https://gateway.example.com/tenant/api/v1/client/bootstrap
```

## Success response

Gateway 返回 `HTTP 200`、`Content-Type: application/json` 和 JSON envelope：

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "schema_version": 2,
    "gateway_version": "gateway-2.0.0",
    "capabilities": {
      "claude": true,
      "codex": true,
      "codex_responses": true,
      "codex_websockets": false,
      "openai_messages_dispatch": false
    }
  }
}
```

客户端要求：

- `code` 必须是数值 `0`；
- `data` 与 `capabilities` 必须存在；
- `schema_version` 必须是数值 `2`；
- 所有 capability 都是 JSON boolean，缺失字段按 `false` 处理；
- `gateway_version` 必须是字符串，最多 128 bytes，只包含普通可打印 ASCII 或空格；空字符串允许；
- 响应最大 1 MiB；
- 未知字段会被忽略，可用于向前扩展。

`message` 不参与成功判定，客户端也不会把响应中的未知字段写入配置。

## Capability semantics

| Field | 含义 | Setup 要求 |
| --- | --- | --- |
| `claude` | 当前 Key 可路由原生 Claude Messages 请求 | Claude 必须为 `true` |
| `codex` | 当前 Key 可路由 Codex 请求 | Codex 必须为 `true` |
| `codex_responses` | 当前 Key 可使用 Responses API | Codex 必须为 `true` |
| `codex_websockets` | Gateway 支持 Codex Responses WebSocket 传输 | 可选；为 `true` 时客户端才启用 |
| `openai_messages_dispatch` | OpenAI 分组兼容 `/v1/messages` 的信息性标记 | 不满足 Claude setup，也不会把 `claude` 变为 `true` |

Gateway 必须根据 bearer credential 的实际授权返回 capability，而不是返回全局服务能力。Claude Key 与 Codex Key 可以得到不同响应。

## Failure response

客户端按 HTTP 状态分类错误，不依赖错误 body：

| Status | 客户端分类 |
| --- | --- |
| `401` | invalid credential |
| `403` | credential not permitted |
| `404` | bootstrap endpoint unavailable |
| `429` | rate limited |
| `3xx` | redirect refused |
| `5xx` | gateway unavailable |
| 其他非成功状态 | request rejected |

Gateway 可以使用自己的错误 envelope，但不得在 body、header 或日志中回显完整 bearer credential。

## Security requirements

- Bootstrap handler 必须执行与实际路由一致的鉴权和授权判断。
- Handler 不得发起模型请求、创建用量记录或修改账号状态。
- 响应建议设置 `Cache-Control: no-store`，避免中间缓存混淆不同 Key 的能力。
- `gateway_version` 不得包含凭据、控制字符、ANSI 序列或双向文本控制字符。
- 日志必须脱敏 `Authorization`，并对失败请求实施合理的速率限制。
- 不应通过 `openai_messages_dispatch` 推断原生 Claude routing；这两个能力有意保持独立。

修改此 contract 时，应同时更新 core DTO、mock fixture、CLI/Desktop 行为和 contract tests。
