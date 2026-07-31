# Moonshot Kimi K3 独立复核传输合同官方核验

- 查询日期：2026-07-31
- 研究对象：`kimi-k3`
- 官方 API 基线：`https://api.moonshot.ai/v1`
- 资料边界：仅使用 Moonshot/Kimi 官方 API 文档、官方 OpenAPI 与官方价格页
- 执行边界：未调用 Moonshot API，未读取或使用任何凭据，未执行 Token Estimate 或正式模型复核

## 结论

Moonshot/Kimi 官方资料可以证明以下 K3 传输合同：

| 项目 | 官方合同 | 核验状态 |
|---|---|---|
| Provider model ID | `kimi-k3` | 已确认 |
| Context window | `1,048,576 tokens` | 已确认 |
| Chat endpoint | `POST https://api.moonshot.ai/v1/chat/completions` | 已确认 |
| Thinking | K3 始终启用思考；不能关闭 | 已确认 |
| Reasoning parameter | 顶层 `reasoning_effort`，取值 `low`、`high`、`max`，默认 `max` | 已确认 |
| K2.x `thinking` 字段 | 迁移至 K3 时应移除，K3 使用顶层 `reasoning_effort` | 已确认 |
| Tool prohibition | `tool_choice: "none"` 表示不进行工具调用；`tools` 可省略 | 已确认 |
| Structured Output | `response_format.type=json_schema`，`json_schema.strict=true` | 已确认 |
| Completion limit | K3 默认 `131072`，最高可设 `1048576`；`32768` 在合同范围内 | 已确认 |
| Token Estimate endpoint | `POST /v1/tokenizers/estimate-token-count` | 已确认 |
| Token Estimate K3 runtime acceptance | 官方示例使用 `kimi-k3`，但同页 OpenAPI 枚举漏列 K3 | **文档不一致，需 live call 证明** |
| 当前价格 | Cache-hit input `$0.30`、cache-miss input `$3.00`、output `$15.00` / 1M tokens，均未含税 | 已确认 |

来源：[Kimi K3 指南](https://platform.kimi.ai/docs/guide/kimi-k3-quickstart)、[模型列表](https://platform.kimi.ai/docs/models)、[Chat API](https://platform.kimi.ai/docs/api/chat)、[Reasoning Effort](https://platform.kimi.ai/docs/guide/use-reasoning-effort)、[Structured Output](https://platform.kimi.ai/docs/guide/response_format)、[Token Estimate](https://platform.kimi.ai/docs/api/estimate)、[K3 价格](https://platform.kimi.ai/docs/pricing/chat-k3)。

## 1. 模型、上下文与端点

官方模型列表把 `kimi-k3` 定义为 Kimi 当前旗舰模型，并声明 1M-token context window；K3 价格页给出精确值 **1,048,576 tokens**。Chat API 的 K3 request discriminator 和 K3 快速入门均使用模型 ID `kimi-k3`。[模型列表](https://platform.kimi.ai/docs/models)、[K3 价格](https://platform.kimi.ai/docs/pricing/chat-k3)、[Chat API](https://platform.kimi.ai/docs/api/chat)

官方服务地址和调用路径为：

```text
baseURL = https://api.moonshot.ai/v1
endpoint = POST /chat/completions
full URL = https://api.moonshot.ai/v1/chat/completions
```

来源：[API Overview](https://platform.kimi.ai/docs/api/overview)、[Kimi K3 指南](https://platform.kimi.ai/docs/guide/kimi-k3-quickstart)。

上下文窗口同时容纳输入与输出。Chat API 明确规定：若 input tokens 与 `max_completion_tokens` 之和超过模型上下文，返回 `invalid_request_error`。[Chat API](https://platform.kimi.ai/docs/api/chat)

## 2. 永久思考与请求参数

K3 始终启用思考，不能关闭。思考强度通过 Chat Completions 请求的顶层字段 `reasoning_effort` 控制，支持 `low`、`high`、`max`，默认 `max`。官方迁移说明要求从 K2.x 切换到 K3 时删除 K2.x 的 `thinking` 配置，按需改用顶层 `reasoning_effort`。[Reasoning Effort](https://platform.kimi.ai/docs/guide/use-reasoning-effort)、[Kimi K3 指南](https://platform.kimi.ai/docs/guide/kimi-k3-quickstart)

因此，本项目候选请求的正确相关字段为：

```json
{
  "model": "kimi-k3",
  "reasoning_effort": "max"
}
```

并且请求中应完全省略 `thinking`。这不是“关闭思考”，而是遵循 K3 专用合同。

K3 官方限制还规定 `temperature=1.0`、`top_p=0.95`、`n=1`、`presence_penalty=0`、`frequency_penalty=0` 为固定值，应从请求中省略。[Kimi K3 指南](https://platform.kimi.ai/docs/guide/kimi-k3-quickstart)

## 3. 工具禁用合同

Chat API 定义：

- `tool_choice="auto"`：模型自行决定是否调用工具；
- `tool_choice="none"`：不进行工具调用；
- `tool_choice="required"`：强制工具调用。

`tools` 本身是可选数组。对于无工具独立复核，候选请求应设置 `tool_choice: "none"`，并完全省略 `tools`，从而同时满足“明确禁止工具选择”和“不提供工具定义”。[Chat API](https://platform.kimi.ai/docs/api/chat)、[Tool Choice](https://platform.kimi.ai/docs/guide/use-tool-choice)

官方资料只证明 API 参数层不触发模型工具调用；操作系统只读隔离、无仓库写权限、无治理凭据等仍属于本项目本地安全边界，不能由 `tool_choice` 单独证明。

## 4. Structured Output

K3 官方指南直接给出以下结构化输出合同：

```json
{
  "response_format": {
    "type": "json_schema",
    "json_schema": {
      "name": "independent_model_review",
      "strict": true,
      "schema": {}
    }
  }
}
```

官方称 K3 可靠支持 Structured Output，包括嵌套对象、数组和 `anyOf`。`strict: true` 时，Schema 必须符合 Moonshot Flavored JSON Schema（MFJS）。最终只应解析 `choices[0].message.content`，不能把 `reasoning_content` 当成最终 JSON。[Kimi K3 指南](https://platform.kimi.ai/docs/guide/kimi-k3-quickstart)、[Structured Output](https://platform.kimi.ai/docs/guide/response_format)

`strict: true` 只提供结构约束，不能证明业务语义正确，也不能替代本地 Canonical Receipt Schema 和语义验证。官方还建议用 `walle` 做 MFJS 静态检查，并明确实际兼容性仍应由目标模型 live call 验证。[Structured Output](https://platform.kimi.ai/docs/guide/response_format)

## 5. `max_completion_tokens` 与完成状态

K3 的 `max_completion_tokens`：

- 默认：`131072`；
- 官方最大可配置值：`1048576`；
- 本项目拟用的 `32768` 是合法的较小值。

若生成达到该上限但未自然结束，`finish_reason` 为 `length`；自然结束则为 `stop`。因此，`finish_reason=length` 必须失败关闭，不能签发 Review Receipt。[Chat API](https://platform.kimi.ai/docs/api/chat)、[Kimi K3 指南](https://platform.kimi.ai/docs/guide/kimi-k3-quickstart)

非流式成功响应的官方结构包含：

- 顶层 `model`；
- `choices[].message.content` 与可能存在的 `reasoning_content`；
- `choices[].finish_reason`，枚举包含 `stop`、`length`、`tool_calls`；
- `usage.prompt_tokens`、`usage.completion_tokens`、`usage.total_tokens`、`usage.cached_tokens`。

来源：[Chat API](https://platform.kimi.ai/docs/api/chat)。

## 6. Token Estimate 的准确能力边界

官方估算端点为：

```text
POST https://api.moonshot.ai/v1/tokenizers/estimate-token-count
```

公开请求 Schema 只包含：

```json
{
  "model": "kimi-k3",
  "messages": []
}
```

成功且没有 `error` 字段时，可读取 `data.total_tokens` 作为估算结果。官方页面的纯文本和视觉示例均使用 `kimi-k3`。[Token Estimate](https://platform.kimi.ai/docs/api/estimate)

### 官方文档不一致

同一 Token Estimate 页面内嵌 OpenAPI 的 `model` 枚举截至查询日仍未列出 `kimi-k3`，虽然页面示例已经使用 K3。由此只能得出：

- K3 Token Estimate 是官方文档展示的预期用法；
- 静态 OpenAPI 尚未与示例同步；
- 在真正放行 Chat Completion 前，必须由一次认证的官方 Token Estimate live call 证明 K3 runtime 接受该请求；
- 若返回模型/请求不受支持或不能取得 `data.total_tokens`，应失败关闭。

### 估算器不证明完整 Chat 请求全部字段的 token 成本

官方将 Estimate 请求描述为与 Chat Completion “almost identical”，但公开 Estimate Schema 只接受 `model` 和 `messages`，没有 `response_format`、JSON Schema、`reasoning_effort`、`tool_choice` 或 `max_completion_tokens`。因此：

- 可以把与正式调用逐字一致的 system/user `messages` 交给估算器；
- 必须绑定 exact messages UTF-8 bytes、messages SHA-256、material SHA-256、model、source commit、时间与原始估算响应；
- 不能声称该结果已经计算了 `response_format` Schema 或其他非 message 字段；
- 非 message 字段的精确 token 开销：**UNKNOWN**。

## 7. 上下文放行不等式

官方唯一明确的上下文规则是：

```text
input_tokens + max_completion_tokens <= context_window_tokens
```

若本项目额外保留 `8192` safety margin，正确的失败关闭门应为：

```text
estimatedInputTokens + 32768 + 8192 <= 1048576
```

不能使用减法形式：

```text
estimatedInputTokens - 32768 - 8192 <= 1048576
```

后者会错误放行本来已经超窗的输入，与官方“input plus max_completion_tokens”规则相反。`8192` 是 ZB-AIOS 自定安全余量，不是 Moonshot 官方参数。

在上述加法门下，允许的估算输入上界为：

```text
1048576 - 32768 - 8192 = 1007616 tokens
```

估算器只计算 messages 时，还必须考虑其未证明覆盖的 Schema/请求字段开销；在无法给出可靠保守上界前，这仍是需要 live evidence 解决的风险。

## 8. 当前官方价格与 USD 4.00 上限

截至 2026-07-31，K3 官方价格为：

| 计费项 | 税前价格 / 1,000,000 tokens |
|---|---:|
| Input，cache hit | USD 0.30 |
| Input，cache miss | USD 3.00 |
| Output | USD 15.00 |

官方说明价格不含适用税费，1M 等于 1,000,000 tokens，实际 Chat Completion 对 input 和 output 按 usage 计费。[K3 价格](https://platform.kimi.ai/docs/pricing/chat-k3)、[模型推理计费说明](https://platform.kimi.ai/docs/pricing/chat)

按最保守的 cache-miss 输入、上述 1,007,616-token 输入上界和 32,768-token 输出上界计算：

```text
input upper-bound cost  = 1007616 / 1000000 * 3.00 = USD 3.022848
output upper-bound cost =   32768 / 1000000 * 15.00 = USD 0.491520
total upper-bound cost  = USD 3.514368 before tax
```

因此，**在加法上下文门成立、`max_completion_tokens=32768` 被服务端执行且没有其他收费项目时**，该 token 费用上界低于本项目税前 USD 4.00 限额。最终正式调用仍须用响应 `usage` 计算实际费用并验证余额；不能用本静态计算代替 provider 回执。

K3 `reasoning_content` 与最终 `content` 在 `completion_tokens` 中的精确拆分，及非流式响应是否提供更细粒度 reasoning token 计数，当前公开 K3 文档未给出，保持 **UNKNOWN**。

## 9. 推荐的冻结合同

```json
{
  "provider": "moonshot",
  "model": "kimi-k3",
  "baseURL": "https://api.moonshot.ai/v1",
  "endpoint": "/chat/completions",
  "contextWindowTokens": 1048576,
  "reasoningEffort": "max",
  "thinkingFieldPresent": false,
  "toolChoice": "none",
  "toolsPresent": false,
  "maxCompletionTokens": 32768,
  "responseFormatType": "json_schema",
  "responseFormatStrict": true,
  "fallbackPolicy": "DISABLED_FAIL_CLOSED",
  "maxReviewMaterialUtf8Bytes": 1048576,
  "maxRequestUtf8Bytes": 1572864,
  "maxResponseUtf8Bytes": 1048576,
  "contextBudgetBasis": "TRANSPORT_DEFENSE_ONLY_NOT_CONTEXT_PROOF"
}
```

字节上限只能防御传输体积，不能证明 token 数。正式调用前必须：

1. 从冻结 source commit 重建 exact messages 和正式请求；
2. 对 exact messages 执行一次 K3 Token Estimate；
3. 冻结估算请求/响应原始字节及全部摘要绑定；
4. 用加法不等式验证上下文；
5. 验证 cache-miss 税前费用上界不超过 USD 4.00；
6. 只有全部成立时才执行唯一一次 K3 Chat Completion；
7. 返回 `model` 必须精确为 `kimi-k3`，`finish_reason` 必须为 `stop`，且本地 Schema/语义验证全部通过。

## 10. 仍属 UNKNOWN 或需 live evidence 的事项

| 项目 | 状态 | 处置 |
|---|---|---|
| K3 在 Token Estimate runtime 的实际接受情况 | 静态文档冲突 | 用一次官方认证估算调用证明；失败即阻断 |
| Estimate 是否计入 `response_format` Schema 等非 message 字段 | UNKNOWN | 不得声称已计入；保留额外安全余量或另行证明 |
| 当前项目 Canonical Receipt Schema 对 K3/MFJS 的实际兼容性 | UNKNOWN | 先静态验证，再由唯一目标模型 live call 证明 |
| K3 reasoning 与 content 的精确 token 拆分 | UNKNOWN | 以响应 usage 和最大 completion 合同为边界 |
| 正式账号当前余额与实际税费 | UNKNOWN | 调用前做不泄密余额/预算检查；税前预算不冒充含税账单 |
| 正式调用的 actual returned model、finish reason、usage 与响应完整性 | UNKNOWN | 仅能由唯一正式调用的原始响应证明 |

## 放行判定

静态官方合同核验本身只支持：

```text
KIMI_K3_STATIC_TRANSPORT_CONTRACT = VERIFIED_WITH_DOCUMENTATION_INCONSISTENCY
tokenEstimateRuntimeAcceptance = UNKNOWN
formalChatCompletionAuthorizedByThisResearch = false
```

本研究不产生模型复核结论，不产生 Receipt，不改变任何 D1、Gate、Profile、Manifest 或工作包状态。
