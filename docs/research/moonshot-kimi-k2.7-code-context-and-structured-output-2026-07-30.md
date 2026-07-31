# Moonshot Kimi K2.7 Code 上下文与结构化输出边界核验

- 查询日期：2026-07-30
- 研究对象：`kimi-k2.7-code`
- API 基线：`https://api.moonshot.ai/v1`，`POST /chat/completions`
- 资料边界：仅使用 Moonshot/Kimi 官方文档、官方 OpenAPI 和 Moonshot 官方模型仓库
- 执行边界：未调用 Moonshot API，未读取或使用任何凭据，未进行模型复核

## 结论

本次研究所核验的 **648,630 UTF-8 bytes 测量样本**不能被证明可安全放入
`kimi-k2.7-code` 的单次请求，必须失败关闭。该数值是研究时快照，不冒充
后续冻结 source commit 的最终 Material 字节数；最终数值必须由同一冻结
commit 重新生成并单独报告。

原因如下：

1. Moonshot 官方将 `kimi-k2.7-code` 的上下文标为 **256K tokens**，而上下文同时容纳输入和输出，不是纯输入额度。[Kimi 模型列表](https://platform.kimi.ai/docs/models)；[K2.7 Code 指南](https://platform.kimi.ai/docs/guide/kimi-k2-7-code-quickstart)
2. Moonshot 只给出了自然英语约 **3–4 个字符/token** 的粗略说明，并未给出 UTF-8 bytes 到 tokens 的安全上界。代码、JSON、Git patch、哈希、路径和非 ASCII 内容不能按自然英语比例作保证。[基本概念](https://platform.kimi.ai/docs/introduction)
3. 按官方粗略比例中更保守的 `3 bytes/token` 暂算，648,630 bytes 已约为 **216,210 input tokens**。再预留官方指南所述的默认 **32,768 completion tokens** 后，仅余 **13,166 tokens**，需要同时覆盖系统提示、消息封装、结构化输出 Schema、其他指令及估算误差；余量只有完整 262,144-token 窗口的约 **5.02%**。
4. 该研究样本还超过现有 **576 KiB（589,824 bytes）** 防御性字节上限 **58,806 bytes（约 9.97%）**。
5. 官方提供按模型估算 token 的接口，但该接口需要认证；本次未获授权调用，也没有使用任何密钥。[Token 估算接口](https://platform.kimi.ai/docs/api/estimate)

因此，**不得以字节数、自然语言换算或 strict JSON Schema 代替完整请求的 token 预检**。

## 已确认的官方能力与限制

### 模型和上下文

| 项目 | 官方事实 | 本次判定 |
|---|---|---|
| 模型 | `kimi-k2.7-code` 是 K2.7 的 coding 模型 | 已确认 |
| API 上下文 | 官方文档标为 256K | 已确认 |
| 模型位置上限 | Moonshot 官方模型仓库的 `config.json` 为 `max_position_embeddings: 262144` | 已确认；这是第一方模型制品，不单独扩大托管 API 合同 |
| 思考模式 | K2.7 必须启用 thinking，不支持关闭 | 已确认 |
| `tool_choice` | K2.7 支持 `auto` 或 `none` | 已确认 |
| 默认输出额度 | K2.7 指南记录 `max_tokens` 默认 32K（32768） | 已确认 |
| 硬性最大输出额度 | 静态公开文档和 OpenAPI 未给出 `kimi-k2.7-code` 的独立数值上限 | **UNKNOWN** |

来源：[K2.7 Code 指南](https://platform.kimi.ai/docs/guide/kimi-k2-7-code-quickstart)、[Chat API](https://platform.kimi.ai/docs/api/chat)、[官方 OpenAPI](https://platform.kimi.ai/docs/openapi.json)、[Moonshot 官方模型配置](https://huggingface.co/moonshotai/Kimi-K2.7-Code/blob/main/config.json)。

Chat API 的确定性约束是：当输入 tokens 与指定的 completion token 额度之和超过模型上下文时，请求返回 `invalid_request_error`。[Chat API](https://platform.kimi.ai/docs/api/chat)

### Strict JSON Schema

官方结构化输出合同支持：

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

K2.7 是官方推荐的稳定结构化输出模型，Schema 需符合 Moonshot JSON Format Schema（MFJS）。`strict: true` 约束最终 JSON 字段和类型，但不解决以下问题：

- 输入是否超出上下文；
- 输出是否因 `finish_reason=length` 截断；
- 业务语义是否正确；
- Canonical Receipt Schema 和本地语义验证是否通过；
- 原始 UTF-8 响应字节是否与冻结摘要一致。

官方明确要求处理 `finish_reason=length`，并建议缩短输入、简化 Schema 或调整输出额度。[结构化输出指南](https://platform.kimi.ai/docs/guide/response_format)

因此，Kimi 返回内容仍必须经过：原始字节冻结、SHA-256、JSON 解析、Canonical Schema 校验、语义校验和绑定校验。

## 648,630-byte 测量样本计算

以下换算仅用于说明风险，**不是 provider-proven token count**：

| 假设 | 估算输入 tokens | 加 32,768 输出预留 | 相对 262,144 上下文 |
|---|---:|---:|---:|
| 4 bytes/token | 162,157.5 | 194,925.5 | 余 67,218.5 |
| 3 bytes/token | 216,210 | 248,978 | 余 13,166 |
| 2 bytes/token | 324,315 | 357,083 | 已超出 |

Review Material 并非普通自然英语，而是包含代码、JSON、diff、哈希和路径的混合材料。官方没有证明 `3–4 characters/token` 可作为这类输入的最坏情况保证；因此不能选取表中的乐观一行作为放行依据。

## 推荐的冻结门禁

### 1. 字节门只作为传输防御

保留：

```text
reviewMaterialUtf8Bytes <= 589824
```

但必须将它明确标记为：

```text
TRANSPORT_DEFENSE_ONLY_NOT_CONTEXT_PROOF
```

576 KiB 在 `3 bytes/token` 粗略换算下正好是 196,608 input tokens；加 32,768 output reserve 后是 229,376 tokens，余 32,768 tokens。这个结果可以支持本地保守策略的选择，但仍不是官方证明的安全字节预算。

**可证明的 provider byte budget：UNKNOWN。**

### 2. 网络调用前增加精确 token 门

冻结完整最终请求材料后，使用官方：

```text
POST /v1/tokenizers/estimate-token-count
model = kimi-k2.7-code
```

估算必须绑定准确模型和最终 messages。估算请求、返回值及其 SHA-256 应作为只读预检证据冻结。若估算接口不计算 `response_format` Schema 或其他请求字段，其 token 成本必须另行计入；官方静态文档没有证明估算器会计入这些字段，因此该点保持 **UNKNOWN**。

建议本地策略：

```text
estimatedCompleteInputTokens <= 196608
completionReserveTokens = 32768
safetyMarginTokens = 32768
estimatedCompleteInputTokens
  + completionReserveTokens
  + safetyMarginTokens
  <= 262144
```

这是 ZB-AIOS 的保守治理门槛，不是 Moonshot 声明的产品保证。任何估算失败、模型不匹配、请求材料变化或总预算超限均应失败关闭。

### 3. 输出门

一次实际调用只有同时满足以下条件才可进入 Receipt 校验：

- 返回模型与请求模型精确匹配；
- `finish_reason` 表明输出完整，不能是 `length`；
- `message.content` 非空；
- 原始 UTF-8 字节及 SHA-256 已冻结；
- Transport Schema、Canonical Receipt Schema 和语义验证全部通过；
- Bundle、Prompt、Schema、source commit 与模型配置摘要全部匹配。

## 仍属 UNKNOWN 的事项

| 项目 | 状态 | 影响 |
|---|---|---|
| 托管 API 对 `kimi-k2.7-code` 的硬性最大 completion tokens | UNKNOWN | 不能把默认 32K解释成硬上限或保证 |
| thinking tokens 与最终 `content` 在 completion 额度中的精确分配 | UNKNOWN | K2.7 强制 thinking，输出余量必须保守 |
| 文本请求体的独立 HTTP byte 上限 | UNKNOWN | 不能用多模态请求体限制推断文本限制 |
| 研究时 648,630-byte 样本的准确 token 数 | UNKNOWN | 未调用官方认证估算接口 |
| Token 估算接口是否计入 `response_format` Schema | UNKNOWN | 必须单独核验或保守计入 |
| 当前 Canonical Schema 是否完全符合 MFJS | UNKNOWN | 需先做官方静态兼容校验，再由唯一获批的目标模型请求验证 |
| 结构化输出在目标 Schema 上的生产稳定性 | UNKNOWN | strict 仍可能因长度截断或业务语义错误失败 |

## 放行结论

```text
KIMI_REVIEW_MATERIAL_CONTEXT_READINESS = BLOCKED
reasonCode = KIMI_REVIEW_MATERIAL_CONTEXT_FIT_NOT_PROVED
researchSnapshotReviewMaterialUtf8Bytes = 648630
currentTransportCapBytes = 589824
providerProvenByteBudget = UNKNOWN
networkCallAuthorized = false
```

最小下一步是先将完整 Review Material 缩减到防御性字节上限内，再在单独授权且凭据可用时，对冻结的最终请求执行一次官方 token 估算。只有 token 门、输出预留和安全余量全部成立，才具备发起唯一 Kimi 复核请求的上下文准备度；这仍不等于模型复核 CLEAR，更不产生任何 D1、Gate、Profile 或工作包治理效力。
