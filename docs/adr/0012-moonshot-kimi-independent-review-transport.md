# ADR 0012: Moonshot Kimi 独立复核传输候选

- 状态：Candidate
- 日期：2026-07-30
- 范围：P0–P2 合成数据阶段的独立模型复核传输
- 数据边界：SYNTHETIC_ONLY

## 背景

ADR 0011 定义了提供商无关的 Independent Review Policy、Review Bundle、
隔离证据和 Receipt 语义。此前 Terra 运行记录只证明了失败或不完整的候选
路径，不能冒充当前独立复核结论。当前需要在不削弱 ADR 0011 边界的前提下，
为一个固定模型增加最小传输适配。

## 候选决定

当前唯一候选传输固定为：

- provider：`moonshot`；
- model：`kimi-k2.7-code`；
- base URL：`https://api.moonshot.ai/v1`；
- endpoint：`POST /chat/completions`；
- credential environment name：`MOONSHOT_API_KEY`；
- Keychain service 建议名：`kimi-p2-independent-review`；
- `thinking: {"type":"enabled"}`；
- `tool_choice: "none"`；
- 请求中不提供 `tools`；
- `response_format.type: "json_schema"` 且 `strict: true`；
- 不主动设置 `frequency_penalty`、`n`、`presence_penalty`、
  `temperature` 或 `top_p`；
- 禁止任何模型或端点回退。

以上准确值、576 KiB Review Material、768 KiB 完整请求和 64 KiB 原始响应
UTF-8 上限，以及禁用回退策略，冻结在
`moonshot-kimi-k2.7-code.v1.json`。这些是保守的固定字节上限，不声称等价于
模型 token 上下文容量；任一上限越界均失败关闭。配置的 `configSha256` 是删除
`configSha256` 字段后，对键按字典序递归排序的 canonical JSON UTF-8 字节
计算的 SHA-256。

## Review Material 与上下文边界

模型不能读取仓库、实现会话或隐藏上下文。调用前必须生成关闭字段的
`independent-review-material.v1`，其中逐项内嵌并绑定：

- 准确 Review Bundle；
- base/source commit、tree 和 patch；
- 规范与相关源码；
- 测试证据；
- reviewer prompt；
- Canonical Output Schema；
- Canonical Receipt Schema；
- 不含凭据值、Authorization、Cookie、邮箱或账户信息的固定 Moonshot/Kimi
  模型可见协议投影。

每个 section 都绑定路径、UTF-8 字节数和 SHA-256，Material 自身也使用
canonical JSON 自哈希。实际序列化 Material 超过固定上下文预算时必须以
`KIMI_REVIEW_MATERIAL_CONTEXT_BUDGET_EXCEEDED` 失败关闭；不得裁剪材料、
静默改用其他模型或代理端点。

完整 provider config 的准确字节通过 Material binding、请求制品和 Receipt
摘要在本地验证。若该文件属于被审查提交，它也会作为源码进入 Material，
因此非秘密的环境变量名和 Keychain service 建议名可能作为配置源码被审查；
任何实际凭据值、Authorization 或账户信息均不得进入模型请求。

## 请求、响应与 Receipt

传输适配器只负责固定 Moonshot 请求和原始响应捕获。提供商无关的 Policy、
Bundle、Output Schema 和语义 Validator 继续复用。

即使服务端声称执行 strict JSON Schema，客户端仍必须：

1. 固定原始请求、原始响应和模型 `content` 的准确 UTF-8 字节；
2. 分别计算并冻结 SHA-256；
3. 解析 `content`；
4. 使用冻结的 Canonical Output Schema 校验；
5. 使用现有独立复核语义验证；
6. 核对 provider、requested/actual model、base URL、source commit、
   Bundle、Prompt、Schema 和配置绑定；
7. 任一失配、空输出、截断、非 JSON、超时或网络失败均失败关闭。

`independent-model-review-receipt.v3` 追加绑定 Moonshot/Kimi 模型身份、
Review Material、Canonical Schema、原始请求/响应/content、Validator
版本、API 无工具隔离、仓库前后快照与记录时间。Moonshot 当前直接接收
Canonical Output Schema，因此 `providerTransportSchemaSha256` 为 `null`；
未来如确需传输 Schema 适配，必须冻结其准确字节，且最终输出仍须通过
Canonical Schema 与语义验证。

历史 Terra 证据必须保留，但 Receipt v3 固定
`historicalTerraEvidenceAccepted: false`，不得作为当前 Kimi 复核结果。

## 凭据和隔离

只有调用进程可以读取 `MOONSHOT_API_KEY`。密钥和 Authorization 不得进入
Review Material、请求制品、响应制品、日志、Receipt 或 Git。缺少密钥时，
必须在发起网络请求前返回
`KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED`。

Kimi 只获得两个消息：冻结 reviewer prompt 和冻结 Review Material。API
请求不给模型文件、Shell、Git、浏览器、D1、Sites 或治理决定工具。传输前后
必须绑定同一仓库 HEAD、tree、工作区状态和受保护文件摘要。

## 不采用项

- `gpt-5.6-terra`、DeepSeek、`kimi-k3`、
  `kimi-k2.7-code-highspeed` 以及第三方代理端点：`REJECT`，不得作为自动
  或人工静默回退。
- 运行时执行 GitHub API 或将仓库凭据提供给模型：`REJECT`。
- 仅凭 strict JSON Schema 跳过本地 Canonical Schema 或语义校验：
  `REJECT`。
- 以普通测试通过、Git commit 或聊天确认冒充独立复核 Receipt：
  `REJECT`。

## 治理效力

This ADR is a candidate and has no governance effect.

This ADR does not activate Independent Review Policy v2.

This ADR does not accept historical Terra evidence as a Kimi review.

This ADR does not satisfy independent human review.

This ADR does not change P1-B11, D1, Gate, Profile, Manifest, Ruleset, or any
work-package state.

This ADR does not authorize or start O02 or O03.

P3、生产发布及 ADR 0011 列出的高风险范围继续要求真实第二名人类复核。
