# ADR 0013: Moonshot Kimi K3 单次独立复核传输候选

- 状态：Candidate
- 日期：2026-07-31
- 范围：P0–P2 合成数据阶段的独立模型复核传输
- 数据边界：SYNTHETIC_ONLY
- 被后续候选取代：无
- 未来传输候选取代：ADR 0012（仅面向本 ADR 生效后的新调用）

## 背景

ADR 0011 定义提供商无关的 Independent Review Policy、Review Bundle、隔离
证据和 Receipt 语义。ADR 0012 冻结了 `kimi-k2.7-code` 的历史候选传输，
但其单次上下文路线未取得合规 CLEAR Receipt。历史文件、失败证据、提交与
ADR 0012 必须继续逐字节保留，不能被本 ADR 改写、删除或表示为 K3 结果。

本 ADR 只增加一个未来候选传输。它不修改 D1、Gate、Profile、Manifest、
工作包状态或公开 HTTP 写入能力，也不赋予模型治理决定权。

## 候选决定

未来唯一候选传输固定为：

- provider：`moonshot`；
- model：`kimi-k3`；
- base URL：`https://api.moonshot.ai/v1`；
- Chat Completions endpoint：`POST /chat/completions`；
- Token Estimate endpoint：`POST /tokenizers/estimate-token-count`；
- context window：`1048576` tokens；
- 顶层 `reasoning_effort: "max"`；
- 请求中不发送 `thinking`；
- `tool_choice: "none"`，且完全省略 `tools`；
- `response_format.type: "json_schema"` 且 `strict: true`；
- `max_completion_tokens: 32768`；
- 不发送 `frequency_penalty`、`n`、`presence_penalty`、`temperature` 或
  `top_p`；
- fallback policy：`DISABLED_FAIL_CLOSED`；
- 税前调用预算上限：USD 4.00。

固定合同、官方来源索引、当前价格、字节防御上限和自哈希规则冻结在
`moonshot-kimi-k3.v2.json` 及其关闭字段 Schema v2 中。官方资料的查询时间、
实际阅读范围和已知歧义记录在
`docs/research/moonshot-kimi-k3-transport-contract-2026-07-31.md`。

禁止回退到 `kimi-k2.7-code`、`kimi-k2.7-code-highspeed`、Kimi Code API、
第三方代理或任何其他模型；也禁止在单次证明失败后自动进入分段复核。

## 追加式版本边界

本候选新增：

- K3 Config v2；
- `independent-review-material.v3`；
- K3 Token Estimate Evidence v1；
- Independent Review Transport Evidence v2；
- Independent Model Review Receipt v4。

K2.7 Config v1、既有 v1 Schema、Receipt v3、ADR 0012 和全部 K2.7 冻结
证据保持不变。它们只能说明历史候选、失败或阻断，不能成为 K3 运行时回退，
也不能冒充 K3 Receipt。

## R/S/E 信任拓扑

传输继续使用彼此分离且必须逐项闭合的 R/S/E 拓扑：

- **R（Runtime trust）**：已冻结、与待审提交不同且为其祖先的可信运行时
  commit、tree、Bootstrap、launcher、Runner、Schema、Validator 和完整依赖
  清单。R 负责从准确 Git 字节重建请求并验证证据；
- **S（Subject）**：被审查的准确 source commit、tree、patch、Review Bundle、
  Review Material、Prompt 和测试证据。S 只能作为待审字节，不能提供或改写
  本次 R；
- **E（External evidence）**：仓库外的原始 Token Estimate 请求/响应、正式
  请求/响应/content、Transport Evidence 和 Receipt。E 在写入后必须逐字节
  回读并由 R 核验，不能反向改变 S 或成为 D1 状态真相。

R、S、E 的 commit、tree、路径、字节数和 SHA-256 任一失配均失败关闭。
Receipt 自身不参与其所引用的请求或传输证据摘要，避免循环依赖。

## Review Material 与字节防御

`independent-review-material.v3` 继续使用长度前缀 UTF-8 Envelope，并把材料
预算提高到 1048576 bytes。固定防御上限为：

- Review Material：1048576 UTF-8 bytes；
- 完整请求：1572864 UTF-8 bytes；
- 原始响应：1048576 UTF-8 bytes。

这些上限的依据固定为
`TRANSPORT_DEFENSE_ONLY_NOT_CONTEXT_PROOF`。字节数不是 token 数，任何本地
字节门通过都不能表示模型上下文已证明。超限时不得裁剪、摘要替代、分段或
换模型。

## Token Estimate、上下文与预算门

正式调用前，R 必须从冻结 S 重建唯一的正式 K3 请求，再以完全相同的
`model` 和 `messages` 构造 Token Estimate 请求。Token Estimate Evidence
必须冻结：

- estimate 请求、响应的准确原始 UTF-8 字节；
- formal request、messages、Review Material、Review Bundle 和 Config 摘要；
- source commit/tree、runtime commit、model、endpoint 与时间；
- `estimatedInputTokens`、context、completion limit、安全余量和预算计算；
- 对官方接口实际覆盖范围的明确枚举。

安全上下文不等式为：

```text
estimatedInputTokens + 32768 + 8192 <= 1048576
```

预算按当前官方税前价格的保守 cache-miss 输入价和最大输出额度计算，并要求：

```text
worstCaseInputMicros + worstCaseOutputMicros <= 4000000
```

Token Estimate endpoint 当前只接收 `model` 与 `messages`。正式 Chat 请求还包含
`reasoning_effort`、Structured Output Schema、工具禁用字段和 completion limit；
官方资料尚未证明 estimate 结果覆盖全部模型可见输入，也未闭合永久思考 token
在 completion limit 与公开输出价格中的准确计费边界。因此，当前可取得的证据
coverage 只能是 `MESSAGES_ONLY`，`contextProved` 必须为 `false`。

只有未来官方合同和实际响应能够证明
`FULL_MODEL_VISIBLE_INPUT_PROVED`，且上下文、预算、摘要和模型全部匹配，才可
进入正式 K3 调用。否则稳定失败关闭为：

`KIMI_K3_SINGLE_CALL_CONTEXT_NOT_PROVED`

该失败不得触发正式 K3、分段复核或任何模型回退。

## 请求、响应与证据

正式 K3 请求只能包含固定字段：`model`、`messages`、`reasoning_effort`、
`tool_choice`、`response_format` 和 `max_completion_tokens`。任何 `thinking`、
`tools` 或固定禁止字段出现都必须在网络前拒绝。

若上下文门未来满足，正式响应还必须同时证明：

- HTTP 200，准确 endpoint，单次网络尝试；
- `actualReturnedModel` 精确为 `kimi-k3`；
- 恰好一个 choice，`finish_reason` 精确为 `stop`；
- `finish_reason=length`、截断、空 content、非 JSON、Schema 或语义失败均拒绝；
- usage 的输入、输出、总量和缓存量相互一致；
- 实际税前成本不超过 USD 4.00；
- 原始请求、响应、content、Token Estimate Evidence 和 Transport Evidence 的
  路径、字节数及 SHA-256 全部闭合；
- 请求、响应、日志、Receipt 和 Git 中不含密钥或 Authorization。

Transport Evidence v2 追加绑定 K3 协议、Token Estimate Evidence、usage 和
cost。Receipt v4 追加绑定 Token Estimate 的 Schema/证据/原始请求响应、
Material v3、Transport v2、provider/model、source/tree/bundle/prompt、全部
Schema 与 Validator、R/S/E 隔离和仓库前后快照。

## 凭据边界

Keychain 定位继续固定为 service `kimi-p2-independent-review`、account
`p2-independent-review`。只有可信父控制平面可在所有本地门通过后临时读取
一次凭据；子模型不得访问 Keychain。密钥值、Authorization、Cookie、邮箱或
账户信息不得显示、打印、记录、写入制品、Receipt、日志、模型输入或 Git。

凭据缺失或余额不可用以
`KIMI_API_CREDENTIAL_OR_BALANCE_REQUIRED` 失败关闭，且不得硬编码、从聊天
读取、改用其他凭据来源或回退其他模型。

## 治理效力

K3 Receipt 的最强结论只能是
`MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION`。它明确满足：

- `humanIndependentReviewSatisfied: false`；
- `humanReviewClaim: false`；
- `governanceEffect: NONE`；
- `selfAuthorizing: false`。

它不是人类独立复核、D1 事件、Gate 决定、P2 Profile Approval、工作包状态、
O02/O03 启动授权或 P3/生产发布批准。P3、真实企业数据和高风险范围继续要求
真实第二名人类复核。

## 后果

优势：模型合同、上下文与预算证明、传输结果和历史证据严格分离；官方接口
不足会稳定阻断正式调用；K2.7 不能静默复活。

代价：在 Moonshot 官方 Token Estimate 尚不能证明全部模型可见输入和思考
计费边界时，即使消息 token 数、字节上限和预算估算看似足够，也不会签发
Receipt。这是有意的失败关闭，不是实现失败或治理通过。
