# ADR 0015: Kimi K3 Transport Contract v3候选

- 状态：Candidate
- 日期：2026-08-01
- 范围：P0–P2合成数据阶段的单次独立模型复核传输
- 数据边界：SYNTHETIC_ONLY
- 追加关系：只取代ADR 0013面向未来调用的v2候选，不改写其历史

对未来K3 v3调用，本ADR同时明确取代ADR 0014中的1048576-byte Material
放行门及“不得提高该上限”规则；ADR 0014的历史物化检查点、原始历史制品和
其他失败关闭规则继续保持不变。

## 背景

ADR 0014消除了五个历史派生证据制品的递归物化，但完整必要Material曾为
1108242 UTF-8 bytes。旧1048576-byte限制是本地传输防御值，不是K3上下文
上限的token证明。历史Config v2、Schema v2、Receipt v4、ADR 0013以及失败
证据必须继续逐字节保留。

## 决定

新增K3 Config v3。资源防御上限固定为：Material 4194304 bytes、完整请求
8388608 bytes、应用层响应1048576 bytes。其依据只能表示
`TRANSPORT_RESOURCE_CEILING_ONLY_NOT_CONTEXT_PROOF`，不能把字节数表示为token。

Token Estimate仍使用与正式调用逐字一致的`model`和`messages`。正式请求中除
messages之外的模型可见字段按
`JSON_UTF8_FIXED_REQUEST_WITHOUT_MESSAGES_V1`生成唯一UTF-8制品，固定上限
16384 bytes并绑定SHA-256。其token消耗始终按65536-token保守预留计算，调用者
不能降低或抵消该预留。

上下文放行要求：

```text
estimatedMessageInputTokens
+ 65536 nonMessageVisibleTokenReserve
+ 32768 maxCompletionTokens
+ 8192 safetyMarginTokens
<= 1048576
```

预算采用cache-miss输入价格，并把`estimatedMessageInputTokens + 65536`作为最坏
输入token；输出按32768-token上限计算。税前最坏成本必须不超过USD 4.00。

## 追加式制品

本候选新增Config v3、Config Schema v3、Token Estimate Evidence v2、Transport
Evidence v3和Receipt v5。Material v4历史引用与完整SOURCE/PATCH覆盖继续生效。
旧v2/v4制品只保留为历史，不得作为运行时回退。

## 失败关闭

模型、messages、Material、Config、Schema、非message制品或任一SHA-256失配；
非message字节超过16384；资源上限、上下文不等式或USD 4预算失败；请求出现
tools、非none tool choice或回退；响应不是HTTP 200、`kimi-k3`、单choice及
`finish_reason=stop`；Schema或语义失败，均不得签发Receipt或重试。

## 治理效力

本候选及未来模型Receipt最多只能表示
`MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION`。它不是人类独立复核、D1事件、Gate决定、
Profile Approval、工作包状态、O02/O03启动授权、部署或P3生产批准。
