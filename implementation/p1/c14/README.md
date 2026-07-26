# C14 模型网关、路由与本地推理

当前工程状态：`IMPLEMENTED / NOT_VERIFIED`

当前范围：`P1_SYNTHETIC_ONLY`

| 边界 | 当前状态 |
|---|---|
| 数据 | `SYNTHETIC_ONLY` |
| Provider | `C0_DETERMINISTIC_MOCK_ONLY` |
| 企业 Connector | `C0_DISABLED` |
| OA、U9、BI、企业端点、凭据和网络 | `P3_REQUIRED` |
| 真实云模型、本地 GPU、vLLM、生产限流和 HA | `NOT_VERIFIED` |
| C14 P1 合成实现 | `IMPLEMENTED` |
| C14 P1 合成验证 | `NOT_VERIFIED` |

C14 只负责在政策已经允许的集合中选择模型、调用确定性 C0 Mock，并记录
路由、受信用量与费率版本。它不授予员工权限，不保存 Prompt 或输入正文，也
不替代 C19 的正式跨模块用量账本。

## 唯一工作负载入口

```text
route(serverContext, request)
```

`serverContext` 由受信路由层提供，调用方不能在请求正文中选择 Tenant、地区、
Provider、数据密级或云/本地位置。请求正文精确为：

```text
sessionToken
delegationId
idempotencyKey
correlationId
taskRef
inputRef
inputSha256
```

任意额外字段都会被拒绝。`inputRef + inputSha256` 必须命中冻结的合成数据策略
目录；目录而不是调用者提供密级、Token 估算和 `LOCAL_ONLY` 要求。

## 运行顺序

```text
C05 第一次解析稳定行动身份
→ C06 MANAGE 决策
→ 决策与 Human/Actor/security epoch/委托链精确绑定
→ C05 最终再次解析且必须完全一致
→ C03 最终 ACTIVE 准入
→ 受信合成数据策略
→ 数据密级、地区、云/本地、能力、上下文和质量硬过滤
→ 只在允许集合内比较质量、成本和延迟
→ C07 签名范围内原子预留配额并写 PREPARED Route
→ 以稳定 effect key 调用 C0 Mock
→ 回读受信 Usage Receipt，按冻结费率计算成本并完成 Route
```

任何硬过滤都先于评分和 Provider 调用。Fallback 使用 PREPARED Route 中已经
冻结的 `candidateBindings`，不能重新扩大集合。`LOCAL_ONLY` 的所有本地候选
失败时，Route 失败；不会静默转云。

## 模型与政策目录

`synthetic-model-catalog.v1.json` 冻结：

- 模型引用、版本、内容 SHA-256 和 C0 Provider ID；
- LOCAL/CLOUD、允许密级、地区、能力和上下文；
- 质量、延迟、输入/输出费率及费率版本；
- 三个 Synthetic Tenant 各自的允许模型、地区、云端密级和日配额；
- 冻结 Task 所需能力、质量下限和最大输出。

目录加载后产生规范化 SHA-256。Route 同时保存目录哈希、Tenant policy
版本、所有候选的允许/拒绝理由以及最终模型内容哈希，后续 C08 Run 可准确
冻结该绑定。加载后的模型、Tenant Policy、Task 及其内部数组均递归冻结，
不能在目录哈希不变时扩大候选或回退集合。

## 幂等、Fallback 与费用

首次请求原子创建 `PREPARED` Route 并预留最大 Token/成本；同 Tenant 相同
`idempotencyKey + requestHash` 返回同一 Route，不同请求哈希冲突。

每个候选的 Provider effect key 由
`Tenant + Route + Model ref + Model version` 决定。Mock Provider 对 effect key
幂等，因此 Provider 已完成而确认丢失时，重试只会回读同一回执，不重复产生
合成计费。单元测试使用内存回执 Store；PostgreSQL 集成验收使用原子文件回执
Store，并销毁、重建 Provider 与 Gateway 实例证明重启后仍只产生一次合成
effect。该文件 Store 只属于 C0 Mock，不是生产 Provider 账本。

调用方不能上报 Token 或成本。完成 Route 只接受与 effect key、Provider、
模型引用和版本一致的受信回执；实际用量不得超过预留。成本由回执 Token 和
冻结费率版本确定。预留成本是按当前任务输入/输出 Token 上限逐个计算允许模型
费用后的最大值；最终成本必须是不超过该预留的安全整数。

公开成功响应只投影 OpenAPI `Route` 声明的十九个字段。Tenant、幂等键、
Authorization/Identity 证据、候选拒绝理由、Provider 尝试回执、内部配额和
时间戳只保留在受 Tenant 隔离的 Route 总账中，不直接返回给调用方。

## PostgreSQL 边界

`0021_model_gateway.sql` 创建 Route 总账、状态形状、不可变绑定、终态禁止更新
及禁止删除触发器。`0022_model_gateway_runtime_roles.sql` 创建无
`SUPERUSER/BYPASSRLS/DELETE` 的 C14 Runtime；每次数据库访问都要取得 C07
短时签名范围和事务围栏。三家 Synthetic Tenant 使用相同逻辑 ID 也不能看到
彼此数据。

## 不属于当前结论

- 没有真实 OpenAI、Anthropic、Google、Azure、Bedrock 或其他 Provider；
- 没有真实本地 GPU、vLLM、驱动、容量、模型权重或性能数据；
- 没有生产密钥、Virtual Key、企业区域政策或真实成本；
- 没有证明生产 HA、限流、Canary 效果和 SLO；
- 没有连接 OA、U9、BI 或任何目标企业；
- C19 仍需把模型、Tool、沙箱和基础设施费用统一对账。

因此，当前实现不能表述为“生产模型网关已上线”。
