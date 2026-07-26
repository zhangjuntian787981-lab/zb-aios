# C18 审计、证据与来源链

当前工程状态：`IMPLEMENTED / EVIDENCE_CANDIDATE`

当前范围：`P1_SYNTHETIC_ONLY`

| 边界 | 当前状态 |
|---|---|
| 数据 | `SYNTHETIC_ONLY` |
| 企业 Connector | `C0_DISABLED` |
| OA、U9、BI、企业端点、企业凭据和企业网络 | `P3_REQUIRED` |
| 生产部署、外部归档、签名检查点和密钥轮换 | `NOT_VERIFIED` |
| C18 P1 合成实现 | `IMPLEMENTED` |
| C18 P1 合成验证 | `EVIDENCE_CANDIDATE` |

C18 是独立的业务审计证据链。C08 的 Domain Event、运行状态和 Outbox
只能作为来源引用，不能替代 C18 AuditEvent；Git、应用日志、
OpenTelemetry 和数据库备份也都不能单独替代 C18。

## 冻结验收清单

完成 C18 P1 前必须同时满足：

1. 只接受受信服务端 Tenant/Workload 上下文和冻结的 Synthetic
   Evidence Bundle；浏览器、模型和请求正文不能选择 Tenant、Principal、
   数据库角色、外部端点或任意证据内容。
2. 每次追加前执行 C05 行动身份解析，最终再次解析且必须一致，再由 C03
   对同一 Synthetic Tenant 做最终 ACTIVE 准入。
3. 身份、授权、模型、知识、Skill、Tool、HumanDecision、结果，以及 C08
   状态引用都必须具备 `EvidenceRef + version + SHA-256`，并通过受限的
   W3C PROV Profile 关系串联。
4. Audit payload 使用 RFC 8785 JSON Canonicalization Scheme 规则规范化并
  计算 SHA-256；每个 Tenant 独立维护连续序号、前一事件哈希和事件哈希。
5. AuditEvent、C18 Outbox 和幂等回执在同一事务中提交；C08 Outbox 不得
   被当作 C18 Outbox。
6. 默认拒绝并且不持久化正文、Prompt、Tool 参数、模型输入输出、文件字节、
   Secret、Token、Cookie、Credential 或自由文本消息；只保留引用、版本、
   摘要代码和哈希。
7. PostgreSQL 对审计表启用并强制 RLS。Writer 只能追加及推进 Tenant 链头；
   业务管理员只能查询；Outbox Worker 只能租约和投递 C18 Outbox；三者不能
   共用角色或连接池。
8. 历史 AuditEvent 和幂等回执禁止 UPDATE/DELETE；链头只能单步推进；
   Outbox 只能走受限租约状态机。
9. Node 测试必须覆盖规范化、八类来源、正文拒绝、幂等、并发、崩溃、
   ACK 丢失、三 Tenant 隔离、篡改检测、导出恢复后全链验证和保留查询。
10. 真实临时 PostgreSQL 测试必须证明事务配对、FORCE RLS、最小角色权限、
    三 Tenant 隔离、并发连续链、管理员不可 UPDATE/DELETE、Worker 分权、
    导出验证和非法正文被数据库拒绝。

未通过全部测试前，本文件不得声称 `VERIFIED`、生产可用或企业系统已接入。

## 最小接口

工作负载追加：

```text
append(serverContext, request)
```

请求信封固定为：

```text
sessionToken
delegationId
idempotencyKey
correlationId
evidenceBundleRef
```

管理员查询和导出只通过只读 Store 端口；Outbox 投递只通过独立 Worker
端口。两者都不能调用追加入口。

## 哈希边界

`payloadSha256` 是规范化 Audit payload 的 SHA-256。事件哈希固定计算：

```text
SHA-256(
  RFC8785({
    eventId,
    tenantId,
    sequence,
    previousEventHash,
    payloadSha256
  })
)
```

每个 Tenant 的第 1 条事件使用固定 Genesis Hash：

```text
sha256:0000000000000000000000000000000000000000000000000000000000000000
```

P2 的外部签名检查点、密钥轮换和独立归档属于 O02/G2，不在本工作包内。

## 运行顺序

追加一条证据的固定顺序是：

```text
校验受信服务端路由和封闭请求
→ C05 首次解析 Human、Workload Actor 和 Delegation
→ 按 Tenant 解析冻结 Synthetic Evidence Bundle
→ C05 最终重新解析，身份必须完全一致
→ C03 最终 ACTIVE 准入
→ 把 Bundle 中的授权 EvidenceRef 绑定到 C07 Tenant Scope
→ 构造 metadata-only Audit payload 和 W3C PROV 图
→ RFC 8785 规范化并计算 payload/provenance SHA-256
→ 锁定 Tenant Audit Head
→ 原子写 AuditEvent + C18 Outbox + CommandReceipt
→ Audit Head 单步推进
```

C18 不重新作出业务授权决定。它保存上游授权决定的
`decisionId + EvidenceRef + policy version + SHA-256`。P1 的上游证据来自每个
Tenant 的冻结合成目录，不能由请求正文自报。

C18 的直接计划依赖保持为 F03、C03、C05、C08。数据库复用 C08 已依赖的 C07
签名 Tenant Scope 和事务围栏；这是现有平台隔离机制，不把 C08 Event 或
Outbox 当成 C18 审计。

## Audit payload 与来源链

每条 payload 固定包含：

- `identity`：C05 行动身份快照的引用、版本和哈希；
- `authorization`：上游授权 Decision 的引用、版本和哈希；
- `model`：模型路由/版本证据；
- `knowledge[]`：至少一个知识来源证据；
- `skill`：被解析 Skill Release 的证据；
- `tool`：Tool/Operation/Receipt 证据引用；
- `humanDecision`：HumanDecision 证据引用；
- `result`：结果 Artifact 证据引用；
- `c08State`：C08 Run/状态证据引用；
- `provenance`：受限 W3C PROV Activity、Agent、Entity 和关系。

PROV Profile 只允许：

```text
prov:wasAssociatedWith
prov:actedOnBehalfOf
prov:used
prov:wasGeneratedBy
prov:wasDerivedFrom
```

`result` 必须由同一 AuditedAction 生成，并从同一 C08 状态证据派生。身份、
授权、模型、知识、Skill、Tool、HumanDecision 和 C08 状态都必须被该
Activity `used`；Human 和 Workload Actor 都必须与 Activity 关联。

## 正文最小化

请求只能提供一个冻结 `evidenceBundleRef`，不能直接提交任意 payload。Core
构造固定字段后仍递归检查；PostgreSQL `metadata_only(jsonb)` 再独立检查。

以下字段和同义写法默认拒绝：

```text
body / content / text / message / raw
prompt / promptText
input / output / modelInput / modelOutput
toolArguments
fileBytes / bytes
secret / token / credential / password / cookie / authorizationHeader
```

明显的 Bearer、API Key、Private Key 和 `secret/token/password=value` 形态也
会被拒绝。AuditEvent 和 CloudEvent 仅保存引用、版本、ID、摘要代码、时间和
SHA-256，不保存文件、对话、Prompt、Tool 参数或模型输入输出正文。

## PostgreSQL 权限与事务

固定迁移：

```text
0023_audit_evidence.sql
0024_audit_evidence_runtime_roles.sql
```

四张表均启用并强制 RLS：

```text
audit_head
audit_event
audit_outbox
audit_command_receipt
```

角色职责固定：

| 角色 | 允许 | 明确禁止 |
|---|---|---|
| `aios_c18_writer` | 追加 Event/Outbox/Receipt，单步推进 Head | DELETE 历史；更新 Outbox 投递状态 |
| `aios_c18_reader` | 按受签 Tenant Scope 查询 Event/Head | INSERT、UPDATE、DELETE；读取 Outbox/Receipt |
| `aios_c18_outbox_worker` | SELECT/UPDATE C18 Outbox | 读取或改变 AuditEvent/Head/Receipt |
| `aios_c18_owner` | 迁移和受控维护 | 不能作为应用连接池角色 |

Writer、Reader、Worker 和 Scope Signer 必须使用四个不同连接池。Store 会拒绝
SUPERUSER、BYPASSRLS、同时拥有多个 C18 角色或复用连接池的配置。

`audit_event` 和 `audit_outbox` 使用双向、延迟检查的外键，缺少任一方就不能
提交；CommandReceipt 和 Audit Head 也引用同一 Event。历史 Event/Receipt
触发器禁止 UPDATE/DELETE；Head 触发器只接受 `sequence + 1` 且前哈希相符的
已插入 Event；Outbox 触发器只接受受限租约状态机。

## 独立 Outbox Worker

`lib/c18-audit-outbox-worker.mjs` 只调用：

```text
claimOutbox
completeOutbox
failOutbox
```

Publisher 必须回 ACK 同一个 Event ID。Worker 崩溃后由过期租约接管；Publisher
已接收但 ACK 丢失时，用完全相同的 CloudEvent ID 重试。消费者必须以该 ID
幂等。事件类型固定为：

```text
product.aios.audit-evidence-recorded.v1
```

它满足 F03 CloudEvents 1.0 外壳，但不等于消息 Broker、外部归档或生产投递已
验证。

## 查询、保留与恢复

业务查询必须同时给出 Tenant Scope、起止序号、起止时间和不超过 500 的
`limit`。当前合成审计类别为 `AUDIT_7Y`，表示最少保留意图；P1 没有自动删除
Worker。Legal Hold、正式删除授权、外部归档、签名检查点和密钥轮换仍属于
O02/G2。

导出格式固定为 `c18-audit-export.v1`。恢复验证从 Genesis 开始，逐条重新计算：

1. 连续序号；
2. `previousEventHash`；
3. RFC 8785 payload SHA-256；
4. Audit Event Hash。

任何 payload、序号、前哈希、事件哈希或 Tenant 变化都会以
`AUDIT_CHAIN_TAMPERED` 失败关闭。

## 当前验证结果

本轮已经实际执行：

```text
Targeted Node：18 PASS，0 FAIL
真实临时 PostgreSQL 17：8 PASS，0 FAIL
全仓 npm test（含 build）：486 PASS，0 FAIL
全仓 ESLint：PASS
```

真实 PostgreSQL 测试包括 20 路并发、三 Tenant、FORCE RLS、真实角色权限、
原子 Event/Outbox/Receipt、数据库正文拒绝、Worker 崩溃与 ACK 丢失、导出
恢复和篡改检测。它只证明本机临时 PostgreSQL 17 上的 P1 Synthetic 行为，
不能升级为生产结论。

## 仍未验证

- 任何目标企业、OA、U9、BI、真实人员、真实 KPI 或真实业务数据；
- 生产数据库 HA、跨区域恢复、容量、SLO 或持续运维；
- 真实消息 Broker、外部 WORM/Object Lock 归档和消费者；
- P2 签名检查点、密钥轮换、Legal Hold 和正式销毁；
- 企业保留法规、隐私要求或管理员职责审批；
- P3 企业 Connector 和真实上游 EvidenceRef。

因此当前只能表述为：

> C18 P1 Synthetic 实现和候选证据已完成，生产与企业集成仍为
> `NOT_VERIFIED / P3_REQUIRED`。
