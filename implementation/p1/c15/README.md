# C15 HumanDecision 与可靠工作流

当前工程状态：`IMPLEMENTED / VERIFIED`

当前范围：`P1_SYNTHETIC_ONLY`

| 边界 | 当前状态 |
|---|---|
| Tenant | 固定 3 个 Synthetic Tenant |
| 决定类型 | 仅 `SYNTHETIC_TEST_DECISION` |
| C0 Effect Adapter | 无网络、无企业凭据、`externalEffectCount = 0` |
| OA、U9、BI、任意 URL、企业 Connector | `P3_REQUIRED` |
| C18 | metadata-only Audit Intent + 已注册 Publisher + PostgreSQL Receipt/Event 持久绑定 |
| P1 合成验收 | `VERIFIED_P1_SYNTHETIC` |
| 生产部署与真实业务动作 | `NOT_VERIFIED` |

C15 建立“完整对象 → 展示差异/来源/风险 → 冻结哈希 → 专用决定仪式
→ 执行前重新鉴权 → 幂等合成执行 → 独立回读 → 补偿”的最小模块。
P1 的所有决定和 Effect 都是机制测试，不能迁移到 P3，也不能授权真实外部
副作用。

## 冻结验收

1. `prepare`、`decide`、`withdraw`、`execute` 是唯一公开工作流接口。
2. `DraftArtifact` 保存完整 Synthetic 候选对象。服务端验证固定 Workflow
   Catalog，再确定性计算 `differences`、`sources` 和 `risks`；请求不能自报
   这些展示结果。
3. Artifact 和 Decision 分别用 RFC 8785 JSON Canonicalization Scheme 与
   SHA-256 冻结。收件人、附件、规则、字段、模型、Skill、知识、任何引用、
   摘要或版本变化都会改变 Artifact 哈希。
4. `decide` 只接受专用 `decisionCeremony.verify` 返回的、绑定 Artifact
   哈希、展示哈希、Human Principal 和 leaf delegation 的短期证明。聊天
   “同意”、Stage Approval、LangGraph Interrupt、普通按钮字段均不构成决定。
5. 四个工作流动作均固定执行：

   ```text
   C05 首次解析
   → C06 operation-specific PEP
   → C05 最终解析且绑定不变
   → C03 最终 ACTIVE 准入
   ```

6. Approval、Withdrawal 和 Execute 各自绑定当次 leaf delegation。执行时
   Human/Workload Principal、Lifecycle Version 或 Security Epoch、Workflow
   Catalog binding、Artifact hash、Decision hash、有效期或撤回状态任一变化
   都失败关闭；Session/Delegation 合法续期可使用新的、经 C05/C06 重新验证
   的 leaf。
7. PostgreSQL 原子保存业务记录、幂等 CommandReceipt、metadata-only Audit
   Intent 及 Audit Outbox。Effect 与 Effect Outbox 也必须成对提交。
8. Effect Worker 只调用 `C15SyntheticEffectAdapter`。`effectKey` 对同一决定
   和 Artifact 稳定；提交、补偿、ACK 丢失和重试不会重复 effect。补偿后
   readback 明确返回 `COMPENSATED`，持久化失败后的重试仍可收敛。
9. Commit 后执行独立 readback。匹配则 `SUCCEEDED`；不匹配必须进入
   `COMPENSATED` 或 `COMPENSATION_FAILED`，不能伪报成功。
10. Memory 与真实临时 PostgreSQL 测试覆盖三 Tenant、并发幂等、重启、
    ACK 丢失、连接上下文清理、FORCE RLS、角色分权、不可篡改、恢复和
    未配对事务回滚；Worker 只能通过受控函数和一次性 lease token 完成任务，
    过期 `PROCESSING` 租约只能按新 lease version 重领。
11. Withdrawal 只在 Effect 尚未入队时成功；一旦执行已入队，
    `withdraw` 必须返回 `DECISION_ALREADY_EXECUTING`，不能伪报已撤回。
    Memory Store 和 PostgreSQL Store 都把 Withdrawal 保存为独立不可变
    事实，不修改原始 Decision 或其哈希。

## 深模块接口

```text
prepare(serverContext, request)
decide(serverContext, request)
withdraw(serverContext, request)
execute(serverContext, request)
```

调用者不管理状态机、哈希、差异、Outbox 或补偿。Memory Store 和 PostgreSQL
Store 是同一 Store seam 的两个 Adapter；C0 Synthetic Effect 和 C18 Audit
Publisher 是两个独立外部 seam。

## DraftArtifact

Candidate 的封闭字段为：

```text
operationId = SYNTHETIC_PREVIEW_EFFECT
recipients[]
attachments[]
rules[]
fields{}
model
skill
knowledge[]
```

引用只允许 `synthetic://`、`fixture://`、`test://`、`policy://` 和
`evidence://`。候选对象拒绝 `http(s)://`、凭据键、Secret/Token/Cookie 和
常见密钥值。Catalog 只列出三个 Synthetic Tenant 的有限引用、版本和摘要。

Artifact hash 覆盖：

```text
schemaVersion / Tenant / Artifact ID / kind
Workflow ref + version + catalog binding digest
完整 candidate
服务端计算的 differences + sources + risks
prepare 身份绑定 + C06 授权证据
createdAt
```

因此不能把“同一个页面大概没变”当成对象未变；必须逐字节重新规范化并比较
完整哈希。

## Synthetic Test Decision

Decision 固定为：

```text
decisionType = SYNTHETIC_TEST_DECISION
outcome = APPROVE
status = ACTIVE
productionReusable = false
externalEffectCount = 0
```

Decision hash 覆盖 Artifact/display hash、Human 和 Workload Actor 的
Lifecycle Version 与 Security Epoch、delegation chain digest、leaf
delegation、C06 evidence、专用 ceremony proof、decidedAt 和 expiresAt。
Withdrawal 是独立、不可变的事实；它不重写原始 Decision。

## 执行与补偿

`execute` 只排队，不在请求事务内产生副作用：

```text
重新验证决定和权限
→ 原子写 workflow_effect + effect_outbox + command_receipt
→ Worker 用 effectKey 幂等 commit
→ 独立 readback
→ 对账成功：SUCCEEDED
→ 对账不一致：compensate
→ COMPENSATED 或 COMPENSATION_FAILED
```

当前 Adapter 完全在内存中模拟 C0 effect，硬编码：

```text
networkRequestCount = 0
enterpriseCredentialCount = 0
externalEffectCount = 0
```

它不是企业 Connector，也不是未来 P3 写回能力。

## C18 审计 seam

C15 不绕过 C18。每次 prepare/approve/withdraw/queue/terminal outcome 都在
同一状态事务内保存 `c15-audit-intent.v1` 和 Audit Outbox。Intent 只含：

```text
Tenant / event type / subject IDs and SHA-256
Artifact / Decision / Effect IDs and SHA-256
Human / Workload / leaf delegation IDs
C06 decision/evidence/policy refs
correlationId / occurredAt
```

它不含 Candidate、Display、字段值、附件内容、Prompt、模型输入输出或 Tool
参数。C15 使用自己的封闭 SQL validator 验证该 Intent，不调用 C18 的内部
validator，也不向 C15 应用连接池授予 `aios_audit` 权限。
`C15AuditOutboxWorker` 只通过已注册的
`createC15C18AuditPublisher(...).publish(intent)` 窄接口调用真实
`AuditEvidenceService`。C18 以 C15 `intentId` 作为幂等键，原子保存
`audit_command_receipt` 与 `audit_event`；C15 只有在数据库外键和 Trigger
核对 Receipt、Event ID、Event hash 后才能进入 `PUBLISHED`。测试覆盖“C18
已提交、C15 ACK 丢失”后的同 Event 幂等重试。该联合验收仍仅使用冻结合成
Evidence Bundle，不表示已经接入生产归档或企业系统。

## PostgreSQL

固定迁移：

```text
0027_human_decision.sql
0028_human_decision_runtime_roles.sql
```

`c15_restore_role_bootstrap.v1.sql` 只用于在空白恢复集群预建迁移中引用的
NOLOGIN 角色；随后使用 `pg_dump`/`pg_restore` 恢复完整 Schema、数据、
RLS、策略和 Outbox。恢复不忽略对象 owner，并在目标集群重新核验 C15
Schema、八表和函数的 owner、PUBLIC ACL、八表 FORCE RLS，以及四个应用角色
的逐表最小权限。源和目标的 `pg_control_system().system_identifier` 必须
不同，不能把同一集群内换数据库误报为 fresh restore。

八张表全部 `ENABLE ROW LEVEL SECURITY` 且 `FORCE ROW LEVEL SECURITY`：

```text
draft_artifact
synthetic_test_decision
decision_withdrawal
workflow_effect
effect_outbox
audit_intent
audit_outbox
command_receipt
```

角色分工：

| 角色 | 允许 | 禁止 |
|---|---|---|
| `aios_c15_runtime` | 按签名 Tenant Scope 创建/读取 Artifact、Decision、Withdrawal、Effect、Receipt 和两个 Outbox 初始记录 | Worker 状态变更、删除历史 |
| `aios_c15_effect_worker` | 通过受控函数领取/完成 Effect，写终态 Audit Intent | 直接 `UPDATE` Effect/Outbox，读取 Artifact/Decision/Receipt |
| `aios_c15_audit_worker` | 通过受控函数领取 Audit Intent，并提交已持久化 C18 ACK | 直接 `UPDATE` Audit Outbox，读取业务正文或 Effect/C18 表 |
| `aios_c15_recovery_reader` | 按 Tenant 只读八表恢复 | 任何写入 |
| `aios_c15_owner` | 迁移和受控维护 | 不能作应用连接池 |

Store 递归核对当前身份和登录身份的 MEMBER/USAGE 角色闭包，只允许连接池
拥有唯一所需角色；同时拒绝 Superuser、BYPASSRLS、CREATEDB、CREATEROLE、
REPLICATION、所需角色上的 `ADMIN OPTION`，以及任何多余或缺失的 `aios_*`
Schema、Table、Column、Sequence、Function 有效权限。每个事务使用 C07 的
短期签名 scope 与 fence，提交或回滚后验证连接没有保留 Tenant 上下文。
`0028_human_decision_runtime_roles.sql` 同时撤销 C03 `aios_core` 的 PUBLIC
对象权限，使该门禁按文档列出的正式迁移即可复现，不依赖测试内补丁。

## 文件

| 文件 | 用途 |
|---|---|
| `draft-artifact.v1.schema.json` | 完整冻结 DraftArtifact Schema |
| `synthetic-test-decision.v1.schema.json` | P1 Decision Schema |
| `human-decision.openapi.v1.json` | 四个工作流命令契约 |
| `synthetic-workflow-fixtures.v1.json` | 三 Tenant 冻结 Catalog |
| `human-decision-verification-matrix.v1.json` | 规格到测试映射 |
| `lib/human-decision-workflow.mjs` | 深模块和 Memory Store |
| `lib/postgres-human-decision-store.mjs` | PostgreSQL Adapter |
| `lib/c15-c06-authorizer.mjs` | operation-specific C06 Adapter |
| `lib/c15-synthetic-effect-adapter.mjs` | 无网络 C0 Effect Adapter |
| `lib/c15-outbox-worker.mjs` | Effect 与 Audit Worker |
| `lib/c15-c18-audit-publisher.mjs` | C15 Intent 到真实 C18 服务的注册 Publisher |
| `postgresql/c15_restore_role_bootstrap.v1.sql` | fresh restore 最小角色引导 |
| `tests/integration/c15-postgres-restore.test.mjs` | 跨集群恢复后继续 Outbox |

## 验证

```text
sh scripts/run-c15-tests.sh
npm run lint
```

脚本创建两个一次性 PostgreSQL 17 集群，禁用 TCP，只通过本地 Unix Socket
运行；源集群完成并发、租约与真实 C18 Receipt/Event 绑定测试后，整库 dump
到全新集群，并继续 Effect Outbox；C18 不可用时恢复后的 Audit Outbox 保持
可重试失败而不伪造 ACK。恢复保留 owner，且目标端重新核验 PUBLIC ACL、FORCE RLS 和
runtime/effect/audit/recovery 最小权限。测试通过只表示 P1 合成机制的源码和
临时数据库证据，不表示生产部署、企业系统接入、真实 HumanDecision 或真实
外部效果已经完成。
