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
   状态引用都必须具备 `EvidenceRef + version + SHA-256`；身份还必须保存可独立
   复算的最小 metadata artifact，账号、链接和会话只保留 SHA-256。目录中的
   每个引用必须解析到冻结的 Tenant/type/version/artifact digest，再通过受限的
   W3C PROV Profile 关系串联。
4. Audit payload 使用 RFC 8785 JSON Canonicalization Scheme 规则规范化并
   计算 SHA-256；事件哈希同时绑定 record schema、Tenant kind 和 createdAt；
   每个 Tenant 独立维护连续序号、前一事件哈希和事件哈希。
5. AuditEvent、不可变 DeliveryIntent、初始 C18 Outbox 状态和幂等回执在同一
   事务中提交；Event 在提交时必须同时具备三者。恢复导入只能由隔离的
   Recovery Writer 跳过初始 Outbox 检查，以允许已发布并清理 Outbox 状态的
   历史证据恢复；C08 Outbox 不得被当作 C18 Outbox。
6. 默认拒绝并且不持久化正文、Prompt、Tool 参数、模型输入输出、文件字节、
   Secret、Token、Cookie、Credential 或自由文本消息；只保留引用、版本、
   摘要代码和哈希。
7. PostgreSQL 对五张 C18 表启用并强制 RLS。Writer、业务 Reader、Outbox
   Worker、Recovery Reader、Recovery Writer、Retention Worker 和 C07 Scope
   Signer 必须使用不同的最小权限角色和连接池。
8. 历史 AuditEvent、DeliveryIntent 和幂等回执禁止 UPDATE/DELETE；链头只能
   单步推进；Outbox 只能走受限租约状态机，只有 Retention Worker 能删除已
   发布满 30 天且没有 Legal Hold 的投递状态。
9. Node 测试必须覆盖完整 RFC 8785 输入边界、九类冻结来源及 digest、封闭
   payload/PROV、可复算身份 artifact、C05 安全字段、正文拒绝、幂等、并发、
   崩溃、ACK 丢失、三 Tenant 隔离、篡改检测、Head/DeliveryIntent/回执/
   Outbox 恢复和保留查询。
10. 真实临时 PostgreSQL 测试必须证明四件套事务配对、FORCE RLS、最小角色
    权限、三 Tenant 隔离、并发连续链、C18 运行角色不可 UPDATE/DELETE、
    Worker 分权、数据库时间租约、独立保留清理、向全新 PostgreSQL 的隔离
    恢复、真实 `pg_dump/pg_restore` 和非法正文被数据库拒绝。DB superuser
    属于受控运维边界，不在运行角色不可变性证明范围内。

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
端口。恢复导入只通过 `restoreChain(scope, verifiedBundle)` 和专用 Recovery
Writer 连接池。三者都不能调用追加入口。

## 哈希边界

`payloadSha256` 是规范化 Audit payload 的 SHA-256。身份 artifact 作为 payload
的一部分，因此其内容和摘要也进入同一哈希链。事件哈希固定计算：

```text
SHA-256(
  RFC8785({
    schemaVersion: "c18-audit-record.v1",
    eventId,
    tenantId,
    tenantKind,
    sequence,
    previousEventHash,
    payloadSha256,
    createdAt
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
→ 在 Synthetic Evidence Registry 中逐项核对 type/version/artifact digest
→ C05 最终重新解析，身份必须完全一致
→ C03 最终 ACTIVE 准入
→ 把 Bundle 中的授权 EvidenceRef 绑定到 C07 Tenant Scope
→ 构造 metadata-only Audit payload 和 W3C PROV 图
→ RFC 8785 规范化并计算 payload/provenance SHA-256
→ 锁定 Tenant Audit Head
→ 原子写 AuditEvent + DeliveryIntent + C18 Outbox 状态 + CommandReceipt
→ Audit Head 单步推进
```

C18 不重新作出业务授权决定。它保存上游授权决定的
`decisionId + EvidenceRef + policy version + SHA-256`。P1 的上游证据来自每个
Tenant 的冻结合成目录，不能由请求正文自报。目录引用必须在
`synthetic-evidence-registry.v1.json` 中找到对应的最小冻结 Artifact，并重新
计算 Artifact SHA-256；仅有格式正确的占位哈希不算证据。

C18 的直接计划依赖保持为 F03、C03、C05、C08。数据库复用 C08 已依赖的 C07
签名 Tenant Scope 和事务围栏；这是现有平台隔离机制，不把 C08 Event 或
Outbox 当成 C18 审计。

## Audit payload 与来源链

每条 payload 固定包含：

- `identity`：C05 行动身份的注册引用、版本、哈希和最小 metadata artifact；
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
构造固定字段后仍递归检查；PostgreSQL `metadata_only(jsonb)` 只允许冻结的
Audit payload、行动身份 artifact、证据引用、PROV 图和 CloudEvent/data
字段与格式。任意深度的未知键、正文值、数组注入和 Secret pattern 都拒绝。

以下字段和同义写法默认拒绝：

```text
body / content / text / message / raw
prompt / promptText
input / output / modelInput / modelOutput
toolArguments
fileBytes / bytes
secret / token / credential / password / cookie / authorizationHeader
apiKey / accessKey / clientSecret / privateKey
```

明显的 Basic/Bearer、常见云/API/GitHub Key、Private Key 和
`api_key/access_key/client_secret/secret/token/password=value` 形态也会被
拒绝。AuditEvent 和 CloudEvent 仅保存引用、版本、ID、摘要代码、时间和
SHA-256，不保存文件、对话、Prompt、Tool 参数或模型输入输出正文。

身份 artifact 不保存 `sessionToken`、账号 ID、链接 ID 或会话 ID；后三者只保存
对原值的 RFC 8785 SHA-256，并保留 Principal/Delegation/Purpose 引用、生命周期
版本、安全 epoch 和委托到期时间。

## PostgreSQL 权限与事务

固定迁移：

```text
0023_audit_evidence.sql
0024_audit_evidence_runtime_roles.sql
```

全新 PostgreSQL 集群在执行 `pg_restore` 前，必须先运行版本化的
`postgresql/c18_restore_role_bootstrap.v1.sql`。它只创建 dump 中 Owner、
Policy 和 ACL 所引用的 C07/C18 `NOLOGIN` 最小权限角色，不创建应用登录、不加载
Schema，也不替代上述迁移。

五张表均启用并强制 RLS：

```text
audit_head
audit_event
audit_delivery_intent
audit_outbox
audit_command_receipt
```

角色职责固定：

| 角色 | 允许 | 明确禁止 |
|---|---|---|
| `aios_c18_writer` | 原子追加 Event/DeliveryIntent/Outbox/Receipt，单步推进 Head | DELETE 历史；更新 Outbox 投递状态 |
| `aios_c18_reader` | 按受签 Tenant Scope 查询 Event/Head | INSERT、UPDATE、DELETE；读取 Outbox/Receipt |
| `aios_c18_outbox_worker` | SELECT/UPDATE C18 Outbox，并只读其 DeliveryIntent Event | 读取或改变 AuditEvent/Head/Receipt |
| `aios_c18_recovery_reader` | 只读 Event/DeliveryIntent/Receipt/非终态 Outbox，生成恢复包 | INSERT、UPDATE、DELETE |
| `aios_c18_recovery_writer` | 仅向空 Tenant 导入已完整验证的恢复包 | 业务查询、UPDATE、DELETE、跨 Tenant 导入 |
| `aios_c18_retention_worker` | 删除满足 30 天、PUBLISHED、无 Legal Hold 的 Outbox 状态 | 删除 Event/DeliveryIntent/Receipt；修改任何审计证据 |
| `aios_c18_owner` | 迁移和受控维护 | 不能作为应用连接池角色 |

Writer、Reader、Outbox Worker、Recovery Reader、Recovery Writer、Retention
Worker 和 Scope Signer 必须使用七个不同连接池。Store 会递归核对当前身份与
登录身份的 MEMBER/USAGE 角色闭包，只允许唯一所需角色；同时拒绝 SUPERUSER、
BYPASSRLS、CREATEDB、CREATEROLE、REPLICATION，以及任何多余或缺失的
`aios_*` Schema、Table、Column、Sequence、Function 有效权限；所需角色的
成员关系也不得带 `ADMIN OPTION`。

`audit_event` 分别与 `audit_delivery_intent`、`audit_command_receipt` 使用
双向、延迟检查的外键；另有延迟约束触发器要求 Writer 首次提交 Event 时必须
具备 Outbox。缺少三者之一都不能提交。Outbox 只保存可清理的投递状态，并引用
不可变 DeliveryIntent 中的 CloudEvent。历史
Event/DeliveryIntent/Receipt 触发器禁止 UPDATE/DELETE；Head 触发器只接受
`sequence + 1` 且前哈希相符的已插入 Event；Outbox 触发器只接受受限租约状态
机和专用 Retention Worker 的合规清理。

## 独立 Outbox Worker

`lib/c18-audit-outbox-worker.mjs` 只调用：

```text
claimOutbox
completeOutbox
failOutbox
```

Publisher 必须回 ACK 同一个 Event ID。Worker 崩溃后由过期租约接管；Publisher
已接收但 ACK 丢失时，用完全相同的 CloudEvent ID 重试。消费者必须以该 ID
幂等。调用方只提交租约时长和重试时长；领取、过期、完成、失败和下次可用
时间全部由 PostgreSQL `statement_timestamp()` 计算。租约最长 300 秒，失败
重试最长 3600 秒，调用方不能伪造绝对时间。事件类型固定为：

```text
product.aios.audit-evidence-recorded.v1
```

它满足 F03 CloudEvents 1.0 外壳，但不等于消息 Broker、外部归档或生产投递已
验证。

## 查询、保留与恢复

业务查询必须同时给出 Tenant Scope、起止序号、起止时间和不超过 500 的
`limit`。AuditEvent、CommandReceipt 和 DeliveryIntent 使用 `AUDIT_7Y`；
DeliveryIntent 保存不可变 CloudEvent。Outbox 表只保存投递状态，发布满 30 天
后，专用 Retention Worker 每次最多删除 500 条且仅删除
`PUBLISHED + legal_hold=false` 的状态，绝不删除上述三类审计证据。

恢复格式固定为 `c18-audit-recovery.v1`，由专用 Recovery Reader 在同一事务中
读取可验证 Head、完整 Event 链、每条 Event 的不可变 DeliveryIntent 与
CommandReceipt，以及全部非 PUBLISHED Outbox 状态，并对整个恢复包计算
RFC 8785 SHA-256。恢复验证从 Genesis 开始，逐条重新计算：

1. 连续序号；
2. `previousEventHash`；
3. RFC 8785 payload SHA-256；
4. Audit Event Hash；
5. Head 与最后一条 Event 完全一致；
6. 每条 Event 唯一且完整的 DeliveryIntent、`legal_hold` 和 CommandReceipt；
7. 非终态 Outbox 的状态形状和由 Event 重建的准确 CloudEvent；
8. 整个恢复包的 `recoverySha256`。

任何 payload、createdAt、序号、前哈希、事件哈希或 Tenant 变化都会失败关闭；
DeliveryIntent、回执、Outbox、Head 或恢复摘要不完整/被替换也会失败关闭。
隔离的 Recovery Writer 只能向空 Tenant 导入已经通过上述验证的恢复包，不能
SELECT、UPDATE 或 DELETE 业务证据。恢复遇到原 `PROCESSING` 状态会转为
`FAILED/RECOVERY_REQUEUE`，从而允许安全重试。

真实验收先使用第二个独立 PostgreSQL 实例做 API 恢复，再停止该实例并重新
`initdb`，核对源/目标 `system_identifier` 不同，执行恢复前角色 bootstrap 后才
运行 `pg_restore`。物理恢复后重新验证 Owner、PUBLIC ACL、运行角色权限、五表
FORCE RLS、完整链、身份 artifact、DeliveryIntent、回执和非终态 Outbox，并继续
追加下一事件，复核 sequence、previousEventHash、Head、租约、保留及 Tenant
Scope 清理。两种验证都不等于生产备份、跨区容灾或外部归档已经完成。

P1 只证明冻结的 `legal_hold` 标志能阻止清理。生产 Legal Hold 的设置、解除和
授权流程、正式销毁、外部归档、签名检查点和密钥轮换仍属于 O02/G2。

## 当前验证结果

本轮已经实际执行：

```text
Targeted Node（Core + Contract）：21 PASS，0 FAIL
真实临时 PostgreSQL 17：16 PASS，0 FAIL
全仓 build：PASS
全仓 Node：573 PASS，0 FAIL
全仓 ESLint：PASS
```

真实 PostgreSQL 测试包括 20 路并发、三 Tenant、FORCE RLS、真实角色权限、
原子 Event/DeliveryIntent/Outbox/Receipt、数据库正文拒绝、数据库时间租约、
Worker 崩溃与 ACK 丢失、独立保留清理、第二个独立 PostgreSQL 实例恢复、
源/目标 `system_identifier` 不同的 `pg_dump/pg_restore` fresh-cluster
恢复，以及恢复后的 Owner、PUBLIC ACL、运行角色、身份 artifact、Head、
DeliveryIntent、回执、非终态 Outbox、链继续追加、租约、保留、RLS 和 Scope
清理重验。它只证明本机临时 PostgreSQL 17 上的 P1 Synthetic 行为，不能升级为
生产结论。

全仓已跟踪的顶层 Node 测试本轮为 573 PASS、0 FAIL。候选证据仍按治理要求
等待 Root Source Freeze 后统一重新生成；源码测试绿色不等于证据已签发。

## 仍未验证

- 任何目标企业、OA、U9、BI、真实人员、真实 KPI 或真实业务数据；
- 生产数据库 HA、跨区域恢复、容量、SLO 或持续运维；
- 真实消息 Broker、外部 WORM/Object Lock 归档和消费者；
- P2 签名检查点、密钥轮换、生产 Legal Hold 流程和正式销毁；
- 企业保留法规、隐私要求或管理员职责审批；
- P3 企业 Connector 和真实上游 EvidenceRef。

因此当前只能表述为：

> C18 P1 Synthetic 实现和定向验证已完成；候选证据等待 Root Source Freeze
> 后重建，生产与企业集成仍为 `NOT_VERIFIED / P3_REQUIRED`。
