# C08 AIOS 状态核心

当前工程状态：`IMPLEMENTED / VERIFIED`

当前范围：`P1_SYNTHETIC_ONLY`

| 边界 | 当前状态 |
|---|---|
| 数据 | `SYNTHETIC_ONLY` |
| 企业 Connector | `C0_DISABLED` |
| OA、U9、BI、企业端点、企业凭据和企业网络 | `P3_REQUIRED` |
| 生产验证 | `NOT_VERIFIED` |
| C08 P1 合成验证 | `VERIFIED` |
| C08 冻结证据 | `c08-verification-evidence.v1.json` |

当前最小 Core、Memory/PostgreSQL Store、独立 Outbox Worker、迁移、合同与
测试已经完成 P1 Synthetic-only 冻结。该结论只属于 C08 工作包，不代表
P1 已完成、G1 已批准或生产可用。

## C08 拥有的状态

C08 只保存 AIOS 平台本地的六类运行状态：

| 对象 | C08 保存 | 不属于 C08 |
|---|---|---|
| `Case` | 一个 Synthetic 工作事项的目标引用、状态和版本 | ERP、OA、订单、合同或审批事实 |
| `Thread` | 一个 Case 内的工作上下文和用途引用 | C09 个人记忆、聊天正文或 C12 Checkpoint |
| `Run` | 一次执行尝试、冻结引用、状态、版本和还原哈希 | C12 Agent 路由图、模型策略或人工决定 |
| `Artifact` | INPUT/RESULT 的不可变版本、内容引用和 SHA-256 | 文件或结果正文、C15 DraftArtifact 决定 |
| `ToolCall` | Operation 版本、请求哈希、effect key、该次 C06 决策、状态和回执引用 | C16 Tool 发现、参数执行、凭据或 Adapter |
| `Outbox` | Domain Event 的待投递、租约和发布状态 | 企业 Connector、真实外部事实或 C18 审计 |

C08 的“状态真相”只指平台自己的运行总账。它不复制 ERP、BI、OA 或其他外部
系统的正式事实，也不把自由聊天内容当流程状态。

固定 ID 前缀：

- Case：`cas_`；
- Thread：`thd_`；
- Run：`run_`；
- Artifact：`art_`；
- ToolCall：`tcl_`；
- Domain Event：`evt_`。

所有 ID 均使用 UUIDv7。首次 ID 由 Core 的受信 ID 工厂生成；浏览器和模型
不能选择 Tenant、Actor 或物理存储位置。

## 五个受控入口

最小 Core 只返回：

```text
execute
recordToolCallResult
inspectRun
reconstructRun
snapshot
```

其中 `execute`、`inspectRun` 和 `reconstructRun` 是受信工作负载入口，
`snapshot` 是独立控制面入口；
`recordToolCallResult` 是只允许 C0 Mock Tool Worker 调用的独立内部入口，
不能由员工、浏览器、模型或普通工作负载调用。`aios-state-core.openapi.v1.json`
明确区分受信工作负载、Tool Worker 和控制面三类 mTLS 身份。

`lib/c08-outbox-worker.mjs` 是独立 Outbox Worker；它只调用 Store 的
`claimOutbox`、`completeOutbox` 和失败重排 Port，并把固定 Event ID 交给
幂等 Publisher。它不是 Core `execute` 命令，也不能由浏览器、模型或普通
业务请求调用。

### execute 请求信封

公共请求信封精确为：

```text
sessionToken
delegationId
idempotencyKey
correlationId
command
```

信封和每一种 `command` 都是封闭对象。Tenant、Principal、workload Actor、
授权结论、C06 surface、Adapter、SQL、URL、Connector Instance 和凭据都不在
请求体中；它们只能来自受信服务端上下文或后端依赖。

### recordToolCallResult 请求

Tool 回执不能经普通 `execute` 写入。独立 Worker 信封精确为：

```text
idempotencyKey
correlationId
command:
  kind
  runId
  expectedRunVersion
  toolCallId
  expectedToolCallVersion
  receiptId
```

`outcome`、`requestHash`、`effectKey`、`receiptRef` 和 `receiptHash` 均不能
由调用者自报。Core 在 C07 范围事务内读取已有 ToolCall，再通过只读
`toolReceiptVerifier` 回读 C0 Mock 的不可变回执，并逐项核对 Tenant、Run、
ToolCall、effect key、request hash、Operation 版本、结果和回执哈希。缺失或
不一致时不产生任何状态、Event、Outbox 或 CommandReceipt。

### inspectRun 请求

`inspectRun` 使用与 `reconstructRun` 相同的封闭请求字段，但允许读取
RUNNING Run。它返回 Case/Thread 的当前状态、版本、目标/用途引用，当前输入
版本、Run 版本和状态、冻结模型/Prompt/Skill/知识引用，以及每个 ToolCall 的
状态、版本、effect key、该次 C06 决策和可空回执。这样进程崩溃后可以判断
“尚未执行、已经产生回执或已经终态”。它是受 C06 READ 控制的运行恢复快照；
获准的上级或运营角色可以读取，但不能因此继续他人的状态变更。它不是 C18
不可变审计。

### reconstructRun 请求

```text
sessionToken
delegationId
runId
correlationId
```

还原只接受一个服务端 Tenant 范围内的终态 Run。还原成功不是新授权，也不等于
C18 不可覆盖业务审计。

### snapshot 请求

`snapshot` 是独立控制面读取，只接收一个 Synthetic `tenantId`。它先执行显式
控制面授权，再执行最终 C03 准入和 C07 范围读取；不复用普通员工请求信封，
不返回 Prompt、知识、Tool 参数、Artifact 正文或企业数据。

## 运行时顺序

普通 `execute`、`inspectRun` 和 `reconstructRun` 必须按以下顺序失败关闭：

```text
C05 resolveActionIdentity
→ C06 enforce
→ C06 decision 与第一次 C05 identity 精确绑定
→ C05 final resolveActionIdentity
→ C03 final admitNewRequest
→ 构造 C07_VERIFIED_TENANT_SCOPE
→ C07 范围内 Store 事务或读取
```

Core 先核对 C06 返回的 Human、Actor、安全 epoch、叶 Delegation、完整
Delegation chain 哈希、用途、Tenant、surface 和 resource；不一致时以
`AUTHORIZATION_BINDING_MISMATCH` 失败关闭，从而阻断 A-B-B-A 身份切换。
第二次 C05 解析还必须与授权前解析完全一致，否则以
`ACTION_IDENTITY_CHANGED` 失败关闭。最终 C03 准入位于 C05/C06 之后、Store
之前，是该次请求进入 C08 数据层的线性化点。任一步失败，后续依赖不得被
调用；Tenant 和 Actor 永远不能由命令覆盖。

`PREPARE_TOOL_CALL` 和 `FINISH_RUN` 还必须与 START_RUN 的稳定 Human、
workload Actor 及各自 security epoch 一致；另一名 Human 即使拥有 READ 权限，
也不能继续该 Run。Session ID、Delegation ID 和调用用途不作为永久所有权键，
因此同一 Human 在 Session/Delegation 更新后仍可恢复任务，但每次操作仍重新
经过完整 C05/C06/C03 链。`inspectRun` 和 `reconstructRun` 不做所有者硬编码，
是否允许上级查看完全由 C06 READ 策略决定。

`snapshot` 的控制面顺序为：

```text
C06 control authorization
→ C03 final admitNewRequest
→ C07_VERIFIED_TENANT_SCOPE
→ Store readTenantSnapshot
```

Tool 回执 Worker 的顺序为：

```text
专用受信 Worker 路由
→ controlAuthorize(AIOS_STATE_RECORD_TOOL_RESULT)
→ C03 final admitNewRequest
→ 构造 C07_VERIFIED_TENANT_SCOPE
→ Store 原子事务
→ C0 Mock receipt 精确回读和绑定校验
```

它不重新使用可能已经过期的人类 Session 或 Delegation。START_RUN 保存初始
Human、workload Actor 和 C06 决策；每个 PREPARE_TOOL_CALL 另存该次真实
TOOL_CALL 决策证据，并纳入还原哈希。P1 的 C0 Mock 回执只证明该次 Synthetic
Tool 副作用，不代表 C16 已交付。

## 六个 execute 命令

P1 Core 精确接受：

| 命令 | 精确字段 | 结果 |
|---|---|---|
| `CREATE_CASE` | `kind, goalRef` | 创建 OPEN Case |
| `OPEN_THREAD` | `kind, caseId, purposeRef` | 在 OPEN Case 下创建 OPEN Thread |
| `RECORD_ARTIFACT_VERSION` | `kind, artifactId, caseId, threadId, expectedArtifactVersion, artifactKind, contentRef, contentSha256` | 由 Core 生成首版 ID，或在同一 ID 上追加下一版本 |
| `START_RUN` | `kind, threadId, manifest` | 创建 RUNNING Run |
| `PREPARE_TOOL_CALL` | `kind, runId, expectedRunVersion, operationRef, operationVersion, requestHash, compensationRef` | 创建 PREPARED ToolCall 和稳定 effect key |
| `FINISH_RUN` | `kind, runId, expectedRunVersion, outcome, resultArtifact` | 冻结终态 Run 和 reconstruction hash |

`RECORD_TOOL_CALL_RESULT` 只存在于前述 Worker 入口，不属于 `execute` union。
没有通用命令、任意状态写入、Outbox 领取命令、Connector 命令或企业系统命令。

Artifact 的版本规则固定为：

```text
artifactId=null + expectedArtifactVersion=0
→ Core 生成 ID 并写 version=1

artifactId=<已有 ID> + expectedArtifactVersion=N
→ 只允许写 version=N+1
→ Case、Thread、kind 必须与首版相同
```

PostgreSQL 主键为 `(tenant_id, artifact_id, artifact_version)`，插入触发器和
Store 错误映射共同把跳号、重复版本、错误 lineage 和并发旧版本统一挡在
`STALE_VERSION`/明确版本错误边界。

## Synthetic Reference Catalog

URI 的 `synthetic://`、`fixture://` 等前缀只表示格式，不代表来源可信。
每次命令在进入 C05/C06 前，都必须在
`synthetic-reference-catalog.v1.json` 中按以下组合精确命中：

```text
Tenant + kind + ref + version + sha256 + asOf
```

Catalog 同时固定每个 Synthetic Tenant 对应的 C06 `READ`、`MANAGE` 和
`TOOL_CALL`
资源；C08 不用动态 Case/Run ID 冒充 C06 资源。模型、Prompt、Skill、知识和
Tool Operation 的条目明确标为 `PENDING_DEPENDENT_PACKAGE`，只表示 C08
冻结了本地替身，不表示 C10、C13、C14 或 C16 已经交付。

模型、Prompt、Skill、Goal、Purpose 和 Mock Tool 定义是冻结的共享产品夹具；
Artifact、Knowledge 和 Trace 则为三个 Synthetic Tenant 分别配置不同
ref/hash。Catalog 加载时把共享条目复制进每个 Tenant 的封闭视图，数据型引用
不能跨 Tenant 命中。

## START_RUN Manifest 与最终 Reconstruction

`run-manifest.v1.schema.json` 精确描述开始运行时已经知道的内容：

```text
inputArtifact
model
prompt
skill
knowledge[]
traceRef
```

字段含义：

- `inputArtifact`：已经由 C08 记录的 INPUT Artifact ID、版本和内容哈希；
- `model`、`prompt`、`skill`：`ref + version + sha256`；
- `knowledge[]`：`evidenceRef + version + asOf + sha256`，1—32 条且不得重复；
- `traceRef`：Synthetic Trace 引用。

开始运行时不能预知或自报：

- ToolCall 最终状态和回执；
- C06 对这次实际动作产生的决策证据；
- FINISH_RUN 绑定的 RESULT Artifact。

因此 `tool`、`policy` 和 `result` 不属于 START_RUN Manifest。它们分别由
服务端在以下时刻形成：

```text
PREPARE_TOOL_CALL + RECORD_TOOL_CALL_RESULT → tools[] + 每个 Tool 的 policy
START_RUN 的 C06 enforce                   → Run policy
RECORD_ARTIFACT_VERSION + FINISH_RUN       → result
```

终态 `reconstructRun` 必须返回完整的八类引用：

```text
input
model
prompt
skill
knowledge
tools
policy
result
```

并同时返回 Run/Case/Thread、C03 生命周期版本、C05 Actor/Delegation 证据、
Trace 和 `dependentPackageStatus=PENDING_DEPENDENT_PACKAGE`。正文、Token、
凭据和企业端点都不进入 Reconstruction。

RUNNING Run 不生成终态 reconstruction hash；它由 `inspectRun` 返回可恢复
快照并标为 `IN_PROGRESS`。终态 Run 经同一入口读取时还会重新校验
reconstruction hash，并标为 `TERMINAL_VERIFIED`。

## 最小状态机

Run：

```text
RUNNING → SUCCEEDED
        ├→ FAILED
        └→ CANCELLED
```

三个终态都不可恢复。`FINISH_RUN` 需要准确 `expectedRunVersion`、同
Case/Thread 的 RESULT Artifact，并要求已存在的每个 ToolCall 都是终态。
`SUCCEEDED` 至少需要一个 ToolCall 且全部 SUCCEEDED；`FAILED` 和
`CANCELLED` 可以没有 ToolCall，也可以包含已经终态的 ToolCall。失败/取消
仍绑定不可变 RESULT 摘要 Artifact，不能伪造一个 ToolCall 来填空。

ToolCall：

```text
PREPARED → SUCCEEDED
         └→ FAILED
```

Worker 入口必须同时匹配 Run 版本、ToolCall 版本、Run 关联及已存
`requestHash/effectKey/Operation`，并验证 C0 Mock 回执。ToolCall 终态不可
恢复，也没有 DISPATCHED、UNKNOWN 或其他超前状态。

同一 Run 同时最多只有一个 `PREPARED` ToolCall；它终态后才可准备下一个。
Core 检查与 PostgreSQL 部分唯一索引共同执行此约束，避免多个并行待处理调用
使较早 Outbox 回执因 Run 版本前进而无法提交。

Outbox 的产品逻辑状态：

```text
PENDING → LEASED → PUBLISHED
```

租约到期或投递失败会回到可重试的 PENDING，不形成新的业务命令。
`createC08OutboxWorker().runOnce()` 使用排他 claim、递增 lease version 和
准确 Worker 围栏；Publisher 成功后才 complete，Publisher 失败才 requeue，
complete 确认失败不会伪装成投递失败。旧 Worker 不能确认新租约。Outbox
仍是至少一次投递，下游必须用同一 Event/effect key 幂等，不能宣称分布式
“恰好一次”。

## 原子提交与幂等

每个 `execute` 请求的规范化哈希绑定：

```text
Tenant
resolved Human Subject
resolved workload Actor
Delegation chain
command
```

相同幂等键和相同哈希返回原结果并标记 `duplicate=true`；相同键配不同命令或
不同 Human 身份必须冲突。

Worker 回执命令的规范化哈希绑定 `Tenant + command`，不绑定具体 Worker
实例，因此另一受信 Worker 可在提交确认丢失后重放同一回执；新的
`correlationId` 不改变已经提交的业务结果。

用于故障恢复验收的 P1 C0 Mock 显式注入按 effect key 保存的本地持久化收据
Store：写临时文件、fsync，再以原子 hard link 首次落盘。Worker/Mock 进程
重启后会回读同一收据并返回 `duplicate=true`；相同 effect key 配不同内容
失败关闭。默认 Memory Store 只用于单元测试。这只证明 P1 Synthetic 故障
恢复，不是 C16 生产执行器或生产级共享存储。

一次命令的聚合状态、Domain Event、Outbox 和 Command Receipt 在同一事务中
提交。提交前崩溃全部回滚；提交已经落盘但调用方未收到确认时，重试返回原
CommandReceipt；提交后、投递前崩溃由独立 Outbox Worker 恢复，并复用原
Event 与 effect key。Memory 与 PostgreSQL Store 使用同一组
`claimOutbox/completeOutbox/failOutbox` Port、相同返回结构、显式时间和租约
围栏。单元测试覆盖 Publisher 已持久接收但确认丢失；PostgreSQL 测试覆盖
Worker/Mock 重启、租约重领、同一 effect key/receipt 去重和旧租约拒绝。

## 与相邻工作包的边界

- **C03**：Tenant 生命周期和最终新请求准入真相。
- **C05**：Human、workload Actor 和 Delegation 身份真相。
- **C06**：当前操作授权与 Policy Evidence 真相。
- **C07**：Tenant 数据范围、RLS、对象和恢复隔离；C08 Store 只接受已验证范围。
- **C09**：Profile、个人记忆与用户 Checkpoint；C08 Thread 不保存它们。
- **C12**：Agent 状态图、路由和编排 Checkpoint；C08 只保存运行总账。
- **C15**：HumanDecision、批准哈希、正式执行与补偿规则。
- **C16**：Tool Catalog、每次重鉴权、参数、凭据与 Adapter 执行。
- **C18**：不可覆盖 AuditEvent、来源链和保留；C08 Event/Outbox 不是完整审计。
- **C19**：Usage、配额、费率和成本账本。

## 当前测试与证据含义

`replay-matrix.v1.json` 将当前实际存在的 Core、PostgreSQL 合同和 PostgreSQL
运行测试逐项映射到精确测试标题。映射状态统一为：

```text
VERIFIED_P1_SYNTHETIC
```

OpenAPI、START_RUN Schema 和矩阵自身由合同测试核对；完整回归、真实
PostgreSQL、最小角色测试、两次独立只读复审和制品哈希记录共同形成 C08 的
P1 合成冻结证据。

当前可运行：

```sh
sh scripts/run-c08-tests.sh
npm run lint
```

这些测试与冻结证据只证明 C08 的 P1 Synthetic-only 范围。P3 企业资料、
OA/U9/BI、真实 Connector、容量、高可用、备份恢复、生产 mTLS 和生产发布仍
全部未验证；C08 通过也不替代 Product Owner 对整个 G1 阶段包的审批。
