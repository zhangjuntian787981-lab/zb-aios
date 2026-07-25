# C03 Tenant Registry 与生命周期

当前工程状态：`IMPLEMENTED / VERIFIED`

本实现只建设 P1 的通用产品核心，只接受 F02 冻结目录中的 Synthetic
Fixture。它没有接收任何目标企业内部资料，没有企业身份、凭据、地址或网络，
也没有连接 OA、U9、BI；所有 Connector 继续保持 `C0`。

## 外部接口

`createTenantRegistry(...)` 只返回三个入口：

- `execute(context, command)`：唯一生命周期写入口；
- `snapshot(context, tenantId)`：只读治理投影；
- `admitNewRequest(serverContext)`：所有新业务请求必须经过的生命周期门。

P1 支持以下命令：

- `CREATE_SYNTHETIC_TENANT`
- `RECORD_PROJECTION_RESULT`
- `RECONCILE_TENANT`
- `SUSPEND_TENANT`
- `RESUME_TENANT`
- `REQUEST_TENANT_DELETION`

权限分为三条独立能力，不能互相替代：

- `TENANT_LIFECYCLE_MANAGE`：创建、暂停、恢复和请求删除；
- `TENANT_PROJECTION_REPORT`：合成投影 Worker 回报结果；
- `TENANT_RECONCILE`：Reconciler 推导 `ACTIVE` 或 `DELETED`。

投影结果同时绑定 `operationId`、generation、projection 和连续 attempt。
旧 operation、旧 generation、跳号、重放冲突或成功后的倒退全部失败关闭，
因此生命周期管理员不能自行伪造五个成功结果来激活 Tenant。

P1 不提供通用 `CREATE_TENANT`，也不读取或保存 Enterprise Tenant
创建载荷。`CREATE_ENTERPRISE_TENANT` 固定返回 `P3_REQUIRED`。P3 必须使用
独立命令、全新的 `etn_` Tenant ID、`ens_` 资源 Namespace 和已授权的
Onboarding Package，禁止升级或复用 Synthetic Tenant。

`configRefs` 不仅检查 scheme、长度和数量，还必须逐项属于该 Fixture 在
F02 冻结目录中的允许集合；把企业地址、未知 Fixture 引用或伪装成
`secret-ref://` 的正文传入都会被拒绝。

## 状态与准入

```text
ABSENT → PROVISIONING → ACTIVE → SUSPENDED
             │            │          │
             └────────────┴──────────┴→ DELETING → DELETED
SUSPENDED → PROVISIONING → ACTIVE
```

- 创建和恢复后都先进入 `PROVISIONING`；
- 只有当前 generation 的五个必需投影全部成功，Reconciler 才能推导
  `ACTIVE`；
- 任何投影失败都不能进入 `ACTIVE`；
- 暂停事务提交后，`admitNewRequest` 立即拒绝新请求；
- 删除先进入 `DELETING`，所有层完成后才进入 `DELETED`；
- `DELETED` 保留最小墓碑，不释放 Tenant ID、Fixture Origin 或资源
  Namespace。

`ACTIVE` 只表示 C03 的当前投影计划已经完成，不表示 C04—C19 已经完成，
也不替代后续身份认证、授权和数据隔离。

## 存储边界

领域模块通过 Tenant Store 端口工作：

- `createMemoryTenantStore`：确定性单元测试和故障场景；
- `createPostgresTenantStore`：生产候选适配器；
- `postgresql/0001_tenant_registry.sql`：表、检查约束、不可变触发器、
  append-only 事件、Outbox 和永久墓碑。

PostgreSQL 命令使用 `SERIALIZABLE` 事务，将 Tenant、Projection、生命周期
事件、Outbox 和幂等回执原子提交。Outbox 使用
`FOR UPDATE SKIP LOCKED` 领取，lease 由数据库按 1—300 秒生成并递增
`lease_version`；完成或失败回执必须同时匹配 Worker、未过期租约和准确
version。远程投影调用不应在数据库事务中执行。

Outbox 提供至少一次投递语义：租约和 `lease_version` 只保证同一时刻的
排他领取并阻止旧 Worker 回执，不能保证外部副作用“恰好一次”。所有下游
消费者必须以 CloudEvent ID、operation ID 和 generation 实现幂等。

运行时信任边界是：Tenant Registry 是唯一获准执行这些表 DML 的产品组件。
数据库 Owner、迁移账号、DBA 和可执行任意原始 SQL 的账号属于可信管理边界；
C03 不声称能阻止这些账号绕过 Reconciler。直接 SQL 负例只证明下列已登记的
数据库不变量。生产最小权限角色、Grant 和凭据轮换仍需后续授权与运维工作包
单独实现和验证。

## 已运行验证

```bash
node --test tests/tenant-registry.test.mjs \
  tests/tenant-postgres-contract.test.mjs
npm run test:c03:postgres
```

内存、契约和真实 PostgreSQL 验证覆盖：

- 32 路并发重复创建只得到一个 Synthetic Tenant；
- 同一 idempotency key 的重放和冲突；
- creation key 双保险；
- 未冻结 Fixture 和 P1 Enterprise 创建拒绝；
- 投影失败不误激活；
- 完整投影后才允许新请求；
- 暂停、过期版本和恢复重新对账；
- 分层删除失败、重试、完成和墓碑；
- kind 修改、旧 generation 和未授权读取拒绝；
- 创建意图冲突、任意企业地址引用和原始 secret scheme 拒绝；
- 投影 operation、连续 attempt、独立 Worker/Reconciler 能力和乱序拒绝；
- PostgreSQL 迁移关键约束和事务适配器合同。
- PostgreSQL 17.10 空数据库执行准确迁移；
- 32 路相同命令和 32 路不同重试键均只创建一个 Tenant；
- Serializable 争用安全重试，过期版本失败关闭；
- Commit 前终止 PostgreSQL Backend 后五类记录全部回滚，同命令可恢复；
- 直接 SQL 修改身份、提前激活、删除墓碑和复用 Origin/Namespace 均被拒绝；
- Outbox 排他领取、租约过期重领、旧租约围栏和最终发布。

真实数据库验证使用一次性本地集群，只开放临时 Unix Socket，不监听 TCP。
成功结束时停止集群并清除临时目录；停止失败时测试返回失败并保留目录和日志
用于排查。测试数据全部来自 F02 Synthetic Fixture，未接收企业资料，OA、
U9、BI 和其他企业 Connector 仍保持 `C0`。

当前 `VERIFIED` 只证明 C03 在本机 PostgreSQL 17.10 上的冻结验收条件。
PostgreSQL 17 是候选支持主版本，但每个补丁版本和部署环境都必须在上线前
重跑同一套验证；本结论不代表整个 17 系列已经验证，也不代表 C04—C19、
生产高可用、数据库角色分权或 P3 Enterprise Onboarding 已完成。
首次 `IMPLEMENTED / NOT_VERIFIED` 快照仍保留在
`c03-implementation-evidence.v1.json`；当前验证证据使用独立的 v2 文件，
不改写历史快照。
