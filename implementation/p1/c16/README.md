# C16 Tool Gateway 与逐次重新鉴权

当前工程状态：`IMPLEMENTED / SOURCE_ONLY`

当前范围：`P1_SYNTHETIC_ONLY`

| 边界 | 当前状态 |
|---|---|
| Tenant | 固定 3 个 Synthetic Tenant |
| Tool Catalog | 3 个定义逐字段冻结的只读合成操作 |
| C0 Adapter | 无网络、无企业端点、无企业凭据、无真实副作用 |
| C05 / C06 | 每个 discover、confirm、execute 都重新解析并鉴权 |
| PostgreSQL | 真实 PostgreSQL 17、FORCE RLS、最小角色、跨实例恢复 |
| C18 | metadata-only Audit Intent + 可恢复 Outbox 窄接口 |
| OA、U9、BI、任意 URL、SQL、Shell、生产 Connector | `P3_REQUIRED` |
| 生产部署与真实企业集成 | `NOT_VERIFIED` |

C16 的职责是把“模型想调用工具”变成一个受治理的服务端过程：

```text
discover
→ confirm 固化参数与权限上下文
→ execute 再次鉴权
→ 临时最小 capability
→ C0 合成 Adapter
→ 幂等结果与 metadata-only 审计
```

MCP 列表、提示词、客户端 allow-list 或阶段 token 只用于帮助调用者发现工具，
不构成运行时授权。

## 冻结验收

1. 唯一公开接口是 `discover`、`confirm`、`execute`。
2. Catalog 只包含：

   ```text
   synthetic.approval.status.get
   synthetic.erp.order.get
   synthetic.bi.metric.get
   ```

3. Catalog 版本、Adapter、audience、授权资源和参数 Schema 均逐字段冻结；
   C0 数据也固定为三个 Tenant × 三个操作的九条记录。结构合法但被本地替换
   的 Catalog 或 Fixture 同样失败关闭。请求不能传 URL、SQL、命令、管理员
   开关或任意工具名。
4. 每一个公开动作都固定执行：

   ```text
   C05 首次解析
   → C06 TOOL_CALL
   → C05 最终解析且绑定不变
   → C03 最终 ACTIVE 准入
   ```

5. `confirm` 由服务端规范化参数，生成两分钟有效的不可变确认；确认绑定
   Tenant lifecycle、Catalog、Adapter、参数、Human/Workload Actor lifecycle
   与 Security Epoch、delegation chain，以及排除阶段性 decision ID 后的稳定
   C06 授权权威哈希。
6. `execute` 不信任此前的发现或确认结果，会再次运行完整 C05/C06/C05/C03
   链路。Tenant lifecycle、身份 lifecycle/epoch、委托、C06 policy version、
   参数、Catalog、Adapter、有效期或确认哈希变化均失败关闭。
7. 同一确认只能产生一个 ToolCall。同一幂等键重试返回同一结果；不同幂等键
   复用确认会被拒绝。
8. C0 Adapter 使用稳定 `effectKey` 去重。即使持久化成功 ACK 丢失，重试也
   不会再次执行 Adapter。
9. capability 只在执行前即时签发，最长 30 秒，绑定 Tenant、operation、
   call 和 audience；只作为 Adapter 的私有第二参数传入，并在 `finally`
   中撤销。响应、错误、Receipt、Audit 和恢复快照均不含 capability。
10. Adapter 没有网络调用 seam，也不接受端点、URL、SQL 或命令。Gateway
    在落库前按操作验证精确结果字段、参数关联、Receipt 全字段、自哈希，
    并要求 `networkRequestCount` 和 `externalEffectCount` 都等于 0；夹带
    capability 或额外字段的结果失败关闭。
11. 确认和执行终态分别在业务事务中创建 metadata-only Audit Intent 与
    Outbox。Publisher ACK 必须返回相同 `intentId`；ACK 丢失按同一 Intent
    重试。
12. PostgreSQL 验证三 Tenant 隔离、并发确认、幂等执行、连接上下文清理、
    FORCE RLS、不可变记录、租约回收和 stale lease fencing。连接还必须只
    拥有指定角色闭包，并与所有 `aios_*` schema 上声明的 schema/table/
    column/sequence/function 有效权限矩阵完全一致；传递角色、预定义读角色、
    高权限属性和任何相邻直授都会失败关闭。
13. 恢复测试使用 `pg_dump` 和 `pg_restore`，目标由第二次 `initdb` 创建；
    源和目标 `system_identifier` 必须不同，恢复后继续消费待发布 Audit
    Outbox。

## 深模块接口

```text
discover(serverContext, request)
confirm(serverContext, request)
execute(serverContext, request)
```

调用者不负责拼接权限证据、签发 capability、管理幂等状态或发布审计。
Memory Store 和 PostgreSQL Store 实现同一个 Store seam；C06、C0 Adapter、
credential broker 和 C18 Publisher 是窄接口。

## 为什么 execute 同步调用 C0 Adapter

当前 C16 在 `execute` 当次请求内完成最新 C05/C06 鉴权，再同步调用无网络的
C0 Adapter。这样不需要把 Session、Delegation 或任何凭据写进队列。若将来
改成异步生产 Connector，Worker 必须重新取得可验证身份与授权上下文，不能
复用或持久化本次临时 capability。

## PostgreSQL

固定迁移：

```text
0029_tool_gateway.sql
0030_tool_gateway_runtime_roles.sql
```

四张表全部带 Tenant key，并启用 `ENABLE ROW LEVEL SECURITY` 与
`FORCE ROW LEVEL SECURITY`：

```text
tool_confirmation
tool_call
audit_intent
audit_outbox
```

角色分工：

| 角色 | 允许 | 禁止 |
|---|---|---|
| `aios_c16_runtime` | 按签名 Tenant Scope 创建/读取确认与调用，原子写初始 Audit | Worker 终态、删除历史 |
| `aios_c16_worker` | 完成 ToolCall，写终态 Audit | 读取确认、发布 Audit |
| `aios_c16_audit_worker` | 读取 metadata-only Intent，租约化更新 Audit Outbox | 读取 Tool 参数和结果 |
| `aios_c16_recovery_reader` | 按 Tenant 只读四表恢复 | 任何写入 |
| `aios_c16_owner` | 迁移和受控维护 | 不能作为应用连接池 |

Store 要求五个不同连接池，并拒绝 Superuser、BYPASSRLS、CREATEDB、
CREATEROLE、REPLICATION、Owner、混合或传递角色连接。每次连接会核对所有
`aios_*` schema 的有效权限闭包；因此上游 C03/C05/C06/C07/C18 迁移也必须
完成 PUBLIC 权限收口，否则 C16 会拒绝启动。每次事务使用 C07 签名 scope 与
fence，提交或回滚后检查连接未残留 Tenant 上下文。

`c16_restore_role_bootstrap.v1.sql` 只用于在空白目标集群预建 dump 所引用的
NOLOGIN 角色。恢复不忽略 owner；恢复后重新验证表 owner、FORCE RLS、角色
边界和待处理 Outbox。

## C18 seam

C16 不修改 C18。写入 `c16-c18-outbox-intent.v1`，固定只含：

```text
Tenant / event type / subject ID / operation ID
identity / authorization / catalog / parameter / result receipt SHA-256
correlationId / occurredAt / intentSha256
```

它不含参数正文、结果正文、Prompt、模型输入输出、Session 或 capability。
当前只验证可恢复 Publisher seam；正式进入 C18 Evidence Registry 需要后续
联合验收。

## P1 限制

C0 Adapter 的速率计数和 effect 去重是单进程内存状态，只用于当前合成验收。
横向扩容、跨进程全局限流和分布式 effect ledger 属于 P3 生产 Connector
接入前的必做项，当前结果不构成对应生产证明。

## 文件

| 文件 | 用途 |
|---|---|
| `operation-catalog.v1.json` | 三个封闭操作及参数 Schema |
| `tool-gateway.openapi.v1.json` | discover/confirm/execute 请求与响应契约 |
| `tool-gateway.mcp-projection.v1.json` | 非授权性的 MCP 发现投影 |
| `synthetic-tool-fixtures.v1.json` | 三 Tenant、三操作 C0 数据 |
| `verification-matrix.v1.json` | 冻结断言到测试证据映射 |
| `lib/tool-gateway.mjs` | 深模块与 Memory Store |
| `lib/c16-c06-authorizer.mjs` | 真实 C06 Facade Adapter |
| `lib/c16-ephemeral-credential-broker.mjs` | 短期私有 capability |
| `lib/c16-synthetic-tool-adapter.mjs` | 无网络 C0 Adapter |
| `lib/c16-outbox-worker.mjs` | metadata-only Audit Worker |
| `lib/postgres-tool-gateway-store.mjs` | PostgreSQL Store |
| `tests/integration/c16-postgres-restore.test.mjs` | 跨实例恢复后继续 Audit Outbox |

## 验证

```text
sh scripts/run-c16-tests.sh
npm run lint
```

脚本创建两个一次性 PostgreSQL 17 集群，禁用 TCP，只通过本地 Unix Socket
运行。通过只表示 P1 合成机制、源码和临时数据库证据成立，不表示生产部署、
企业系统接入、真实凭据或真实业务效果已经完成。
