# C09 个人 Profile、会话与记忆

## P1 边界

C09 只接受三个冻结 Synthetic Tenant、合成 Human Principal 和合成个人偏好/
工作状态。它不连接企业系统，不接收企业资料，也不声称已经完成生产部署。

个人数据的稳定所有者键是：

```text
Tenant ID + C05 stable Human Principal ID
```

Session、Identity Account、Identity Link 或 Delegation 更新不会改变所有者。
C06 在每次命令和召回时重新授权并绑定 Human、workload Actor 和 Delegation；
授权后再次解析 C05 身份。每条 Recall item 获得 C06 ALLOW 后也会再次解析
C05，并完整比较 Human、workload Actor、Delegation chain 及其生命周期和安全
纪元；发生变化的 item 会被丢弃且不会读取正文。C07 验证 Tenant 事务范围，C09
的数据库签名同时绑定
最终稳定 Human Principal ID、生命周期版本和安全纪元；Store 不接受同 Tenant
内替换 Principal。经理、管理员和其他 Human 默认不能读取个人会话、Checkpoint
或记忆。

## 验收标准

1. 模型入口只能创建 `CANDIDATE`，不能提交 `CONFIRMED` 或改写现有记忆。
2. 确认与纠正必须携带由独立真人流程签发的短期、一次性
   **Human consent artifact**。制品绑定 Tenant、稳定 Human Principal、
   Memory、期望版本、批准内容哈希、有效期和用途；C09 服务只能验证并消费，
   不能签发，普通 Agent/workload 也不能自行生成。
   消费结果按固定九字段白名单重构：
   `tenantId`、`humanPrincipalId`、`memoryId`、`expectedVersion`、
   `contentSha256`、`expiresAt`、`purpose`、`tokenSha256`、`consumedAt`；
   服务、PostgreSQL Store 和数据库约束都拒绝额外 token、content、secret
   字段及非规范类型，明文 token 永不进入 Event。
   已提交命令的相同请求优先从持久 `command_receipt` 返回，不再次消费 consent。
   未提交的 Human consent 在服务重启后会 fail closed，必须由 Human 重新批准；
   P1 不因此声明已经实现生产 Human consent 系统。
3. 召回在返回内容前依次执行 Tenant、Principal、`CONFIRMED` 状态、有效期、
   C06 item 授权和 C05 最终身份复核；身份发生变化的 item 不读取正文；
   Profile 暂停时返回空集。
4. `ENTERPRISE_FACT`、`PRICE`、`ORDER`、`CONTRACT`、`CERTIFICATION` 和
   `KPI` 类别在服务与数据库两层均被拒绝。
5. 纠正必须删除旧值并由本人明确确认新值；旧值不能再召回。
6. 暂停会阻断召回和 Checkpoint 读取，并使按时点导出的恢复快照不含该
   Profile 的可用明文。自然过期在召回、Checkpoint 和恢复导出中按可信
   `asOf` 立即过滤；后台 worker 再通过幂等 `MATERIALIZE_EXPIRY` 命令，
   在同一事务中清除明文、Checkpoint 引用并追加过期事件。
   独立 `aios_c09_retention_runtime` 只可执行一个窄函数，没有任何表级读取或
   写入权限。它在 C06 前后两次解析并锁定同一个 ACTIVE Service Principal，
   再使用资源与版本绑定的 C06 决策和签名 C07 Tenant scope；因此 Human 已
   SUSPENDED 或 DEACTIVATED 后仍可按数据库时钟清理到期
   `CANDIDATE`/`CONFIRMED`，但不能提前清理、返回明文或执行其他操作。
   Memory Store 的 retention seam 对 Actor、生命周期、安全纪元、固定十字段
   授权证据和完整命令 envelope 做闭集及绑定校验；Actor 身份三元组同时纳入
   canonical request/idempotency hash。
7. 跨用户、跨 Tenant、重放冲突和并发旧版本均失败；相同幂等键与相同请求
   返回同一结果且不重复产生事件。
8. 服务重启和 PostgreSQL 恢复后，上述所有隔离、删除和过期规则仍成立。
   恢复库必须来自第二个 fresh `initdb` 集群，先运行只创建 11 个 NOLOGIN
   依赖角色的版本化 bootstrap，并证明 system identifier 与源集群不同。
   创建任何 test-only LOGIN 前，恢复测试重新核验 C09 Schema、六表和八函数
   Owner、PUBLIC ACL、五表 FORCE RLS、11 个角色属性与无交叉成员，以及四个
   应用角色的精确 Schema/Table/Column/Sequence/Function 权限矩阵。随后再验证
   服务级 committed receipt 重放、同 Tenant 跨 Human 隔离、18 GUC 清理、暂停
   召回、自然过期和 retention worker 继续执行，且 receipt 检查继续先于
   consent 消费。
9. PostgreSQL 使用 `FORCE ROW LEVEL SECURITY`。每个 Pool 会递归核验
   current/session user 的全部有效角色成员资格：除登录角色自身外，唯一
   有效成员必须是该 Pool 的 required role，同时拒绝 Owner、相邻
   `aios_*`、`pg_*` 内建高权角色、
   `SUPERUSER/BYPASSRLS/CREATEDB/CREATEROLE/REPLICATION` 以及额外受保护
   对象或函数权限；所需角色的成员关系也不能带 `ADMIN OPTION`。运行角色不能
   把应用角色授予他人、变更追加式事件或绕过专用存储接口。
   Runtime 连接归还前检查全部 18 个事务身份 GUC；任一残留都会销毁连接。
10. 工作矩阵在最终冻结证据生成前只能标记为 `CANDIDATE_P1_SYNTHETIC`；
    企业接入与生产结论保持 `NOT_VERIFIED`。

## 最小实现

- `lib/c09-personal-memory.mjs`：领域规则、C05/C06/C07 门、Human consent
  验证/消费接口、仅供 P1 测试注入的 Synthetic 签发器和内存事务存储；
- `lib/c09-personal-memory-postgres-store.mjs`：PostgreSQL 原子事务存储；
- `postgresql/0015_personal_memory.sql`：Schema、约束、RLS、追加式事件与仅处理
  到期记录的窄 retention 函数；
- `postgresql/0016_personal_memory_runtime_roles.sql`：Owner/Runtime 及独立 Service
  retention 角色的最小权限；
- `postgresql/c09_restore_role_bootstrap.v1.sql`：fresh cluster 恢复前所需的
  11 个 NOLOGIN 依赖角色；不创建应用或测试 LOGIN；
- `personal-memory.openapi.v1.json`：候选、确认、纠正、暂停、删除、Checkpoint
  和召回契约；
- `synthetic-personal-memory-catalog.v1.json`：唯一允许的 P1 合成内容；
- `memory-matrix.v1.json`：正向、越权、重放、并发、删除与恢复验收矩阵。
- `scripts/run-c09-personal-memory-postgres-tests.sh`：分别创建源和恢复两个
  fresh `initdb` 集群，执行真实 `pg_dump/pg_restore`，并只在恢复集群运行时
  设置 `C09_TEST_RESTORED=1`。

## 明确不做

- 不把聊天原文当作生效记忆；
- 不保存 ERP、BI、OA、价格、订单、合同、认证或 KPI 事实；
- 不允许模型、Prompt、客户端过滤器或管理员直接写入生效记忆；
- 不把 P1 Synthetic Human consent 签发器当作生产身份或同意服务；
- 不声明 LangGraph、Mem0、Graphiti 或真实企业集成已经完成；
- 不把 P1 Synthetic 决定复用于 P3。
