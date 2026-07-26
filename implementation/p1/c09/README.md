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
授权后再次解析 C05 身份。C07 验证 Tenant 事务范围，C09 的数据库签名同时绑定
Human 的生命周期版本和安全纪元。经理、管理员和其他 Human 默认不能读取个人
会话、Checkpoint 或记忆。

## 验收标准

1. 模型入口只能创建 `CANDIDATE`，不能提交 `CONFIRMED` 或改写现有记忆。
2. 只有同一 Tenant、同一稳定 Human Principal 且 `explicitConfirmation=true`
   的请求可以把候选变为 `CONFIRMED`。
3. 召回在返回内容前依次执行 Tenant、Principal、`CONFIRMED` 状态、有效期和
   C06 授权过滤；Profile 暂停时返回空集。
4. `ENTERPRISE_FACT`、`PRICE`、`ORDER`、`CONTRACT`、`CERTIFICATION` 和
   `KPI` 类别在服务与数据库两层均被拒绝。
5. 纠正必须删除旧值并由本人明确确认新值；旧值不能再召回。
6. 暂停、自然过期和显式删除立即从召回、Checkpoint 引用和恢复快照中失效。
   删除后任何持久化表或恢复快照都不得保留明文值。
7. 跨用户、跨 Tenant、重放冲突和并发旧版本均失败；相同幂等键与相同请求
   返回同一结果且不重复产生事件。
8. 服务重启和 PostgreSQL 恢复后，上述所有隔离、删除和过期规则仍成立。
9. PostgreSQL 使用 `FORCE ROW LEVEL SECURITY`；运行角色无
   `SUPERUSER/BYPASSRLS`，不能变更追加式事件或绕过专用存储接口。
10. P1 验证证据只能标记为 `VERIFIED_P1_SYNTHETIC`，企业接入与生产结论保持
    `NOT_VERIFIED`。

## 最小实现

- `lib/c09-personal-memory.mjs`：领域规则、C05/C06/C07 门、内存事务存储；
- `lib/c09-personal-memory-postgres-store.mjs`：PostgreSQL 原子事务存储；
- `postgresql/0015_personal_memory.sql`：Schema、约束、RLS 与追加式事件；
- `postgresql/0016_personal_memory_runtime_roles.sql`：Owner/Runtime 最小权限；
- `personal-memory.openapi.v1.json`：候选、确认、纠正、暂停、删除、Checkpoint
  和召回契约；
- `synthetic-personal-memory-catalog.v1.json`：唯一允许的 P1 合成内容；
- `memory-matrix.v1.json`：正向、越权、重放、并发、删除与恢复验收矩阵。

## 明确不做

- 不把聊天原文当作生效记忆；
- 不保存 ERP、BI、OA、价格、订单、合同、认证或 KPI 事实；
- 不允许模型、Prompt、客户端过滤器或管理员直接写入生效记忆；
- 不声明 LangGraph、Mem0、Graphiti 或真实企业集成已经完成；
- 不把 P1 Synthetic 决定复用于 P3。
