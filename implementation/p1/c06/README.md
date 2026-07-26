# C06 统一授权策略与 PEP SDK

## 当前结论

本目录实现的是 **P1 合成数据环境中的 C06 工程基础**：固定授权模型、六类受保护操作、OpenFGA PDP 适配器、Authorization Facade、PEP SDK、策略发布/激活/回滚、决策记录与回放，以及 60 条合成验收 Fixture。

它不代表生产可用，也不代表已经接入任何真实企业：

| 边界 | 当前状态 |
|---|---|
| 阶段 | `P1_SYNTHETIC_ONLY` |
| 数据 | `SYNTHETIC_ONLY` |
| 企业连接器 | `C0_DISABLED` |
| 生产验证 | `NOT_VERIFIED` |
| 真实企业身份、权限与数据 | `P3_REQUIRED` |
| C01/C02/C11/C16/O01 实际接入 | `PENDING_DEPENDENT_PACKAGE` |

项目级状态、Gate 结论和批准结果仍以治理清单、冻结证据与审批记录为准；不能只根据本目录存在代码或测试就宣称 C06 已通过阶段验收。

## C06 负责什么

C06 只负责回答一个问题：

> 对当前受保护操作，经过服务端验证的人、工作负载 Actor 和用途，是否同时满足同一已激活策略版本？

一次决策固定检查三项关系：

1. Human 是否有目标资源关系；
2. workload Actor 是否有目标资源关系；
3. purpose scope 是否与当前 surface 匹配且有目标资源关系。

三项必须全部通过才返回 `ALLOW`。用途不匹配、任一关系缺失、租户/身份/资源状态变化、PDP 不可用或 PDP 返回的 Store/Model/一致性不匹配，都失败关闭为 `DENY` 或稳定错误。

## 六类受保护操作

`protected-operations.v1.json` 固定以下 surface：

| Surface | 资源类型 | 未来代表性调用方 |
|---|---|---|
| `READ` | `protected_resource` | C01 |
| `RETRIEVE` | `protected_resource` | C11 |
| `DOWNLOAD` | `protected_resource` | C01 |
| `MANAGE` | `protected_resource` | C02 |
| `TOOL_CALL` | `tool_operation` | C16 |
| `SANDBOX_RUN` | `sandbox_profile` | O01 |

`pep-coverage.v1.json` 将六类 surface 指向真实的 Synthetic 代表性 Adapter 与测试；这些 Adapter 都实际经过 PEP。未来调用方仍标记为 `PENDING_DEPENDENT_PACKAGE`，因此没有冒充 C01/C02/C11/C16/O01 已完成真实集成。

## 信任边界

Authorization Facade 接收两个彼此隔离的输入通道：

```text
受信内部网关
  └─ serverContext
     ├─ Synthetic Tenant
     ├─ protected surface
     ├─ verified route
     └─ verified workload Actor

调用请求体
  ├─ sessionToken
  ├─ delegationId
  ├─ resourceId
  └─ correlationId
```

调用方请求体不能提交或覆盖 Principal、Actor、Tenant、Store、Model、relation、Allow 结果或 contextual tuples。`serverContext` 也不能来自浏览器 JSON；它只能由完成内部工作负载认证的网关构造。详细封闭请求结构见 `authorization.openapi.v1.json`。

C05 与 C06 的职责分开：

- C05 解析稳定 Human、workload Actor 和 delegation 来源，不作业务授权；
- C06 使用 C05 的已验证结果进行业务授权，不接受调用方自报身份。

## 策略发布与回滚

控制面只开放四类命令：

1. `STAGE_SYNTHETIC_POLICY_RELEASE`
2. `RECORD_POLICY_PROJECTION`
3. `ACTIVATE_POLICY_RELEASE`
4. `ROLLBACK_POLICY_RELEASE`

命令使用封闭字段、能力检查和幂等键。策略先形成不可变 Policy Release，再由受信投影 Worker 记录 OpenFGA Store、`authorization_model_id`、Tuple Bundle 和 Fixture 报告。失败的投影保留为不可覆盖墓碑；同一冻结模板可用新的 Release ID 重试，不删除失败证据。激活或回滚前会重放冻结证据；激活版本变化时，正在执行的旧决策不能提交陈旧的 `ALLOW`。

`bundleSha256` 固定抽象策略模板，`modelSha256` 固定规范化 OpenFGA 模型，`tupleBundleSha256` 固定该 Tenant 经受信 Principal 映射后、从 Release 专属 Store 分页读回的完整 Tuple 集；三者语义不同，不能互相代替。投影成为 `READY` 前和每次激活/回滚前，Concrete Verifier 都会读回实际 Model/全部 Tuple，做精确哈希核对，并在固定 Store/Model 上重跑 6 × 5 = 30 条正反检查。

运行时只获得 Read/Check 端口，不暴露创建 Store、发布 Model 或写 Tuple 的方法。每个实时决策和历史 `replay` 都先重新核对完整投影；高权限外部写入造成任何额外、缺失或变更时都会失败关闭。历史决策记录固定 Store、Model、Tuple Bundle、输入哈希、三项结果和证据引用；Decision、Event 和 Outbox 作为一个精确幂等证据组提交并回读。`replay` 返回 `authorizationStatus: NOT_AUTHORIZATION`，不能给新动作授权。

## 主要文件

| 文件 | 用途 |
|---|---|
| `authorization.openapi.v1.json` | C06 内部命令、决策、回放和快照契约 |
| `protected-operations.v1.json` | 六类 surface 与关系名 |
| `pep-coverage.v1.json` | 代表性 PEP 接入点及依赖包状态 |
| `synthetic-authorization-fixtures.v1.json` | 6 × 10 = 60 条合成决策矩阵 |
| `synthetic-policy-catalog.v1.json` | 冻结模型、操作、Fixture 哈希与迁移模板 |
| `openfga/authorization-model.v1.json` | OpenFGA 1.1 关系模型 |
| `openfga/openfga-distribution.lock.json` | P1 本地 OpenFGA 发行包锁定信息 |
| `openfga-official-notes.md` | 官方资料核验与版本选择依据 |
| `../../../lib/authorization-facade.mjs` | Facade、内存证据库和 PEP SDK |
| `../../../lib/synthetic-pep-adapters.mjs` | 六类服务端固定的 Synthetic 代表性 PEP Adapter |
| `../../../lib/openfga-pdp.mjs` | 固定 Store/Model/一致性的 OpenFGA 适配器 |
| `../../../lib/openfga-policy-verifier.mjs` | 实际 Model/Tuple 读回、真实投影报告与 30 条重放 |
| `postgresql/0009_authorization.sql` | Policy Release、激活、决策、回执、Event 和 Outbox |
| `postgresql/0010_authorization_runtime_roles.sql` | 控制、决策、Outbox 三类最小权限角色 |
| `../../../lib/postgres-authorization-store.mjs` | Facade 的真实 PostgreSQL Store |

## 合成验收矩阵

每个 surface 执行同一组十种场景：

- 三项关系全部有效；
- Human 关系缺失；
- Actor 关系缺失；
- purpose 关系缺失；
- surface 用途不匹配；
- 资源属于其他 Synthetic Tenant；
- Synthetic Tenant 已暂停；
- 身份已失效；
- Store 或 Model 响应不匹配；
- PDP 不可用。

因此 Facade 矩阵为 6 个 surface × 10 个场景，共 60 条。唯一正例是三项因素全部有效，其余九类均为拒绝路径。

## 与后续包的分界

C06 不替代以下能力：

- **C01**：员工入口中的实际读取与下载 PEP 接入；
- **C02**：管理后台中的实际管理 PEP 接入；
- **C07**：数据库、向量、对象、搜索、缓存和恢复副本的 Tenant 隔离；
- **C11**：检索前的权限过滤、EvidenceRef 与知识生命周期控制；
- **C16**：窄 Tool Operation、凭据管理和每次调用重鉴权；
- **O01**：短生命周期 microVM、网络/文件/资源限制和销毁证据。

C06 只给 `TOOL_CALL` 和 `SANDBOX_RUN` 定义授权入口，不会创建企业 Tool Gateway、代码沙箱、OA/ERP/BI 连接器或生产凭据。

## 验证

契约与静态模型测试：

```bash
node --test \
  tests/authorization-api.test.mjs \
  tests/pep-coverage.test.mjs \
  tests/authorization-model.test.mjs
```

C06 单元与 Facade 测试：

```bash
node --test \
  tests/authorization-catalog.test.mjs \
  tests/openfga-pdp.test.mjs \
  tests/openfga-policy-verifier.test.mjs \
  tests/authorization-fixture-matrix.test.mjs \
  tests/authorization-facade.test.mjs \
  tests/synthetic-pep-adapters.test.mjs
```

本地真实依赖测试：

```bash
sh scripts/run-c06-openfga-tests.sh
sh scripts/run-c06-postgres-tests.sh
sh scripts/run-c06-roles-postgres-tests.sh
```

这些脚本执行成功只能证明本次 P1 合成环境证据。OpenFGA/PostgreSQL 的生产认证、投影写凭据撤销、网络隔离、高可用、备份、容量、凭据轮换及 C07 存储隔离仍未验证，也不能代替 P3 的真实企业授权、连接器和隔离验收。
