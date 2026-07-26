# C10 知识摄取、解析与目录

## 当前结论

- 实现状态：`IMPLEMENTED`
- 证据状态：`EVIDENCE_CANDIDATE`
- 验证范围：`P1_SYNTHETIC_ONLY`
- 生产验证：`NOT_VERIFIED`
- 企业资料与连接器：`C0_DISABLED`
- 企业接入：`P3_REQUIRED`

C10 已实现一个可执行的最小工程闭环：冻结合成文档先以持久 `PUT` effect 和 `UPLOAD_PENDING` 状态登记，字节写入 Tenant 隔离检疫区后才原子完成为 `QUARANTINED`；删除则先进入不可读的 `DELETE_PENDING`，擦除引用后才原子完成为 `DELETED`。每个文档版本取得独立引用，相同内容的物理字节可复用且只在最后一个引用释放后擦除；服务或存储重启后可重新授权并收敛未完成 effect。内容经过哈希、类型、大小、宏、病毒标记和隐藏指令检查。只有检查通过的内容才会跨越封闭的 Parser Adapter 接口，转成候选节点；只有 Owner、来源、版本、有效期、密级和 ACL 全部齐全，并且服务端重新取得同 Tenant 的 C06 授权后，资料才可发布。

这不是生产知识平台验收。当前未接入任何企业资料、企业端点、真实对象存储、真实防病毒引擎、Docling、Tika 或 OCR。扫描图像路径使用冻结 PBM 字节和预置合成转写，只验证 Adapter 可替换接缝与坐标来源链，`productionOcrVerified=false`。

## 依赖与边界

| 依赖 | C10 使用方式 |
|---|---|
| C03 | PostgreSQL 外键只接受已登记的 Synthetic Tenant |
| C06 | 每次上传、检查、解析、发布、撤回、过期、删除和 as-of 读取都由服务端重新决策 |
| C07 | PostgreSQL 使用签名 Tenant 事务上下文和 `FORCE RLS` |
| C08 | 使用版本、CAS、幂等回执和追加式修订快照，不复制业务系统事实 |

P1 只接受 `synthetic-document-benchmark.v1.json` 中冻结的七份合成文档。未知引用或企业引用直接失败，不能通过上传接口夹带真实企业资料。

## 最小架构

```text
冻结合成文档
  -> Tenant 检疫引用 -> 内容哈希物理对象
  -> 持久 PUT / ERASE effect -> 重试与重启收敛
  -> SHA-256
  -> 类型 / 大小 / 宏 / 病毒标记 / 隐藏指令检查
  -> 封闭 Parser Adapter
  -> 候选解析 + 合成 golden 质量重算
  -> Original -> Page -> Section/Table -> Chunk 来源链
  -> 必填目录元数据校验
  -> 服务端 C06 同 Tenant 复核
  -> PostgreSQL 目录 + 存储 effect + 修订快照 + 幂等回执
```

核心实现：

- `lib/knowledge-catalog.mjs`
  - 冻结合成基准加载；
  - Tenant 隔离检疫、独立文档版本引用、内容去重和最后引用擦除；
  - `UPLOAD_PENDING` / `DELETE_PENDING` 两阶段存储 effect 与恢复协调；
  - 检疫对象与引用映射快照恢复；
  - 内容 SHA-256；
  - 确定性安全检查；
  - 封闭、可替换的 Parser Adapter，以及按节点类型递归闭集的节点和坐标；
  - 候选解析、合成 golden 质量重算和来源链校验；
  - 发布必填字段；
  - 状态机、版本、as-of、撤回、过期和删除传播；
  - 内存存储、并发和恢复基准。
- `lib/c10-c06-authorizer.mjs`
  - 调用 C06 `AuthorizationFacade.decide`；
  - 绑定 Tenant、操作面、资源、Human、Workload、Delegation 和安全纪元；
  - 拒绝、异常或绑定不完整时失败关闭。
- `lib/postgres-knowledge-catalog-store.mjs`
  - 使用 C07 短时事务签名；
  - Serializable 写事务；
  - CAS 修订；
  - 持久存储 effect、语义请求哈希和幂等回执；
  - 读取与写入使用分离的最小权限角色。

## 状态机

```text
UPLOAD_PENDING -> QUARANTINED
  -> INSPECTED -> PARSED_CANDIDATE -> PUBLISHED
  -> REJECTED

PUBLISHED -> WITHDRAWN
PUBLISHED -> EXPIRED
任一未删除状态 -> DELETE_PENDING -> DELETED
```

重要约束：

1. `REJECTED` 资料不能解析或发布。
2. `PARSED_CANDIDATE` 不是权威知识。
3. 发布不会改变节点的 `authorityStatus=CANDIDATE`；它只改变可用状态。
4. 撤回、过期和删除会传播到全部来源节点。
5. `UPLOAD_PENDING` 不可检查、解析或发布；只有检疫写入成功后才成为 `QUARANTINED`。
6. `DELETE_PENDING` 会同步阻断目录与全部来源节点读取；只有检疫引用擦除成功后才成为 `DELETED`。
7. 删除后，目录与来源链保留不可变审计墓碑；物理对象仅在同 Tenant 最后一个引用释放后擦除。
8. 相同幂等键和相同语义请求返回原结果；相同键的不同输入被拒绝。
9. inspect/parse 在每次 C06 重新授权后、读取检疫字节或调用 Parser 前先查持久回执，因此删除后仍能重放已提交结果。

## 发布的七个硬条件

发布前必须同时存在：

1. `ownerPrincipalId`
2. `sourceRef`
3. `version`
4. `validFrom`
5. `validUntil`
6. `classification`
7. `acl`

ACL 必须与当前 `documentId` 绑定，并且至少各有一个读取主体和管理主体。缺少任何一项都不能发布。

## 来源链

所有解析结果始终是 `CANDIDATE`：

```text
ORIGINAL
  -> PAGE
      -> SECTION
          -> CHUNK
          -> TABLE
              -> CHUNK
```

每个节点保存：

- 稳定节点 ID；
- 类型和父节点；
- 顺序；
- 页、行、表或行号坐标；
- 节点文本哈希；
- 原件内容哈希；
- 候选权威状态；
- 当前可用状态；
- 删除时间。

应用层先按 `nodeType` 重构节点，拒绝任何额外字段、错误坐标变体、错误类型或越界值，再验证父子类型、循环、根节点和来源哈希。即使替换 Parser 重新计算 `parseSha256`，不在闭集内的数据也不能进入目录。PostgreSQL 再用触发器验证原件哈希、父节点类型、不可变来源字段和状态传播。

## PostgreSQL

迁移顺序：

1. `C03/0001_tenant_registry.sql`
2. `C07/0011_tenant_data_isolation.sql`
3. `C07/0012_tenant_data_runtime_roles.sql`
4. `C10/0017_knowledge_catalog.sql`
5. `C10/0018_knowledge_catalog_runtime_roles.sql`

C10 表：

- `aios_knowledge.knowledge_document`
- `aios_knowledge.source_node`
- `aios_knowledge.knowledge_revision`
- `aios_knowledge.command_receipt`
- `aios_knowledge.storage_effect`

三个 NOLOGIN 角色：

| 角色 | 权限 |
|---|---|
| `aios_c10_owner` | 对象所有者；不登录、不继承、不绕过 RLS |
| `aios_c10_runtime` | 读取、插入和受触发器约束的更新；无 DELETE |
| `aios_c10_reader` | 只读目录、来源节点和修订；不能读取命令回执 |

所有五张表启用并强制 RLS。`storage_effect` 只允许 Runtime 读取、插入和从 `PENDING` 更新为 `COMPLETED`；不能删除或改写 effect 身份。PUBLIC 没有 Schema、Table、Sequence 或 Function 权限。

## 冻结基准

`synthetic-document-benchmark.v1.json` 包含：

- 干净 Markdown，两页、两个节和一张表；
- 干净 CSV；
- 冻结 PBM 扫描图像字节；
- 合成宏文档；
- 合成病毒标记；
- 隐藏指令；
- 超过冻结大小限制的文档。

每份基准都有固定字节数和 SHA-256。它只用于证明安全边界和状态转换，不代表生产解析质量。

## P1 合成解析质量证据

- `synthetic-parser-golden.v1.json` 冻结两份解析期望：两页 Markdown 的 Page/Section/Table/Chunk 坐标，以及 PBM 扫描路径的 Page/Section/Chunk 坐标。
- PBM 路径使用文件中冻结的预置合成转写，不运行 OCR，也不声称识别了图像文字。
- `createC10SyntheticParserAdapter()` 只暴露 `parse(input)`；C10 对返回字段、候选状态、来源链、计数和解析哈希做失败关闭校验。
- 后续 Docling、Tika 或其他解析器只能通过同一个 Adapter 接口替换；当前环境没有连接或验证它们。
- `synthetic-parser-quality-report.v1.json` 可由冻结 benchmark、golden 和 Adapter 重算，精确比较页、节、表、Chunk 数量与坐标。
- 报告状态固定为 `CANDIDATE_P1_SYNTHETIC`、范围固定为 `P1_SYNTHETIC_ONLY`，不能外推成真实扫描件或生产 OCR 质量。

## 验收矩阵

`acceptance-matrix.v1.json` 冻结了 52 个候选验收场景，覆盖：

- 合成边界和 Tenant 检疫；
- 哈希和五类检查；
- 候选解析和来源链；
- 七项发布硬条件；
- C06/C07 绑定；
- 版本和 as-of；
- 撤回、过期和删除；
- 跨 Tenant、越权、重放、并发和恢复；
- 相同内容的独立引用、共享物理字节、最后引用擦除和重启恢复；
- 封闭 Parser Adapter、PBM 合成扫描路径和可重算质量报告；
- 递归闭集 Parser 节点/坐标、删除后的 inspect/parse 回执预检；
- PUT/ERASE 故障、阶段间崩溃、服务/Store 重建和 reconciliation；
- PostgreSQL RLS、最小权限和不可变证据。

矩阵当前标记为 `CANDIDATE_P1_SYNTHETIC`，不能写成生产证明。

## 已执行测试

专项 Node 测试：

```sh
node --test \
  tests/c10-c06-authorizer.test.mjs \
  tests/c10-knowledge-catalog.test.mjs \
  tests/c10-knowledge-catalog-contract.test.mjs \
  tests/postgres-knowledge-catalog-store.test.mjs
```

结果：`45 PASS, 0 FAIL`。

本轮按任务边界没有改写 `c10-verification-evidence.candidate.v1.json`。因此旧候选证据的文件哈希完整性测试不属于上述通过数；它仍指向变更前文件，只有在单独批准重新生成候选证据后才能更新。

真实 PostgreSQL 17、pgvector、RLS 与角色测试：

```sh
implementation/p1/c10/run-postgresql-tests.sh
```

结果：`13 PASS, 0 FAIL`。

专项 lint：

```sh
npx eslint \
  lib/knowledge-catalog.mjs \
  lib/c10-c06-authorizer.mjs \
  lib/postgres-knowledge-catalog-store.mjs \
  tests/c10-c06-authorizer.test.mjs \
  tests/c10-knowledge-catalog.test.mjs \
  tests/c10-knowledge-catalog-contract.test.mjs \
  tests/c10-knowledge-catalog-evidence.test.mjs \
  tests/integration/c10-postgres.test.mjs
```

## P1 不证明的内容

- 内存检疫区不是生产对象存储；
- 合成病毒标记不是 ClamAV 或商业防病毒扫描；
- 确定性 Parser Adapter 不是 Docling、Tika 或 OCR 的质量证明；
- PBM 合成图像加预置转写不是 OCR；没有真实 PDF、Office、扫描件或加密文档解析质量证明；
- 没有企业密级映射、真实组织 ACL、保留策略、KMS、DLP 或法务保全；
- 没有证明 C11 检索、向量索引和生成回答已经失效传播；
- 没有生产备份、灾备、容量、吞吐、延迟或长时间稳定性证明；
- 没有任何 OA、ERP、BI、网盘、邮件或其他企业连接器。

这些能力必须在后续工作包和 P3 企业接入阶段使用批准的数据、接口和责任人重新验证。
