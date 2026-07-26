# C11 权限感知检索与 RAG

## 当前结论

- 实现状态：`IMPLEMENTED`
- 证据状态：`EVIDENCE_CANDIDATE`
- 验证范围：`P1_SYNTHETIC_ONLY`
- 生产验证：`NOT_VERIFIED`
- 企业资料与连接器：`C0_DISABLED`
- 企业接入：`P3_REQUIRED`

C11 已实现一个可执行的合成闭环：服务端先验证 C07 Tenant 范围并向 C06 重新取得当前 Human/Workload 授权，再由服务端解析 Human 与部门 Principal；只有当前 C10 状态为 `PUBLISHED`、位于有效期内且 ACL 允许的 Chunk，才会进入 PostgreSQL 全文与向量混合检索。候选返回前会再读取当前 C10 状态并执行最终 C06 与 Principal 复核。证据不足时固定拒答，不把候选正文送入模型上下文。

这不是生产 RAG 验收。当前没有企业资料、真实组织目录、真实模型生成、真实 Embedding 服务、OA、U9、BI、邮件、网盘或生产端点。

## 依赖与边界

| 依赖 | C11 使用方式 |
|---|---|
| C06 | 检索或同步前，服务端重新校验 Tenant、surface、resource、Human、Workload、Delegation 和安全纪元 |
| C07 | 使用已验证的 Synthetic Tenant 范围、短时签名事务和 `FORCE RLS` |
| C10 | 当前知识目录、发布状态、有效期、ACL、内容哈希以及 Original/Page/Section/Table/Chunk 来源链 |

P1 只允许 `synthetic-rag-benchmark.v1.json` 中冻结的合成 Principal、文档和查询。系统不会读取用户提供的 Tenant、Principal、ACL、状态、as-of 时间、Embedding 或任意向量库 Filter。

## 请求到回答

```text
SearchRequest（只有 requestId / query / limit）
  -> 验证 C07 Tenant
  -> 服务端调用 C06 RETRIEVE
  -> 服务端解析 Human + Group Principal
  -> 服务端可信时钟生成 as-of
  -> 服务端构造 Tenant + Principal + ACL + PUBLISHED + as-of Filter
  -> PostgreSQL authorized CTE 先过滤
  -> FTS + pgvector 混合评分
  -> 复核当前 C10 状态 / 修订 / 有效期 / ACL / Chunk 来源
  -> 最终 C06 RETRIEVE + Human / Group Principal 复核
  -> 分数与证据门
      -> 足够：EXTRACTIVE_DRAFT + EvidenceRef
      -> 不足：REFUSED + 空 modelContext
  -> 只记录哈希和计数的审计
```

首次 C06 `ALLOW` 和 Principal 解析成功后，服务端才读取可信时钟并固定本次检索 `asOf`；这个时刻是检索有效期判断的线性化点。候选当前态复核完成后，最后一次安全外部调用固定为 C06 `RETRIEVE`，紧接着重新解析 Principal；Tenant、Human 与安全纪元、Workload 与安全纪元、Delegation 链、purpose、policy、Principal refs 或 scope hash 有任何变化，候选全部丢弃并失败关闭。最终复核是候选和正文交付的线性化点，之后不再读取 C10 安全状态。

Filter 在检索前生效。没有“先搜出全部资料，再靠 Prompt 叫模型不要泄露”的路径。

## 服务端过滤条件

每次检索固定同时检查：

1. `tenant_id` 与 C07 范围一致；
2. C10 当前目录仍为 `PUBLISHED`；
3. C11 投影和 Chunk 都为 `PUBLISHED` 且 Chunk 为 active；
4. `validFrom <= asOf < validUntil`，其中 as-of 只来自服务端可信时钟；
5. C10 当前修订与投影修订一致；
6. C10 Chunk 当前可用状态仍为 `PUBLISHED`；
7. ACL `readPrincipalRefs` 至少命中一个服务端解析的 Human 或 Group Principal。

只有通过上述 CTE 的行才执行全文和向量评分。

## EvidenceRef 与拒答

每条 EvidenceRef 保存：

- Tenant、文档 ID、版本和 C10 修订；
- 原件内容哈希；
- Original 节点；
- Page 节点和页码；
- 可选的 Section；
- 可选的 Table；
- Chunk ID、顺序、位置和文本哈希；
- as-of 时间；
- 本次请求精确的服务端 `filterHash`；
- C06 决策、策略版本、Human 和 Principal 范围哈希。

回答只引用同一响应中存在的 Evidence ID。没有达到冻结证据门时：

```json
{
  "status": "REFUSED",
  "reasonCode": "INSUFFICIENT_AUTHORIZED_EVIDENCE",
  "answer": null,
  "modelContext": [],
  "evidence": []
}
```

## 缓存、撤回、过期与删除

缓存键只包含 Tenant、Human、Human 安全纪元、Principal scope、query、limit 和 Embedding model，不包含每次请求变化的精确 `asOf` 或 `filterHash`；两者都保留在 EvidenceRef，查询审计另保留精确 `filterHash`。命中缓存前会重新验证当前 index epoch、C10 状态与修订、当前有效期、ACL 和候选 Chunk，缓存最长存活 30 秒；空结果缓存同样受 TTL 约束。读取时会机会式删除过期行，写入仍使用 index epoch CAS，避免撤权或索引变化后的旧候选复活。

C10 状态变为 `UPLOAD_PENDING`、`DELETE_PENDING`、撤回、过期或删除后，C11 会立即视为不可检索；同步会在一个 Serializable 事务内：

1. 增加 Tenant index epoch；
2. 清除该 Tenant 的检索缓存；
3. 将该文档全部 Chunk 标为 inactive；
4. 传播 C10 状态和目录修订；
5. 写入幂等投影回执；
6. 由延迟约束在提交时验证 C10/C11 一致。

检索开始时会记录当时看到的 Tenant index epoch。缓存写入必须在同一原子操作中确认该 epoch 仍未变化；若原子比较发现投影在检索期间发生变化，旧候选不得写入或返回，服务只重试一次，第二次仍冲突则安全拒答。

检索 SQL还会联接 C10 当前目录与来源节点，避免一个旧投影绕过当前 C10 状态。生产事件消费者和延迟 SLO 仍需在后续部署工作中实现和验证。

## PostgreSQL

迁移顺序：

1. `C03/0001_tenant_registry.sql`
2. `C07/0011_tenant_data_isolation.sql`
3. `C07/0012_tenant_data_runtime_roles.sql`
4. `C10/0017_knowledge_catalog.sql`
5. `C10/0018_knowledge_catalog_runtime_roles.sql`
6. `C11/0025_permission_aware_rag.sql`
7. `C11/0026_permission_aware_rag_runtime_roles.sql`

C11 六张表：

- `aios_rag.tenant_index_epoch`
- `aios_rag.document_projection`
- `aios_rag.chunk_index`
- `aios_rag.retrieval_cache`
- `aios_rag.projection_receipt`
- `aios_rag.query_audit`

索引包括：

- 投影状态、Tenant 和有效期 B-tree；
- ACL GIN；
- Chunk 全文 GIN；
- `vector(8)` cosine HNSW。

三个 NOLOGIN、NOINHERIT、NOBYPASSRLS 角色：

| 角色 | 权限 |
|---|---|
| `aios_c11_owner` | 数据库对象所有者，不作为应用登录 |
| `aios_c11_projector` | 写投影、索引、epoch、回执；可删除缓存；不能写查询审计 |
| `aios_c11_query` | 只读投影和索引；可写缓存、删除过期缓存并写查询审计；不能修改索引，也不能读取审计 |

六张表全部启用并强制 RLS。PUBLIC 没有 C11 Schema、Table、Sequence 或 Function 权限。

## 冻结基准

`synthetic-rag-benchmark.v1.json` 冻结了：

- 3 个合成 Human Principal 和两个合成部门；
- 销售、财务、已过有效期和生命周期失效用文档；
- 每个可索引 Chunk 的精确文本和 SHA-256；
- 8 维确定性哈希 Embedding；
- 4 个允许、越权和证据不足查询。

确定性 Embedding 只用于证明排序、隔离和重复执行，不代表生产语义召回质量。

## 验收矩阵

`acceptance-matrix.v1.json` 冻结 45 个候选验收场景，覆盖：

- 合成边界和客户端 Filter 禁止；
- C06/C07 与 Principal 绑定；
- Tenant、ACL、状态和有效期前置过滤；
- FTS + pgvector；
- 完整 EvidenceRef 与确定性拒答；
- Principal 范围缓存和 index epoch；
- 短 TTL、最终授权复核、Pending 状态、撤回、删除和无正文审计；
- 幂等、并发、恢复；
- PostgreSQL 17、来源触发器、RLS 与最小权限。

矩阵全部标记为 `CANDIDATE_P1_SYNTHETIC`，不能写成生产证明。

## 已执行测试

专项 Node 测试：

```sh
node --test \
  tests/c11-c06-authorizer.test.mjs \
  tests/c11-permission-aware-rag.test.mjs \
  tests/c11-permission-aware-rag-contract.test.mjs \
  tests/c11-permission-aware-rag-evidence.test.mjs
```

真实 PostgreSQL 17、pgvector、FTS、RLS 与角色测试：

```sh
implementation/p1/c11/run-postgresql-tests.sh
```

专项 lint：

```sh
npx eslint \
  lib/c11-c06-authorizer.mjs \
  lib/permission-aware-rag.mjs \
  lib/postgres-permission-aware-rag-store.mjs \
  tests/c11-c06-authorizer.test.mjs \
  tests/c11-permission-aware-rag.test.mjs \
  tests/c11-permission-aware-rag-contract.test.mjs \
  tests/c11-permission-aware-rag-evidence.test.mjs \
  tests/integration/c11-postgres.test.mjs
```

最终精确 PASS 数与文件哈希记录在 `c11-verification-evidence.candidate.v1.json`。

## P1 不证明的内容

- 没有企业资料、真实用户、真实部门、调岗、离职或临时项目 ACL；
- 没有真实 Embedding API、模型生成、重排模型或人工标注的生产质量集；
- 没有中文分词、OCR、真实 PDF/Office/图片或超大知识库质量证明；
- 没有缓存集群、消息总线、自动索引消费者、失效延迟 SLO 或长时间稳定性证明；
- 没有生产容量、吞吐、P95/P99 延迟、备份、灾备、KMS、DLP 或法务保全；
- 当前恢复测试只是在同一个临时数据库中重建 Store 实例并读取既有状态；P2 要求的全新 PostgreSQL 集群备份恢复尚未验证；
- 没有任何 OA、U9、BI、邮件、网盘或其他企业连接器；
- 独立复核、已提交源码哈希和父任务冻结后的全仓回归仍待完成。

这些内容必须在后续工作包和 P3 企业接入阶段，用批准的资料、接口、责任人和生产验收重新证明。
