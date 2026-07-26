# C07 Tenant 数据隔离与生命周期

当前范围：`P1_SYNTHETIC_ONLY`。

当前实现和验证不得被描述为生产可用或 P3 已验证：

| 边界 | 状态 |
|---|---|
| 数据 | `SYNTHETIC_ONLY` |
| 生产验证 | `NOT_VERIFIED` |
| P3 验证 | `NOT_VERIFIED` |
| Enterprise Connector | `C0_DISABLED` |
| OA、U9、BI、企业身份、企业凭据和企业网络 | `P3_REQUIRED` |

## 调用者 Interface

调用者只选择冻结的 `operationId` 并提交该操作允许的输入。Tenant、Adapter、
物理路径和 C06 surface 全部由可信服务端绑定，不能来自浏览器请求或业务载荷。

```js
const operation = operationCatalog.resolve("SQL_GET");
```

`resolve` 返回递归冻结的 descriptor：

```text
operationId / adapterId / kind / path / surface / mode / inputKeys
```

业务请求不得包含 `tenantId`、`surface`、`adapterId`、`path`、任意 SQL、
Bucket、索引或 Namespace。`kind` 与 `operationId` 相同，供 Adapter 做封闭
分派；Adapter 不能使用调用者自报的 kind。

## 冻结操作

| operationId | Adapter | path | surface | mode | inputKeys |
|---|---|---|---|---|---|
| `SQL_PUT` | `c07.postgres` | `records` | `MANAGE` | `WRITE` | `resourceId,value` |
| `SQL_GET` | `c07.postgres` | `records` | `READ` | `READ` | `resourceId` |
| `VECTOR_UPSERT` | `c07.postgres` | `vectors` | `MANAGE` | `WRITE` | `resourceId,embedding,metadata` |
| `VECTOR_SEARCH` | `c07.postgres` | `vectors` | `RETRIEVE` | `READ` | `embedding,limit` |
| `SEARCH_INDEX` | `c07.postgres` | `search-documents` | `MANAGE` | `WRITE` | `resourceId,text,metadata` |
| `SEARCH_QUERY` | `c07.postgres` | `search-documents` | `RETRIEVE` | `READ` | `query,limit` |
| `CACHE_PUT` | `c07.postgres` | `cache-entries` | `MANAGE` | `WRITE` | `cacheKey,value,ttlSeconds` |
| `CACHE_GET` | `c07.postgres` | `cache-entries` | `READ` | `READ` | `cacheKey` |
| `OBJECT_PUT` | `c07.object-storage` | `objects` | `MANAGE` | `WRITE` | `objectKey,body,contentType` |
| `OBJECT_GET` | `c07.object-storage` | `objects` | `DOWNLOAD` | `READ` | `objectKey` |
| `OBJECT_LIST` | `c07.object-storage` | `objects` | `RETRIEVE` | `READ` | `cursor,limit` |

所有写操作固定使用 C06 `MANAGE`；普通读取使用 `READ`，向量、搜索和对象
列举使用 `RETRIEVE`，对象正文读取使用 `DOWNLOAD`。请求方不能降低或覆盖
surface。

## Ports 与 Adapters

- 生产候选 PostgreSQL Adapter：SQL、pgvector、PostgreSQL FTS、最小 TTL
  Cache 和连接池。所有 Tenant 表同时使用 `tenant_id`、`ENABLE/FORCE RLS`、
  `USING` 与 `WITH CHECK`。
- 数据连接不能自己声明 Tenant。独立 Scope 角色在 C03/C06 已通过后签发
  15 秒 HMAC，绑定 Tenant、生命周期、授权证据、数据库 Backend PID 和
  Transaction ID；数据角色只拿签名，拿不到签名密钥，也没有签发权限。
- 数据、Scope、生命周期使用三个独立连接池。每次取连接都反查实际角色，
  拒绝 Owner、Superuser、`BYPASSRLS` 或错误角色成员。
- 当前 P1 对象实现：仅使用合成数据的本地文件 Adapter。逻辑对象键映射到
  服务端生成的 Tenant 目录，不能由请求选择物理目录；同 Tenant 写入与
  生命周期清理由同一进程内、同一根目录的共享锁串行，即使创建多个 Adapter
  实例也不能在删除成功后复活对象；符号链接和越界路径失败关闭。
- S3-compatible Object Storage 与其 Tenant Prefix/Bucket Policy 仍为
  `NOT_VERIFIED`，不是当前实现或生产候选证明。
- 合成测试使用确定性 Adapter 故障替身，验证任一存储投影失败时不能回报
  `STORAGE/SUCCEEDED`，并验证相同事件重试后才收敛。
- C03 与 C06 使用现有真实 Adapter；单元测试可换成记录调用的 Fake。
- 恢复副本复用相同读取 Adapter，只绑定专用 `SELECT` 角色；恢复进程不持有
  生命周期写凭据，`project` 与治理 Snapshot 在只读实例上均失败关闭。

P1 不引入 Qdrant、OpenSearch 或专用 Redis/Valkey。容量证据出现前，向量、
搜索和 Cache 保持在 PostgreSQL 内，减少必须独立证明隔离的系统数量。

## 顺序与不变量

1. 服务端校验冻结目录与封闭输入。
2. 按 descriptor 固定的 surface 调用 C06；C06 内部执行 C03 准入，
   拒绝或不可用均失败关闭。
3. C07 再次调用 C03，将该次 `ACTIVE` 准入作为请求的线性化点，并创建
   内部 Tenant Scope。已经准入的在途请求可以完成；生命周期切换提交后
   的下一次请求必须拒绝，不能在 Adapter 提交后再返回事后失败。
4. 删除投影会等待已经准入的在途写完成，再清除该 Tenant 的数据。
5. C03 生命周期事件必须与 C03 Event/Outbox 中的同 ID、同规范化哈希
   记录完全一致，不能只信任调用者自报的 worker 字符串。
6. 授权成功后才允许查询幂等回执、Cache 或任一存储 Adapter。
7. PostgreSQL 在事务内使用已签名的 `set_config(..., true)` Context；
   RLS 重新计算 HMAC 并核对 Backend PID、Transaction ID 和过期时间。
   连接归还前逐项确认 Context 已清除。
8. 普通读写事务先锁住 Tenant 生命周期行；删除投影等待在途写入提交后，
   再在 `READ COMMITTED` 下清除，避免恢复旧快照遗漏刚提交的数据。
9. C03 进入 `DELETING` 后，C07 清除并反查 SQL、向量、对象、搜索和 Cache；
   全部为空后才可回报 `STORAGE/SUCCEEDED`。

Cache 命中仍必须重新调用 C06。对象前缀、向量 Filter、搜索 Filter、缓存键
或单一 `tenant_id` 字段都不能单独作为完整隔离证明。

P1 的 HMAC 密钥只存在合成 PostgreSQL 中并随合成备份恢复；生产密钥托管、
轮换、Worker 凭据隔离、对象多进程锁、S3 Policy 和网络策略仍由 C18/P3
验收，当前不得描述为生产认证。

## pgvector 锁定

P1 锁定 pgvector `0.8.5` 的 Homebrew source tarball：

```text
source tarball sha256:
6f88a5cbdde31666f4b6c1a6b75c51dcbeffe58f9a7d2b26e502d5a6e5e14d44

实测 vector.control sha256:
cd7733e99b25bd02b11db28f5f53a1fb7d253dd773e4bc47f6e3236950ff0ddd
```

锁文件只固定 P1 本机合成验证输入，不构成生产发行认证。
PostgreSQL 在线脚本会现场重算已安装 `vector.control`；source tarball SHA
只锁定已取得的分发输入，本轮不会依赖网络重新下载该 tarball。

## 验收

`isolation-matrix.v1.json` 冻结 SQL、vector、object、search、cache、pool 和
restore 的正例、跨 Tenant 负例，以及接口注入和 Tenant 生命周期负例。

```bash
sh scripts/run-c07-tests.sh
npm run lint
```

`run-c07-tests.sh` 会依次运行边界/目录/对象/静态合同、真实 PostgreSQL 17.10
在线隔离、实际角色滥权，以及 `pg_dump → 独立恢复库 → 只读端点` 三 Tenant
黑盒复测。静态合同通过不等于运行时隔离或恢复通过；三组脚本均通过并冻结
前，不得生成 C07 最终 verification evidence。
