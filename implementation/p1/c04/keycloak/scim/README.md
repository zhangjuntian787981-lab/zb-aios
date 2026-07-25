# C04 Keycloak SCIM Preview 合成验证

状态：`RUNTIME_VERIFIED_PREVIEW_ONLY / NOT_PRODUCTION_STABLE`

本目录记录 Keycloak 26.7.0 `scim-api:v1` 的真实合成运行验证。该能力在
Keycloak 中仍是 **Preview、默认关闭且不建议直接用于生产**。这里的绿色测试
只能证明锁定版本的本机协议行为和 C04 最小 Provisioning Adapter 边界，不能
把 SCIM 或整个 C04 标记为生产 `VERIFIED`。

## 运行

```sh
sh scripts/run-c04-keycloak-scim-tests.sh
```

脚本复用
`implementation/p1/c04/keycloak/keycloak-distribution.lock.json`，固定：

- Keycloak `26.7.0`；
- 发布包 SHA-256
  `f771df0aa1e4820f57d56f7d6d015beb6415487b43f8de7e5a6d48f8a7fe118a`；
- OpenJDK 21；
- 一次性 H2、随机运行时密钥、自签 `.example` TLS；
- 仅 `127.0.0.1` 监听；
- `mktemp` 运行目录和退出清理。

任何真实企业目录、凭据、OA、U9 或 BI 数据都不进入该测试。

## 已实际验证

真实 Keycloak 进程中的验收包括：

1. SCIM `/ServiceProviderConfig` 明确返回 `etag.supported=false`；
2. OAuth 2.0 confidential service account 使用 `manage-users`，令牌必须包含
   与 realm SCIM base URL 完全相同的 `aud`；
3. `/Users` 的 create、read、update 和 `active=false` deactivate；
4. 重复 `userName` 返回 HTTP 409 和 `scimType=uniqueness`；
5. 虚构的 stale `If-Match` 仍能修改资源，且没有 ETag 响应头。这是
   **不支持并发条件写入的负面能力证据**，不是成功特性；
6. User Profile 将专用 Keycloak attribute 映射到 SCIM `externalId`；
7. Adapter 在远端创建成功、但本地确认失败后，重试通过 `externalId`
   找回并接管同一资源，不重复创建；
8. `sourceRevision` 使旧事件只读回当前结果，`TERMINATED` 为吸收态，更高
   revision 的 ACTIVE 也不能复活同一任职实例；
9. 每次写后都按 resource ID 回读并核对 externalId、userName、active、
   姓名和邮箱；
10. Adapter 只接受精确 HTTPS origin 和精确 SCIM audience；令牌 Port、
    网络 Port 和任意上游 `scimType` 失败都转换为固定脱敏错误；
11. 同一 `externalId` 的完整远端流程必须由 checkpoint Store 严格互斥；
    并发 revision 按序完成，旧 PENDING 进程消失后更高 TERMINATED 可以接管。
12. `lib/scim-identity-provisioner.mjs` 先提交 C04 Core 账号投影，再调用
    SCIM Adapter；SCIM 失败后的同事件重试只做远端对账，不重复 C04 Outbox。
    Core 判定 stale、终态复活或同 `sourceEventId` 篡改时不会调用 SCIM。

## Adapter 接口

实现文件：
`lib/keycloak-scim-provisioning-adapter.mjs`

对外只暴露一个运行方法：

```text
apply({
  externalId,
  userName,
  sourceRevision,
  desiredState: ACTIVE | SUSPENDED | TERMINATED,
  profile: { givenName, familyName, email }
})
```

构造时必须注入三个可信 Port，其中 checkpoint Port 包含两个方法：

- `getAccessToken`：获取短期 service-account token；
- `request`：执行受网络出口策略约束的 HTTPS 请求；
- `checkpointStore.transact`：原子读取、比较并保存 PENDING/CONFIRMED
  checkpoint；
- `checkpointStore.runExclusive`：把同一 externalId 的整个 token、搜索、
  写入、回读和确认流程串行化。

Adapter 不保存 client secret，也没有 logger Port，因此不会主动记录凭据。
生产候选使用 `lib/postgres-scim-checkpoint-store.mjs` 和
`postgresql/0005_scim_checkpoint.sql`：Store 构造时冻结 Synthetic
Tenant 与 Provider，数据库用复合主键、Provider 外键、不可逆状态守卫和
session-level advisory lock 实现持久检查点。真实 PostgreSQL 17 测试证明
两个独立 Store/数据库会话会按同一命名空间串行，回调异常后能释放锁；这不等
于真实进程或数据库 Backend 崩溃恢复演练。

`runExclusive` 只能在回调完成或持有数据库会话消失时释放，不能使用会过期
后仍允许旧 Worker 回写的普通短租约。部署必须使用直接连接或 session
pooling；transaction pooling 会破坏 session advisory lock 的归属，禁止用于
该 Store。每个进行中的 SCIM 操作会占用一个数据库连接。

## Core 组合接口

`lib/scim-identity-provisioner.mjs` 构造时固定 `tenantId`、
`providerConnectionId`、Core 调用上下文和可信账号 resolver。调用方只提交：

```text
apply({
  fixtureUserId,
  sourceEventId,
  sourceRevision,
  desiredState: ACTIVE | SUSPENDED | TERMINATED,
  correlationId
})
```

resolver 必须返回与固定租户、Provider 和 `fixtureUserId` 完全一致的
`directoryObjectId`、`loginSubject` 和 profile；组合层分别将前两者固定
映射为 SCIM `externalId` 和 `userName`，调用方不能覆盖。幂等键由固定命名
空间和 `sourceEventId` 生成 SHA-256，不接受外部输入。

## 不能据此宣称

- 不能宣称 Keycloak SCIM 是稳定生产能力；
- 不能宣称支持 ETag、`If-Match` 或乐观并发控制；
- 不能宣称完成高可用、外部 PostgreSQL、升级/回滚或容量验证；
- 不能宣称已经连接真实企业 IdP 或企业目录；
- C04 Core 负责账号 Outbox；独立 SCIM Adapter 本身仍不提供业务审计或适用
  的人工发布门；
- 不能把 Keycloak 管理员或 realm-management 广泛权限交给普通员工。

生产候选必须等待 Keycloak 将 SCIM 移出 Preview，并重新执行版本冻结、
协议回归、安全评审、故障恢复和权限最小化验收；在此之前，稳定 Admin REST
适配器或经验证的独立 SCIM 服务仍应保留为替代路径。

## 官方依据

- [Keycloak 26.7.0 release](https://www.keycloak.org/2026/07/keycloak-2670-released)
- [Keycloak server features](https://www.keycloak.org/server/features)
- [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/)
