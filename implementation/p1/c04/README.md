# C04 身份联邦、SSO 与 Provisioning

P1 工程状态：`IMPLEMENTED / VERIFIED（SYNTHETIC_ONLY）`

生产验证状态：`NOT_VERIFIED`

C04 已完成本工作包的 P1 通用产品核心，只使用三个 F02 Synthetic Tenant 和合成
身份数据。没有接收目标企业身份资料、IdP 地址、账号或凭据；OA、U9、BI
及全部企业 Connector 继续保持 `C0`。这里的 `VERIFIED` 只表示锁定版本和
所列合成边界已经通过工程验收，不能解释为真实企业身份接入或生产部署完成。
本页继续区分“已进入 C04 Core 的证据”“独立协议运行证据”和“相邻组件
组合证据”，不把它们混称为一条尚未运行过的生产端到端链路。

## 五个 Core 入口

`createIdentityFederation(...)` 只返回：

- `execute(context, command)`：处理 Tenant 投影、账号快照、Provider 密钥
  轮换/退役和会话撤销；
- `startLogin(serverContext, request)`：生成一次性 state、nonce 和 PKCE S256；
- `completeLogin(serverContext, request)`：通过 Broker 验证授权码并签发短时
  会话；
- `resolveSession(serverContext, request)`：每次使用前重新检查 Tenant、账号、
  Provider、会话有效期和撤销代次；
- `snapshot(context, query)`：返回字段白名单治理视图，不含 subject、目录 ID、
  Token、Token Hash、密码或完整 Claims。

`execute` 当前只接受五类 P1 命令：

- `APPLY_TENANT_LIFECYCLE_EVENT`
- `APPLY_SYNTHETIC_ACCOUNT_SNAPSHOT`
- `ROTATE_SYNTHETIC_PROVIDER_KEYS`
- `RETIRE_SYNTHETIC_PROVIDER_CONFIGURATION`
- `REVOKE_SESSION`

每类命令由 Core 按 kind 重新检查自己的能力，HTTP 网关的 OAuth scope 不能
替代这次服务端鉴权。

## 当前证据分层

| 能力 | 当前证据 | 不能据此宣称 |
|---|---|---|
| OIDC + MFA | Keycloak 26.7.0 真实 Authorization Code + PKCE、JWKS RS256 与 password→TOTP；缺失/错误 OTP 无授权码，`amr=pwd+otp` 进入 C04 Core | 生产 Keycloak 集群、真实企业 IdP 或企业 MFA 策略已接入 |
| SAML | Keycloak 两 Realm 的 SAML Broker → OIDC PKCE 黑盒路径，验证双向签名、Audience、Recipient、InResponseTo、精确响应重放，并拒绝未知且未预链接用户的 JIT 创建 | SAML Assertion 已直接进入 Core，或通用 Assertion-ID replay cache 已实现 |
| SCIM | Keycloak 26.7.0 `scim-api:v1` Preview 真实协议测试；Adapter 防护；独立 SCIM→Core 固定组合测试；PostgreSQL 持久 checkpoint 双会话互斥测试 | Preview 已稳定可生产，或三者已在一个真实进程中完成端到端故障演练 |
| PostgreSQL | 17.10 迁移 0002→0006、0002→0004 有数据升级、32 路重复投递、登录/离职竞态、崩溃回滚、直接 SQL 防篡改及三个最小权限运行角色 | 高可用、备份恢复、凭据轮换和正式部署环境已验收 |
| Outbox | claim、lease fencing、失败重试、过期重领、`PUBLISHED` 终态及真实 C04→C03 投递回路 | 独立生产 Worker 服务已经部署 |

Keycloak SCIM 在当前锁定版本仍为 Preview，且
`ServiceProviderConfig.etag.supported=false`。虚构 stale `If-Match` 仍会被
接受，因此并发顺序由 C04 checkpoint 和严格 `externalId` 互斥负责，不能
假设远端资源具备乐观锁。

## 身份认证不等于业务授权

C04 只回答“这个登录是否属于一个已 Provision 的有效账号”：

- 返回 `identityAccountId`，不返回 `principalId`；
- 固定返回 `authorizationStatus=NOT_EVALUATED`；
- 邮箱、姓名、显示名、工号、Group 和 Role 都不是合并键；
- IdP Group/Role 不直接变成业务权限；
- C05 才建立 Stable Principal 与委托链；
- C06 才决定读取、运行、管理或 Tool 调用是否允许。

## P1 固定边界

- 只接受 C03 登记的 `stn_*` Synthetic Tenant；
- 初始 Provider 身份和安全配置来自冻结的
  `synthetic-identity-catalog.v1.json`；
- 初始 `configurationVersion` 必须为 1；
- Provider issuer 和 Redirect 必须是无凭据的 `.example` HTTPS；
- 登录策略固定为 `SCIM_REQUIRED`，未知 subject 即使 Token 有效也拒绝；
- Federation 唯一键使用 Tenant、Provider、精确 issuer 和区分大小写的
  subject；
- Provisioning 唯一键使用 Tenant、Provider 和 directory object；
- 两种绑定只通过 Synthetic Catalog 显式关联；
- 不保存密码、授权码、原始 ID/Access/Refresh Token、原始 Session Token
  或完整 Claims。

后续 Key Set 不通过编辑 Catalog 变更，只能由具备
`IDENTITY_PROVIDER_ROTATE` 的服务提交单调版本命令：

- 普通轮换：旧 CURRENT 进入 GRACE，完整保留一个登录事务 TTL；未到期不能
  普通退役；
- 到期退役：GRACE 单向进入 RETIRED；
- 紧急轮换：所有旧 CURRENT/GRACE 立即进入紧急 RETIRED，新版本成为唯一
  CURRENT，并撤销该 Tenant 的现有会话；
- 登录事务和会话都固定记录准确 Provider 配置版本；
- PostgreSQL legacy Provider 镜像与新 CURRENT 配置原子同步，防止滚动升级
  中旧读取进程继续信任旧 Key。

仅改变 Key 数组顺序不算轮换；紧急轮换必须实际移除至少一个当前 Key。

## 账号、会话与重放

账号状态：

```text
ACTIVE ↔ SUSPENDED → TERMINATED
```

`TERMINATED` 是同一任职实例的永久吸收态。旧 revision、乱序消息、重放或
更高 revision 的 ACTIVE 都不能恢复它。P1 不实现返聘；未来返聘必须创建新
account incarnation。

每个账号和 Tenant 身份投影都有单调 `revocationEpoch`。账号变更、Tenant
暂停、恢复或删除会增加相应代次并撤销现有会话。登录 callback 必须固定并
验证其 Provider 配置版本；配置只能处于 `CURRENT` 或未过期 `GRACE`。会话
签发后，普通到期退役不会追溯性撤销既有会话；紧急轮换会显式撤销。每次解析
既有会话必须同时满足：

```text
C03 Tenant = ACTIVE
C04 Tenant Projection = READY
Provider = ACTIVE
Account = ACTIVE
Session = ACTIVE 且未过期
Session.accountEpoch = Account.revocationEpoch
Session.tenantEpoch = TenantProjection.revocationEpoch
```

登录 callback 先以 Hash 领取一次性事务，再交换授权码，并在提交会话前重新
锁定检查事务、Provider 版本、账号、Tenant 投影和撤销代次。离职先提交或登录
先提交两种顺序都不能在离职完成后留下有效会话。

Session Token 只由 Core 返回一次，Store 只保存 SHA-256。当前尚无 HTTP BFF
Cookie 实现；未来 BFF 必须转换为 `HttpOnly + Secure + SameSite` Cookie，
不能把 Token 暴露给浏览器脚本。

## PostgreSQL 与 Outbox

迁移顺序：

```text
C03 0001_tenant_registry.sql
→ C04 0002_identity_federation.sql
→ C04 0003_identity_outbox_delivery.sql
→ C04 0004_versioned_provider_configuration.sql
→ C04 0005_scim_checkpoint.sql
→ C04 0006_identity_runtime_roles.sql
```

命令在 `SERIALIZABLE` 事务内原子写入投影、Provider、账号/会话、事件、Outbox
和回执。只对 PostgreSQL `40001`、`40P01` 以及明确的
`identity_provider_tenant_id_key` 首次投影竞争做有界重试；其他唯一键冲突
继续失败关闭。

Outbox 是至少一次语义。Worker claim 使用排他 lease 和递增
`lease_version`；旧 Worker 不能确认新租约，`PUBLISHED` 不可恢复。

`0006` 创建三个无登录能力、互不继承的运行角色：

- Core 只拥有 C04 核心表所需的精确读写权限；
- Outbox Worker 只拥有投递表所需的精确读写权限；
- SCIM checkpoint 角色只拥有 checkpoint 表所需的精确读写权限；
- 迁移 Owner 不属于任何运行角色，`PUBLIC` 不保留 C04 表权限。

SCIM checkpoint 以 `(tenant_id, provider_connection_id, external_id)` 隔离，
使用 session-level advisory lock。必须使用直连或 session pooling；
transaction pooling 会破坏锁归属，因此禁止。

## 可重复运行验证

```sh
node --test tests/identity-catalog.test.mjs \
  tests/identity-federation.test.mjs \
  tests/identity-federation-api.test.mjs \
  tests/identity-postgres-contract.test.mjs \
  tests/identity-postgres-outbox-contract.test.mjs \
  tests/keycloak-scim-provisioning-adapter.test.mjs \
  tests/postgres-scim-checkpoint-contract.test.mjs \
  tests/scim-identity-provisioner.test.mjs \
  tests/c04-c03-integration.test.mjs

sh scripts/run-c04-postgres-tests.sh
sh scripts/run-c04-outbox-postgres-tests.sh
sh scripts/run-c04-scim-checkpoint-postgres-tests.sh
sh scripts/run-c04-roles-postgres-tests.sh
sh scripts/run-c04-keycloak-oidc-tests.sh
sh scripts/run-c04-keycloak-saml-tests.sh
sh scripts/run-c04-keycloak-scim-tests.sh
```

真实运行脚本只使用一次性本地 PostgreSQL/Keycloak、随机测试凭据、`.example`
TLS 和回环监听；结束时必须停止进程并删除临时运行目录。

## P1 验收结果

当前冻结前总验收：

- 全部仓库单元/契约测试：`145 PASS, 0 FAIL`；
- C04 Core 真实 PostgreSQL：`13 PASS, 0 FAIL`；
- Outbox 真实 PostgreSQL：`1 PASS, 0 FAIL`；
- SCIM checkpoint（含契约与真实 PostgreSQL）：`12 PASS, 0 FAIL`；
- 数据库最小权限角色：`1 PASS, 0 FAIL`；
- 真实 Keycloak OIDC + TOTP：`1 PASS, 0 FAIL`；
- 真实 Keycloak SAML Broker：`1 PASS, 0 FAIL`；
- 真实 Keycloak SCIM Preview：`5 PASS, 0 FAIL`；
- 全量构建、ESLint 和 `git diff --check`：通过。

账号 ACTIVE revision 的更新会增加撤销代次、撤销旧会话并产生一次账号更新
Outbox，但不会授予任何业务 Group、Role 或权限；这些仍由 C05/C06 负责。

## 生产前仍需完成

以下事项不阻止 `P1 SYNTHETIC_ONLY` 工程验收，但继续阻止生产状态变为
`VERIFIED`：

1. P3 使用获批的真实企业资料，验证真实 IdP、目录属性、MFA 策略和账号关联；
2. Keycloak 外部 PostgreSQL、集群、高可用、备份恢复、密钥托管、证书与
   凭据轮换；
3. Keycloak SCIM 仍为 Preview；正式选型时重新评估稳定 SCIM 服务或
   Admin REST Adapter；
4. 当前 checkpoint 证明两个独立 Store/数据库会话互斥和异常释放，但没有
   完成真实 OS 进程或 PostgreSQL Backend 崩溃接管演练；
5. 若正式 SAML 风险模型要求跨登录会话防重放，增加有期限的
   Assertion-ID replay store；
6. C05 Stable Principal 与 C06 业务授权完成后，验证调岗、离职对全部下游
   关系和权限的撤销；
7. 将当前库和 Worker 部署到候选环境，重新执行容量、故障、恢复、审计、
   网络出口及升级/回滚验收。

因此，C04 当前可以进入下一个 P1 工作包，但不能宣称已经接入企业、已经可在
生产使用，或 OA、U9、BI 已连接。
