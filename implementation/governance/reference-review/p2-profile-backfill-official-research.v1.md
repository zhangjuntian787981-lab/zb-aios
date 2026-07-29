# P2 Profile 回填官方参考研究 v1

## 1. 状态与边界

- 状态：`RESEARCH_INPUT_ONLY`
- 查询日期：`2026-07-30`
- 仓库核验提交：`817ab47674dd7a312aeaf386063acdec559a7fa1`
- 仓库核验 Tree：`141bd74abf86b7c16b08062f1ef10a49b010f6b0`
- 适用工作包：`C04`、`C06`、`C07`
- 目标：为 P2 Profile Approval 前的 `RETROSPECTIVE_BACKFILL` Reference Review Receipt 提供官方资料和仓库事实输入。

本文件不是 Reference Review Receipt、Bundle、D1 Approval、工作包状态或启动授权。下文的 `ADOPT`、`DEFER` 是拟议决定；只有后续关闭字段 Receipt 经语义验证、Git 冻结并被既有治理路径引用后，才具有对应治理效力。

权威边界：

1. `work-package-manifest.v1.json` 继续定义工作包与依赖；
2. 线上 D1 只追加治理账本继续记录治理状态；
3. Git 只冻结官方研究、Receipt、测试和工程证据；
4. 本研究不把 P1 合成验证写成生产采用；
5. 未研究的替代项目保持 `NOT_EVALUATED`，不凭空写成已拒绝。

## 2. 固定治理输入

| 输入 | 绑定 |
|---|---|
| Reference Candidate Catalog | `implementation/governance/reference-review/reference-candidate-catalog.v1.json` |
| Catalog 文件 SHA-256 | `sha256:2c2163e1ba42b67e6887451092bcec6d6eacdd9efd9b523cf64ed47e006f0654` |
| Catalog canonical SHA-256 | `sha256:db37fa9e04dfe5468ef97e13de55c7702b919040fc78755d33a8db7d1018523a` |
| Reference Review Policy | `implementation/governance/reference-review/reference-review-policy.v1.json` |
| Policy 文件 SHA-256 | `sha256:94db1b533ec3d81b755d52633f3890bd53452ef5730c7ce1f1a102198c3a29b9` |
| 当前 Profile 绑定状态 | `REQUIRES_NEW_PROFILE_AND_EXECUTION_BASELINE` |
| 被替换 Profile SHA-256 | `sha256:90a9741d6ae39012458f073523da0c7b4dc8e4eef53ea759b32d6640e6aaef32` |
| 被替换 source commit | `48a4e4eac1f2fc2404d21ca5ab9a2d014a0e20e5` |
| 被替换 execution baseline digest | `sha256:e6282c301d6eb05cace8361f5974143897db59c3770d4c8856211f0635599bee` |

Policy 明确把以下引用列为 Profile Approval 前的追加式回填：

- `C04` → `R09.KEYCLOAK`
- `C06` → `R11.OPENFGA`
- `C07` → `R12.POSTGRESQL_RLS`、`R12.PGVECTOR`

Catalog 当前仍将四项标为 `UNPINNED_REQUIRES_RECEIPT` 和 `candidateOnly=true`。本研究核实仓库已有精确版本锁与 PoC，但不直接改写 Catalog 或 Policy。

## 3. 结论摘要

| 工作包 / Reference | 仓库实际采用 | 拟议 Receipt 决定 | 精确范围 | 生产边界 |
|---|---|---|---|---|
| C04 / `R09.KEYCLOAK` | 是 | `ADOPT` | Keycloak 26.7.0 的 P1 合成 OIDC、TOTP、SAML Broker；SCIM 仅作 Preview 负面能力与适配验证 | SCIM 生产采用 `DEFER`；整体生产 IAM 仍未验证 |
| C06 / `R11.OPENFGA` | 是 | `ADOPT` | OpenFGA v1.18.1 的 P1 合成关系授权、不可变 Model ID、Tuple 和 Check | 持久化、认证、TLS、HA、备份与容量仍未验证 |
| C07 / `R12.POSTGRESQL_RLS` | 是 | `ADOPT` | PostgreSQL 17.10 RLS、`FORCE ROW LEVEL SECURITY`、`NOBYPASSRLS` 运行角色 | 生产 HA、独立灾备、容量、滚动升级仍未验证 |
| C07 / `R12.PGVECTOR` | 是 | `ADOPT` | pgvector 0.8.5 的 `vector` 类型、租户向量表和 RLS 隔离 | 当前无近似索引；生产规模、召回、延迟和降级仍未验证 |

关键纠偏：pgvector 不是“候选但未采用”。迁移 `0011_tenant_data_isolation.sql` 明确创建 `vector` 扩展和 `tenant_vector_record.embedding vector`，`0012_tenant_data_runtime_roles.sql` 对该表施加运行角色和 RLS 策略，C07 真实 PostgreSQL 验证也记录了 pgvector 0.8.5。

## 4. C04 / R09.KEYCLOAK

### 4.1 官方来源与实际阅读范围

| 官方来源 | 固定版本 | 实际阅读章节 / 内容 |
|---|---|---|
| [Keycloak 26.7.0 release](https://github.com/keycloak/keycloak/releases/tag/26.7.0) | tag `26.7.0`，release commit `6c73e30` | Highlights；SCIM API Preview；SAML Step-up；升级提示 |
| [Keycloak 26.7.0 Server Administration Guide](https://www.keycloak.org/docs/26.7.0/server_admin/) | 26.7.0 | OIDC client、PKCE、身份代理、SAML、OTP/2FA |
| [Managing users and groups through SCIM](https://www.keycloak.org/docs/26.7.0/server_admin/#managing-users-and-groups-through-scim) | 26.7.0 | Preview 状态、默认关闭、Bearer Token、Audience、Client Role 和用户/组接口 |
| [Production configuration](https://www.keycloak.org/server/configuration-production) | 官方在线文档，查询于 2026-07-30 | TLS、生产数据库、hostname、反向代理和集群基础要求 |
| [High availability introduction](https://www.keycloak.org/high-availability/introduction) | 官方在线文档，查询于 2026-07-30 | 单集群/多集群 HA 边界和运维责任 |
| [Upgrading Guide](https://www.keycloak.org/docs/latest/upgrading/) | 官方在线文档，查询于 2026-07-30 | 升级前备份、数据库 Schema 迁移、回退需恢复旧版本与数据库备份、H2 仅用于开发 |
| [Keycloak 26.7.0 LICENSE.txt](https://github.com/keycloak/keycloak/blob/26.7.0/LICENSE.txt) | tag `26.7.0` | Apache License 2.0；再分发、Notice、修改声明、商标和无担保条款 |

官方结论：

- 26.7.0 是明确发布版本；SCIM 在该版本是 **Preview**、默认关闭，不能据此宣称稳定生产能力。
- Keycloak 支持 OIDC、SAML、身份代理、OTP/2FA 和 PKCE；这些能力与 C04 PoC 的协议路径一致。
- 生产部署不能继续使用当前一次性 H2 形态；官方生产配置要求 TLS、生产数据库及相应集群/反向代理配置。
- Keycloak 升级会涉及数据库 Schema；官方升级资料要求先备份，出现问题时不能把数据库 Schema 原地“降级”，而应恢复旧安装和数据库备份。

### 4.2 仓库实际版本、实现和 PoC

版本锁：

- `implementation/p1/c04/keycloak/keycloak-distribution.lock.json`
- 文件 SHA-256：`sha256:c886967c1c9abc87ace8fa52a4f8cf5a93f80fae0ca2e10c881e8fe149121555`
- Keycloak：`26.7.0`
- 下载制品：`keycloak-26.7.0.tar.gz`
- 下载制品 SHA-256：`sha256:f771df0aa1e4820f57d56f7d6d015beb6415487b43f8de7e5a6d48f8a7fe118a`
- Java：21

冻结验证：

- `implementation/p1/c04/c04-verification-evidence.v1.json`
- 文件 SHA-256：`sha256:554df39362987342eaab88b5146b04a70bc3db8b566a81c6af5b1866816063de`
- `verified_source_commit`：`a24cb1a02c2fee0ac46c3558c42f5e7143957ac8`
- `verification_scope`：`P1_SYNTHETIC_ONLY`
- `production_verification_status`：`NOT_VERIFIED`
- C04 定向测试：75 PASS，0 FAIL
- 真实 Keycloak OIDC + TOTP：1 PASS
- 真实 Keycloak SAML Broker：1 PASS
- 真实 Keycloak SCIM Preview：5 PASS

主要证据路径：

- `implementation/p1/c04/keycloak/README.md`
- `implementation/p1/c04/keycloak/saml/README.md`
- `implementation/p1/c04/keycloak/scim/README.md`
- `scripts/run-c04-keycloak-oidc-tests.sh`
- `scripts/run-c04-keycloak-saml-tests.sh`
- `scripts/run-c04-keycloak-scim-tests.sh`
- `tests/integration/c04-keycloak-oidc.test.mjs`
- `tests/integration/c04-keycloak-saml.test.mjs`
- `tests/integration/c04-keycloak-scim.test.mjs`

仓库当前证明：

- OIDC Authorization Code + PKCE S256、密码后 TOTP、精确 issuer/audience/redirect、JWKS RS256；
- 双 Realm SAML Broker、双向签名、Audience、Recipient、InResponseTo 和精确响应重放拒绝；
- SCIM Preview 的 create/read/update/uniqueness/deactivate；
- SCIM `etag.supported=false`，虚构 `If-Match` 不构成乐观并发保护。这是已测得的负面能力证据，不是实现缺失被隐藏。

### 4.3 拟议决定

`decision = ADOPT`

决定严格限定为：

1. 采用 Keycloak 26.7.0 作为 C04 P1 合成身份联邦 PoC 的固定实现；
2. 采用范围包含 OIDC、TOTP 和 SAML Broker；
3. SCIM 仅采用为 Preview 兼容性和负面能力验证，不批准生产使用；
4. 生产 SCIM 决定维持 `DEFER`，触发条件为：候选版本离开 Preview 或替代 SCIM Adapter 完成版本、权限、并发、恢复和升级 PoC。

这不是 Keycloak 的整个平台生产采用决定，也不把 C04 P1 `VERIFIED` 扩张为生产 `VERIFIED`。

### 4.4 能力缺口、替代方案和风险

- 当前能力缺口：真实企业 IdP/AD/LDAP、生产 SCIM、外部 PostgreSQL、HA、备份恢复、正式证书、HSM/密钥托管、凭据轮换、容量和故障演练。
- 当前实现：一次性本机 Keycloak、H2、自签 `.example` TLS、随机凭据、loopback-only；测试结束删除临时材料。
- 替代路径：
  - 现有 C04 Core/Adapter 边界应保留，使身份提供者可替换；
  - 生产 SCIM 可改用经评审的独立 SCIM 服务或自有 Adapter；
  - 本研究没有评估或拒绝任何具名替代 IdP，状态为 `NOT_EVALUATED`。
- 数据流：Keycloak 接触身份、认证因素、协议断言和令牌；业务授权仍由 C06 处理，不得让 Keycloak Role 冒充完整业务授权真相。
- 安全边界：生产必须使用 TLS、正式信任链、最小 Client Role、精确 Audience/Redirect、密钥轮换和网络隔离；SCIM Preview 不得因测试绿色绕过此边界。

### 4.5 许可证、维护与退出

- 许可证：Apache-2.0。允许使用、修改和再分发，但必须保留许可证和适用 Notice/版权声明，并标明修改；许可证不自动授予产品商标权，也不提供担保。
- 品牌边界：可描述“兼容/使用 Keycloak”，不得暗示 Keycloak 官方背书。
- 升级：新版本必须重算分发制品 SHA-256，重跑 OIDC/TOTP/SAML/SCIM 兼容与负向测试，并先备份数据库。
- 退出：保留内部身份 Port、稳定 Principal 映射和 Provider 配置版本；退出时迁移 Realm/用户/配置并重新验证协议映射。数据库升级失败不能假设原地回退，必须使用旧版本安装和已验证备份恢复。

## 5. C06 / R11.OPENFGA

### 5.1 官方来源与实际阅读范围

| 官方来源 | 固定版本 | 实际阅读章节 / 内容 |
|---|---|---|
| [OpenFGA v1.18.1 release](https://github.com/openfga/openfga/releases/tag/v1.18.1) | tag `v1.18.1`，release commit `69efbd9` | 发布版本和制品边界 |
| [OpenFGA Concepts](https://openfga.dev/docs/concepts) | 官方在线文档，查询于 2026-07-30 | Store、Authorization Model、Tuple、Check |
| [Immutable Authorization Models](https://openfga.dev/docs/getting-started/immutable-models) | 官方在线文档，查询于 2026-07-30 | Model 不可变、固定 Model ID、渐进发布和影子检查 |
| [Running OpenFGA in Production](https://openfga.dev/docs/best-practices/running-in-production) | 官方在线文档，查询于 2026-07-30 | 认证、TLS、Playground、集群、数据库、限制和运维 |
| [Configure OpenFGA](https://openfga.dev/docs/getting-started/setup-openfga/configure-openfga) | 官方在线文档，查询于 2026-07-30 | datastore、迁移命令、认证方式、TLS |
| [OpenFGA Access Control](https://openfga.dev/docs/getting-started/setup-openfga/access-control) | 官方在线文档，查询于 2026-07-30 | 内置访问控制为 experimental，不建议生产使用 |
| [Contextual Tuples](https://openfga.dev/docs/interacting/contextual-tuples) | 官方在线文档，查询于 2026-07-30 | Contextual Tuple 的请求级、临时语义和令牌时效边界 |
| [OpenFGA v1.18.1 LICENSE](https://github.com/openfga/openfga/blob/v1.18.1/LICENSE) | tag `v1.18.1` | Apache License 2.0 的再分发、Notice、商标和无担保条款 |

官方结论：

- Authorization Model 不可变；运行时应绑定精确 `authorization_model_id`，而不是隐式使用“最新模型”。
- 生产环境需要外部认证、TLS、持久化 datastore、资源限制、集群与升级迁移。
- OpenFGA 内置访问控制仍是 experimental，官方不建议用于生产；不能用它替代外围服务身份、网络和最小凭据控制。
- Contextual Tuple 是请求级临时输入；若由 Token Claim 构造，其撤销时效受令牌寿命约束。

### 5.2 仓库实际版本、实现和 PoC

版本锁：

- `implementation/p1/c06/openfga/openfga-distribution.lock.json`
- 文件 SHA-256：`sha256:09a0cf0320f84aa478d78b394527b87a881be07614fef1cf856ef894f92f84a5`
- OpenFGA：`v1.18.1`
- release commit：`69efbd9`
- Darwin arm64 制品：`openfga_1.18.1_darwin_arm64.tar.gz`
- 制品 SHA-256：`sha256:d667620fcf54d5343fae374c60e1ac0af98defd5e44d93ca9af52866a2881f94`

冻结验证：

- `implementation/p1/c06/c06-verification-evidence.v3.json`
- 文件 SHA-256：`sha256:b80fe8d28b8c4b2ea8caa33f6685af0ab1c00b7f127b736600cd5e82feef83de`
- `verified_source_commit`：`6a23e93ed37eabec1201ff3a7bb00a0d9231fc49`
- `verification_scope`：`P1_SYNTHETIC_ONLY`
- `production_verification_status`：`NOT_VERIFIED`
- 单元验证：6 PASS
- 真实 OpenFGA：1 PASS
- 持久化矩阵：1 PASS
- 288 个决策样本：72 allow、216 deny、0 backend touch leak、0 attribution error

主要证据路径：

- `implementation/p1/c06/README.md`
- `implementation/p1/c06/openfga/README.md`
- `implementation/p1/c06/openfga/authorization-model.v1.json`
- `lib/openfga-pdp.mjs`
- `lib/openfga-policy-verifier.mjs`
- `scripts/run-c06-openfga-tests.sh`
- `tests/integration/c06-openfga.test.mjs`

仓库当前实现与官方建议一致的部分：

- 显式固定 Store 和不可变 `authorizationModelId`；
- 发布 Model 后读回并核验 Model/完整 Tuple 摘要；
- Check 使用固定 Store/Model，并支持 `HIGHER_CONSISTENCY`；
- 调用者不能覆盖 Store、Model、relation、Allow 结果或任意 Contextual Tuple；
- 任何 Model/Tuple/证据失配均失败关闭。

### 5.3 拟议决定

`decision = ADOPT`

决定严格限定为：

1. 采用 OpenFGA v1.18.1 作为 C06 P1 合成关系授权 PDP；
2. 采用不可变 Model ID、冻结 Tuple Bundle、读回验证和固定 Check；
3. 不采用 OpenFGA experimental 内置访问控制作为生产控制面安全边界；
4. 生产部署维持 `DEFER`，直到持久化 datastore、认证、TLS、网络隔离、备份、HA、容量、升级和恢复证据齐全。

### 5.4 能力缺口、替代方案和风险

- 当前能力缺口：真实工作负载身份、生产 TLS、持久化数据库、HA、备份恢复、容量和控制面隔离。
- 当前实现：真实 v1.18.1 可执行文件，但使用一次性 P1 datastore 和 loopback 路径。
- 替代路径：
  - 保留内部 PDP/PEP Port，避免业务代码直接依赖 OpenFGA HTTP 结构；
  - 可在未来用其他经评审 PDP 替换，但本研究未评估或拒绝具名替代产品，状态为 `NOT_EVALUATED`。
- 数据流：OpenFGA 保存授权 Model 和关系 Tuple；不应保存企业密码、业务文档或原始认证凭据。
- 安全边界：运行时仅获得 Check/Read 能力，模型/元组发布使用隔离控制面凭据；外围服务身份、TLS 和网络策略必须承担生产访问控制。
- 时效风险：受信 Contextual Tuple 若来自令牌声明，必须把 Token TTL 和撤销窗口纳入策略；不能宣称即时撤销。

### 5.5 许可证、维护与退出

- 许可证：Apache-2.0；再分发需保留许可证、版权/Notice 和修改声明，不能把许可证解释为商标授权或官方背书。
- 升级：每个新版本必须重新冻结 release/tag/asset SHA，运行数据库迁移，并重放冻结 Model/Tuple/决策矩阵。
- 回滚：Authorization Model 不可变，应保留旧 Model ID 和 Tuple Bundle，用新激活指针执行渐进发布或回滚；不能覆盖旧模型来伪造回滚。
- 退出：冻结的 OpenFGA 1.1 JSON Model 与 Tuple 可作为迁移输入；内部 PDP Port 允许替换实现。退出前必须导出、计数、哈希和对账全部 Model/Tuple，并重放相同允许/拒绝矩阵。

## 6. C07 / R12.POSTGRESQL_RLS

### 6.1 官方来源与实际阅读范围

| 官方来源 | 固定版本 | 实际阅读章节 / 内容 |
|---|---|---|
| [PostgreSQL 17.10 Release Notes](https://www.postgresql.org/docs/release/17.10/) | 17.10 | 精确版本、17.x 小版本迁移和安全修复 |
| [PostgreSQL 17 Row Security Policies](https://www.postgresql.org/docs/17/ddl-rowsecurity.html) | 17 | `ENABLE ROW LEVEL SECURITY`、默认拒绝、Owner/`BYPASSRLS` 边界、Policy 组合 |
| [CREATE POLICY](https://www.postgresql.org/docs/17/sql-createpolicy.html) | 17 | `USING`、`WITH CHECK`、permissive/restrictive、命令和角色范围 |
| [Role Attributes](https://www.postgresql.org/docs/17/role-attributes.html) | 17 | Superuser 与 `BYPASSRLS` 绕过边界 |
| [CREATE ROLE](https://www.postgresql.org/docs/17/sql-createrole.html) | 17 | `NOBYPASSRLS`、角色属性和 Owner 风险 |
| [pg_restore](https://www.postgresql.org/docs/17/app-pgrestore.html) | 17 | custom archive 恢复、角色/所有权和恢复选项 |
| [PostgreSQL License](https://www.postgresql.org/about/licence/) | 官方当前许可证 | PostgreSQL License；使用、复制、修改、分发、Notice 和无担保 |

官方结论：

- 启用 RLS 后，如果没有适用 Policy，普通角色获得默认拒绝；但表 Owner、Superuser 和 `BYPASSRLS` 角色可能绕过。
- `FORCE ROW LEVEL SECURITY` 可让表 Owner 在普通访问时也受策略约束，但运维角色和备份恢复路径仍需单独治理。
- Policy 必须分别约束可见行和可写入的新行；只写应用层 `WHERE tenant_id = ...` 不能替代数据库强制边界。

### 6.2 仓库实际实现和 PoC

冻结验证：

- `implementation/p1/c07/c07-verification-evidence.v1.json`
- 文件 SHA-256：`sha256:0d9b53b93966859a91fc3f7a8cf73d0ded84d3760cd5d46c3d3696e4424ceeb3`
- `verified_source_commit`：`b52ff7c5bd1e247745db48dad94b42d52daa888c`
- PostgreSQL：`17.10`
- `verification_scope`：`P1_SYNTHETIC_ONLY`
- `production_verification_status`：`NOT_VERIFIED`
- C07 定向测试：33 PASS
- 真实 PostgreSQL 隔离、运行角色、恢复：各 1 PASS
- 22 个冻结隔离矩阵用例

关键实现：

- `implementation/p1/c07/postgresql/0011_tenant_data_isolation.sql`
  - 文件 SHA-256：`sha256:06350029d5d99dd0b57681cd0c19ecfce87a4da7c61a74911ea2837c983e1f46`
  - 对租户表执行 `ENABLE ROW LEVEL SECURITY` 和 `FORCE ROW LEVEL SECURITY`
  - 使用 Tenant Context 和 `WITH CHECK` 约束读写
- `implementation/p1/c07/postgresql/0012_tenant_data_runtime_roles.sql`
  - 文件 SHA-256：`sha256:3ec52cc75571e863ffa01e6dddb256c174652375138cb1622baef798fbbfd41c`
  - 创建 `NOBYPASSRLS` 运行角色
  - 分离 Owner、Runtime、Lifecycle 和 Restore 能力

主要证据路径：

- `implementation/p1/c07/README.md`
- `scripts/run-c07-postgres-tests.sh`
- `scripts/run-c07-roles-postgres-tests.sh`
- `scripts/run-c07-restore-postgres-tests.sh`
- `tests/integration/c07-postgres.test.mjs`
- `tests/integration/c07-roles-postgres.test.mjs`
- `tests/integration/c07-restore-postgres.test.mjs`

### 6.3 拟议决定

`decision = ADOPT`

决定严格限定为 PostgreSQL 17.10 的 C07 P1 合成租户隔离基线。RLS、`FORCE ROW LEVEL SECURITY`、`NOBYPASSRLS` 与角色分离均被实际迁移和真实 PostgreSQL 测试使用。

应用层 Tenant Filter 不能作为同等替代方案；它可以作为纵深防御，但不能取代数据库层 RLS。生产部署仍为 `NOT_VERIFIED`。

### 6.4 许可证、安全、维护与退出

- 许可证：PostgreSQL License，宽松且类似 BSD/MIT；使用、复制、修改和分发需保留版权与许可文本，软件无担保。
- 数据边界：Tenant Context 必须由受信服务器设置，普通调用者不能提供或覆盖；运行连接必须是 `NOBYPASSRLS`，不能使用 Owner/Superuser。
- 特殊边界：备份、恢复、DDL、完整性约束和全表运维不等同于普通 RLS 查询，需独立角色、审计和恢复验收。
- 生产缺口：独立实例/主机恢复、HA、备份保留、密钥恢复、网络分区、容量、监控和滚动升级。
- 退出：RLS Policy 和角色是标准 PostgreSQL SQL 资产；退出到另一 PostgreSQL 17+ 环境时保留迁移、角色和 Policy，并用相同隔离矩阵验证。若退出 PostgreSQL，则必须先设计等价的数据库强制隔离，不能退化为仅应用过滤。

## 7. C07 / R12.PGVECTOR

### 7.1 官方来源与实际阅读范围

| 官方来源 | 固定版本 | 实际阅读章节 / 内容 |
|---|---|---|
| [pgvector v0.8.5 release](https://github.com/pgvector/pgvector/releases/tag/v0.8.5) | tag `v0.8.5`，release commit `159b79a` | 精确发布版本 |
| [pgvector v0.8.5 README](https://github.com/pgvector/pgvector/blob/v0.8.5/README.md) | v0.8.5 | PostgreSQL 13+、`CREATE EXTENSION vector`、vector 类型、精确/近似检索、HNSW/IVFFlat、过滤、升级 |
| [pgvector v0.8.5 CHANGELOG](https://github.com/pgvector/pgvector/blob/v0.8.5/CHANGELOG.md) | v0.8.5 | 版本变化和兼容性输入 |
| [pgvector v0.8.5 LICENSE](https://github.com/pgvector/pgvector/blob/v0.8.5/LICENSE) | v0.8.5 | PostgreSQL License；Notice 和无担保 |

官方结论：

- pgvector v0.8.5 支持 PostgreSQL 13+，因此与仓库 PostgreSQL 17.10 的版本范围兼容。
- 默认检索是精确搜索；HNSW 和 IVFFlat 是近似索引，用召回率换速度。
- 近似索引与过滤条件组合时，过滤发生位置和扫描参数会影响返回数量；新增近似索引前必须单独验证召回、延迟和租户过滤。
- 扩展升级使用 `ALTER EXTENSION vector UPDATE`，应检查 `pg_extension` 中实际安装版本。

### 7.2 仓库实际版本、实现和 PoC

版本锁：

- `implementation/p1/c07/pgvector/pgvector-distribution.lock.json`
- 文件 SHA-256：`sha256:bb52906adea3ce87cb21738cd6c12bef44b55cd2fc877a19c932a2153b53d5e4`
- pgvector：`0.8.5`
- source tarball SHA-256：`sha256:6f88a5cbdde31666f4b6c1a6b75c51dcbeffe58f9a7d2b26e502d5a6e5e14d44`
- 已安装 `vector.control` SHA-256：`sha256:cd7733e99b25bd02b11db28f5f53a1fb7d253dd773e4bc47f6e3236950ff0ddd`

实际采用证据：

- `0011_tenant_data_isolation.sql` 执行 `CREATE EXTENSION IF NOT EXISTS vector`；
- 创建 `tenant_vector_record`，字段 `embedding vector NOT NULL`；
- 约束 `vector_dims(embedding) BETWEEN 1 AND 2048`；
- 对向量表启用并强制 RLS；
- `0012_tenant_data_runtime_roles.sql` 为向量表定义 Runtime/Lifecycle Policy 和最小权限角色；
- C07 真实 PostgreSQL 测试核验 pgvector 0.8.5、隔离、角色与恢复。

当前迁移没有冻结 HNSW 或 IVFFlat 索引。因此，本研究只确认向量类型、读写和租户隔离的采用，不宣称近似向量检索已经设计或验证。

### 7.3 拟议决定

`decision = ADOPT`

决定严格限定为 pgvector 0.8.5 在 C07 P1 合成 PostgreSQL 数据平面中的向量存储和精确检索基础。它已经被实际迁移与真实数据库测试采用，不能写成 `NOT_APPLICABLE` 或“仅候选”。

以下范围仍为 `DEFER`：

- HNSW/IVFFlat 索引选型；
- 生产召回率、延迟、容量和并发；
- Tenant Filter 与近似扫描参数的正确性；
- 分片、多区域、降级和重新嵌入策略。

### 7.4 许可证、安全、维护与退出

- 许可证：PostgreSQL License；允许使用、复制、修改和分发，但应保留版权及许可文本，不提供担保。
- 数据边界：向量和 metadata 与其他租户数据共用 PostgreSQL 权限边界；必须继续由 RLS、运行角色和受信 Tenant Context 保护。
- 运维：升级前冻结 tag、source tarball SHA 和安装后 `vector.control`；执行 `ALTER EXTENSION vector UPDATE` 后重跑隔离、维度、检索和恢复测试。
- 退出：
  - 保留原始业务对象与重新嵌入所需的受控源数据/版本信息；
  - 导出向量前必须保持 Tenant 边界和行数/摘要对账；
  - 若迁移至外部向量库，需新增独立 Reference Review、数据流、删除/保留、权限和回滚 PoC；
  - 删除 `vector` 列或扩展只能在迁移完成、回读对账和回滚窗口关闭后进行。
- 替代方案：外部向量数据库本轮未评估，状态为 `NOT_EVALUATED`；不能据此推断已拒绝，也不应为凑 Receipt 强行引入。

## 8. Receipt 输入建议

后续每份正式 Receipt 应逐字绑定本文件中的官方来源版本和仓库证据，但仍需单独完成：

1. `applicableReferenceSetDigest` 和每份 Receipt 自身的 canonical SHA-256；
2. 精确 `reviewedSections`；
3. `sourceCommit` 与 Git Freeze Attestation；
4. `licenseAndRedistributionAssessment`、`securityAndDataFlowAssessment`、`maintenanceAndExitAssessment`；
5. `pocRequired=true` 与上述真实 PoC 证据路径/哈希；
6. ADR 引用；
7. `RETROSPECTIVE_BACKFILL` 标记；
8. C04 SCIM Preview、C06 生产安全、C07 生产 HA/容量的明确非采用或延后边界。

推荐的单项 Receipt 决定：

- `C04 / R09.KEYCLOAK`：`ADOPT`，并在限制中明确 `SCIM_PRODUCTION=DEFER`；
- `C06 / R11.OPENFGA`：`ADOPT`，并明确 `PRODUCTION_RUNTIME=DEFER`；
- `C07 / R12.POSTGRESQL_RLS`：`ADOPT`；
- `C07 / R12.PGVECTOR`：`ADOPT`，并明确 `APPROXIMATE_INDEXING=DEFER`。

这些 Receipt 完成前，Policy 中 C04/C06/C07 的 Profile Approval 回填条件仍未闭合。完成 Receipt 也不会自动产生 P2 Profile Approval 或 O02/O03 启动授权。
