# O02 官方参考研究 v1

## 1. 状态与边界

- 状态：`RESEARCH_INPUT_ONLY`
- 查询日期：`2026-07-30`
- 仓库核验提交：`0cd6813f3fec4a07e61cd19d679e6e00713358a3`
- 仓库核验 Tree：`f324263ff688836c132c38a7cb82933bec19f245`
- 适用工作包：`O02`
- 适用工具锁：`O02_SECRETS_SYSTEM`、`O02_WORKLOAD_IDENTITY`
- 研究对象：
  - `R26.OPENBAO`
  - `R26.SPIRE`
  - `R26.EXTERNAL_SECRETS_OPERATOR`

本文件只提供官方资料研究输入。它不是 Reference Review Receipt、Reference Review Bundle、PoC 结果、ADR、D1 事件、Profile Approval、工作包启动授权或生产采用决定。

下文出现的 `DEFER` 是建议的后续 Receipt 决定，不具有治理效力。只有关闭字段 Receipt 通过语义验证、Git 冻结并由现有 D1 治理路径准确引用后，才可能满足相应审查门。

本研究不改变：

1. `work-package-manifest.v1.json` 对 37 个工作包及依赖的定义；
2. 线上 D1 只追加治理账本的状态权威地位；
3. 当前 Profile Candidate 的工具锁状态；
4. O02 的实现、验证、启动授权或运行状态；
5. O03 对 O02 的既有 Manifest 依赖。

## 2. 固定治理输入

| 输入 | 绑定 |
|---|---|
| Reference Candidate Catalog | `implementation/governance/reference-review/reference-candidate-catalog.v1.json` |
| Catalog 文件 SHA-256 | `sha256:2c2163e1ba42b67e6887451092bcec6d6eacdd9efd9b523cf64ed47e006f0654` |
| Reference Review Policy | `implementation/governance/reference-review/reference-review-policy.v1.json` |
| Policy 文件 SHA-256 | `sha256:94db1b533ec3d81b755d52633f3890bd53452ef5730c7ce1f1a102198c3a29b9` |
| 当前 P2 Profile Candidate | `implementation/p2/acceptance/p2-acceptance-profile.v2.candidate.json` |
| Profile Candidate 文件 SHA-256 | `sha256:90a9741d6ae39012458f073523da0c7b4dc8e4eef53ea759b32d6640e6aaef32` |
| `O02_SECRETS_SYSTEM` | `UNSELECTED_BLOCKS_EVIDENCE` |
| `O02_WORKLOAD_IDENTITY` | `UNSELECTED_BLOCKS_EVIDENCE` |

Policy 将三项参考全部列为 O02 的 `PROSPECTIVE` 审查输入，并要求在 `START_AUTHORIZATION` 前闭合两个工具锁。Catalog 当前仍将三项标记为：

- `versionStatus = UNPINNED_REQUIRES_RECEIPT`
- `candidateOnly = true`
- `productionAdoptionClaim = false`
- `pocRequirement = REQUIRED_FOR_ADOPT`

本研究没有改写这些字段，也没有把下文核验到的发布版本自动写成 O02 的工具锁。

## 3. 结论摘要

| Reference | 映射工具锁 | 当前建议 | 允许继续评估的角色 | 当前不能声称 |
|---|---|---|---|---|
| `R26.OPENBAO` | `O02_SECRETS_SYSTEM` | `DEFER` | 首选秘密系统合成 PoC 候选；PoC 通过后再决定是否 `ADOPT` | 已生产采用、已完成多租户隔离、已完成 HA/备份/升级/退出 |
| `R26.SPIRE` | `O02_WORKLOAD_IDENTITY` | `DEFER` | 跨集群、VM、裸机或统一 SPIFFE 身份出现时的条件 PoC 候选 | 当前 Kubernetes 范围必须引入 SPIRE、SPIRE 是秘密存储 |
| `R26.EXTERNAL_SECRETS_OPERATOR` | `O02_SECRETS_SYSTEM` | `DEFER` | 仅在确需把外部秘密同步成 Kubernetes Secret 时作为可选交付层 PoC | ESO 是秘密源、ESO 可单独满足 `O02_SECRETS_SYSTEM`、OpenBao 当前组合已受官方生产支持 |

角色级纠偏：

- OpenBao 与 O02 集中式秘密管理目标最匹配，但高敏感性运维和恢复要求使“官方文档匹配”不能替代 PoC。
- SPIRE 解决工作负载身份与 SVID 生命周期，不保存业务秘密，不能替代 OpenBao。
- ESO 从外部 Provider 读取秘密并写入 Kubernetes Secret。它增加了秘密物化副本，不能作为主要秘密系统；因此对“主要秘密存储”这一角色应视为 `REJECT_AS_PRIMARY_SECRET_STORE`，但对“可选同步层”仍是 `DEFER`。

当前两个工具锁继续保持 `UNSELECTED_BLOCKS_EVIDENCE`。本研究没有产生 `ADOPT` Receipt、部署制品锁、PoC PASS、运维责任人或启动授权。

## 4. R26.OPENBAO

### 4.1 精确版本与供应链事实

截至查询日期，官方 GitHub 将 `v2.6.1` 标为最新稳定发布：

| 字段 | 官方核验值 |
|---|---|
| Release | `v2.6.1` |
| 发布时间 | `2026-07-22T14:37:36Z` |
| Tag / release commit | `ba7ad8861d0578cd4da4f7b9e5a6756d30484f8f` |
| Linux amd64 tar.gz | `sha256:ca8d836eb3a5c80407e45e762300b64e7138c419e78826955f2e4ba4ce6d8a6b` |
| Linux arm64 tar.gz | `sha256:a74aa73b80000a4340a90edbf27726c0fb0a4537970eab6e1a7e0e211d117b75` |
| Source distribution | `sha256:fa257aa265ca05d0fb1a65f88645f65e39bde71012a6c7886bac52e4fc3af9b1` |
| `checksums.txt` 文件 | `sha256:e6985523c63e527dc4f25f0121d53fc08c7e79bed955bb28d747d6724bc3535b` |
| Linux amd64 SBOM 文件 | `sha256:daa03e49e37b826d1d1abf2c290d0bfe871d9c9e0997b4ee89b5768580b49af5` |
| 许可证 | `MPL-2.0` |

官方发布提供 checksum、GPG 签名、Sigstore bundle 和 SBOM。上述 Digest 只约束对应下载制品，不约束尚未选择的 OCI 镜像或 Helm Chart。

当前实际部署平台、CPU 架构、OCI 镜像 Digest、Helm Chart 版本与 Chart 内容摘要均为 `UNKNOWN / UNSELECTED`。不能只固定 `v2.6.1` 标签或可变镜像标签就认定工具锁已闭合。

### 4.2 官方来源与阅读范围

| 官方来源 | 固定边界 | 实际阅读内容 |
|---|---|---|
| [OpenBao v2.6.1 release](https://github.com/openbao/openbao/releases/tag/v2.6.1) | `v2.6.1` | 发布提交、变更、安全修复和发布制品 |
| [OpenBao v2.6.1 commit](https://github.com/openbao/openbao/commit/ba7ad8861d0578cd4da4f7b9e5a6756d30484f8f) | commit `ba7ad886…` | 发布提交身份与签名 |
| [Installation](https://openbao.org/docs/install/) | 查询于 `2026-07-30` | checksum、GPG、Cosign 和制品验证 |
| [What is OpenBao](https://openbao.org/docs/what-is-openbao/) | 查询于 `2026-07-30` | 集中式秘密、动态秘密、加密、租约和撤销 |
| [Security model](https://openbao.org/docs/internals/security/) | 查询于 `2026-07-30` | TLS、默认拒绝、Security Barrier、集群 mTLS、存储威胁边界 |
| [Architecture](https://openbao.org/docs/internals/architecture/) | 查询于 `2026-07-30` | Core、Audit、Auth、Secrets Engine 和存储路径 |
| [Leases](https://openbao.org/docs/concepts/lease/) | 查询于 `2026-07-30` | TTL、续期、撤销以及静态 KV 的边界 |
| [Audit devices](https://openbao.org/docs/audit/) | 查询于 `2026-07-30` | 审计启用、设备失败和敏感日志边界 |
| [Kubernetes](https://openbao.org/docs/platform/k8s/) | 查询于 `2026-07-30` | Helm、Agent Injector、CSI 与 Kubernetes 交付路径 |
| [Kubernetes auth](https://openbao.org/docs/auth/kubernetes/) | 查询于 `2026-07-30` | ServiceAccount Token、TokenReview、短期 Token 和撤销窗口 |
| [Namespaces](https://openbao.org/docs/concepts/namespaces/) | 查询于 `2026-07-30` | Namespace 隔离、层级管理和跨 Namespace 身份风险 |
| [Sealable Namespaces](https://openbao.org/docs/concepts/namespaces/sealable-namespaces/) | 查询于 `2026-07-30` | 独立密封、Shamir 限制和恢复责任 |
| [Storage backends](https://openbao.org/docs/configuration/storage/) | 查询于 `2026-07-30` | Integrated Storage、外部存储和 HA 能力 |
| [High availability](https://openbao.org/docs/internals/high-availability/) | 查询于 `2026-07-30` | Active/Standby、故障转移与非多写语义 |
| [Upgrading](https://openbao.org/docs/upgrading/) | 查询于 `2026-07-30` | 备份、数据结构变化和回退限制 |
| [HA upgrade](https://openbao.org/docs/upgrading/ha-upgrade/) | 查询于 `2026-07-30` | HA 升级顺序和停机边界 |
| [Storage and backup concepts](https://openbao.org/docs/concepts/storage/) | 查询于 `2026-07-30` | 备份、快照和恢复责任 |
| [Support policy](https://openbao.org/docs/policies/support/) | 查询于 `2026-07-30` | 社区 best-effort 支持和版本边界 |
| [Migration guide](https://openbao.org/docs/guides/migration/) | 查询于 `2026-07-30` | 已发布迁移路径及其适用范围 |
| [MPL-2.0 license at v2.6.1](https://github.com/openbao/openbao/blob/ba7ad8861d0578cd4da4f7b9e5a6756d30484f8f/LICENSE) | commit `ba7ad886…` | 使用、修改、分发、Source Code Form、通知和商标边界 |

### 4.3 能力、数据流与安全边界

官方资料证明 OpenBao 能够提供：

- KV 秘密存储；
- 动态数据库或云凭据；
- 租约、续期和撤销；
- PKI、密钥和加密服务；
- 身份认证、路径 ACL 和默认拒绝；
- API、Agent Injector、CSI 等交付路径；
- 审计、高可用和加密持久化。

目标数据流：

```text
工作负载
  → TLS + 短期工作负载身份
OpenBao API
  → Token + 路径 ACL
Secrets Engine
  → Security Barrier 加密
Raft 或经批准的外部持久存储
```

安全边界：

1. 客户端必须验证服务端 TLS；集群节点间使用双向 TLS。
2. 离开 OpenBao Core 的持久数据由 Security Barrier 加密，但底层存储权限、宿主机、解封材料和运行时内存仍是安全边界。
3. 策略默认拒绝；不能让管理员 Token、Root Token 或长期凭据进入普通工作负载。
4. 动态秘密有租约、续期和撤销；KV 静态秘密不应被描述成自动轮换或自动撤销。
5. 审计初始并非自动启用。多个审计设备、全部审计写入失败时的请求行为、日志敏感性和日志留存必须 PoC。
6. Agent、CSI 或文件交付可能在 Pod、节点文件系统、日志、崩溃转储或备份中形成副本，必须单独验证。
7. Namespaces 可提供隔离构件，但不能只凭 Namespace 名称宣称多企业隔离已成立；跨 Namespace 身份、管理员委托、密封、恢复和密钥轮换必须攻击验证。

### 4.4 许可证、再分发和品牌边界

OpenBao `v2.6.1` 主仓库采用 `MPL-2.0`：

- 可使用、复制、修改和分发；
- 被修改的 MPL 源文件继续按 MPL 提供；
- 分发可执行形式时需要提供相应 Source Code Form 的取得方式；
- Larger Work 中的独立文件可采用其他条款；
- 必须保留适用许可证、版权和通知；
- MPL 不授予 OpenBao 名称、服务标志或 Logo 的商标权；
- 第三方依赖仍需独立 SBOM 和许可证审查。

工程建议是把 OpenBao 作为独立服务并通过内部 Port 调用，避免把其源码无边界地嵌入产品。若随产品分发二进制、镜像或修改版，必须由法务复核 Source Code Form、通知、第三方依赖和商标要求。

### 4.5 运维、升级与退出

- 多数场景官方推荐 Integrated Storage；HA 是单 Active、多 Hot Standby，不是多写 Active-Active。
- 升级可能改变数据结构，单纯替换旧二进制不能证明可降级；回退需要同时考虑数据存储回退。
- 升级前必须备份，并在隔离环境演练恢复、升级和回退。
- 备份不能替代 HA；快照调度、离线副本、恢复密钥和 RTO/RPO 属于平台运维责任。
- 社区支持是 best effort，不能据此声明企业响应 SLA。
- 官方存在特定来源到 OpenBao 的迁移指南；未找到可证明“从 OpenBao 无损迁移到任意秘密系统”的通用官方方案。通用退出能力当前为 `UNKNOWN`，必须通过导出、重导入、客户端切换和旧凭据撤销 PoC 证明。

停止维护或退出触发条件至少包括：

- 安全修复无法在约定窗口内完成；
- 备份恢复或解封演练失败；
- 运行团队无法满足值班和密钥持有人分离；
- 许可证或再分发边界无法接受；
- 目标平台无法完成租户隔离；
- 替代系统迁移 PoC 失败且风险不可接受。

### 4.6 必须完成的 PoC

在任何 `ADOPT` Receipt 或 `O02_SECRETS_SYSTEM` 工具锁前，至少需要：

1. 固定实际部署的镜像/二进制、Chart、SBOM 和签名 Digest，并验证 checksum、Sigstore/GPG 与来源。
2. 证明租户间读取、写入、管理和身份引用全部拒绝。
3. 证明 Kubernetes 短期 ServiceAccount 身份、最小策略、短期 Token、续期、撤销和失效传播。
4. 分别验证 KV 静态秘密和动态数据库凭据，禁止把 KV 描述成自动轮换。
5. 验证 Agent/CSI/API 交付后 Pod、节点、日志和崩溃转储不存在非预期持久副本。
6. 配置至少两个审计目标，验证一个失败、全部失败及阻塞审计设备。
7. 验证 Active 节点故障、Standby 接管、密封/解封和 KMS/HSM 故障。
8. 完成备份、隔离恢复、升级和“二进制 + 数据”共同回退。
9. 演练导出到替代秘密系统、客户端切换和旧凭据撤销。
10. 冻结运行负责人、值班、密钥持有人、RTO/RPO、停止维护和退出条件。
11. 完成许可证、SBOM、漏洞、商标和产品再分发复核。

### 4.7 建议决定

```json
{
  "referenceId": "R26.OPENBAO",
  "candidateVersion": "v2.6.1",
  "candidateCommit": "ba7ad8861d0578cd4da4f7b9e5a6756d30484f8f",
  "decision": "DEFER",
  "preferredRole": "O02_SECRETS_SYSTEM_SYNTHETIC_POC_CANDIDATE",
  "productionAdoptionClaim": false,
  "reReviewTrigger": [
    "O02_SYNTHETIC_POC_AUTHORIZED",
    "EXACT_DEPLOYMENT_TARGET_DEFINED"
  ],
  "blockedBy": [
    "EXACT_DEPLOYMENT_ARTIFACT_DIGEST_UNSELECTED",
    "TENANT_ISOLATION_POC_NOT_RUN",
    "WORKLOAD_IDENTITY_INTEGRATION_POC_NOT_RUN",
    "SEAL_AND_RECOVERY_POC_NOT_RUN",
    "AUDIT_FAILURE_POC_NOT_RUN",
    "BACKUP_RESTORE_AND_UPGRADE_ROLLBACK_NOT_RUN",
    "EXIT_MIGRATION_NOT_PROVED",
    "OPERATIONS_OWNER_NOT_ASSIGNED"
  ]
}
```

## 5. R26.SPIRE

### 5.1 精确版本与供应链事实

截至查询日期，官方 GitHub 将 `v1.15.2` 标为最新稳定发布：

| 字段 | 官方核验值 |
|---|---|
| Release | `v1.15.2` |
| 发布时间 | `2026-07-09T20:07:55Z` |
| Annotated tag object | `a7e490ee2864e2e05ebbadcef79872604270f3c4` |
| Peeled release commit | `e78e2eeca03a8a420bfe1b23b6eaf3db0db78630` |
| Linux amd64 musl tar.gz | `sha256:3874d07ffeb6640bafb9fe6a538de06151f155d5ed2f8e8a51f138d2f51b8105` |
| Linux arm64 musl tar.gz | `sha256:92e782b285c50c62cdf37fdfa8917ea68fa57685b3bf99d03db36da4095678fa` |
| 许可证 | `Apache-2.0` |

SPIRE 的 tag 是 annotated tag；工具锁必须绑定 peeled release commit，而不能把 tag object ID 当成运行源码提交。

当前部署目标、平台制品、镜像 Digest、Helm Chart 或 operator 版本均未选择。表中 tar.gz Digest 仅用于证明官方发布存在精确可核验制品，不是当前工具锁。

### 5.2 官方来源与阅读范围

| 官方来源 | 固定边界 | 实际阅读内容 |
|---|---|---|
| [SPIRE v1.15.2 release](https://github.com/spiffe/spire/releases/tag/v1.15.2) | `v1.15.2` | immutable release、发布提交、变更和安全条目 |
| [SPIRE concepts](https://spiffe.io/docs/latest/spire-about/spire-concepts/) | `v1.15.2 Latest`，查询于 `2026-07-30` | Server、Agent、Node/Workload Attestation、SVID、Registration Entry |
| [Configuring SPIRE](https://spiffe.io/docs/latest/deploying/configuring/) | `v1.15.2 Latest` | trust domain、attestation、datastore 和 Key Manager |
| [Scaling SPIRE](https://spiffe.io/docs/latest/planning/scaling_spire/) | `v1.15.2 Latest` | HA、共享 datastore、嵌套和联邦拓扑 |
| [Upgrading SPIRE](https://spiffe.io/docs/latest/maintenance/upgrading/) | `v1.15.2 Latest` | Server/Agent 升级顺序、版本偏差、回滚和实验特性 |
| [SPIRE Agent](https://spiffe.io/docs/latest/deploying/spire_agent/) | `v1.15.2 Latest` | Agent、Workload API、bootstrap trust 和 delegated identity |
| [SPIRE v1.15.2 SECURITY.md](https://github.com/spiffe/spire/blob/v1.15.2/SECURITY.md) | tag `v1.15.2` | 漏洞报告和受支持版本范围 |
| [SPIRE v1.15.2 LICENSE](https://github.com/spiffe/spire/blob/v1.15.2/LICENSE) | tag `v1.15.2` | Apache-2.0 再分发、专利、通知和商标边界 |

### 5.3 能力、数据流与安全边界

SPIRE 是 SPIFFE 的生产级实现，负责：

- 节点身份验证；
- 工作负载身份验证；
- X.509-SVID / JWT-SVID 签发与轮换；
- trust domain、Registration Entry 和 selector；
- 本地 Workload API；
- 跨集群或跨环境联邦。

目标数据流：

```text
SPIRE Server
  → 注册、签名和 trust domain
SPIRE Agent
  → 节点身份验证
本地 Workload API
  → 工作负载身份验证
工作负载
  → 短期 X.509-SVID / JWT-SVID
OpenBao 或其他受信服务
```

安全边界：

1. SPIRE 不保存业务秘密，也不替代 `O02_SECRETS_SYSTEM`。
2. Server 管理签名和注册；Agent 位于每个节点并暴露本地 Workload API。Agent、socket、selector 和 delegated identity 权限错误会直接影响身份边界。
3. 生产 HA 需要多个 Server 共享 datastore；单 Server 是单点故障。
4. 默认 SQLite 适合测试，不应被默认推断为生产 datastore；生产需评审 PostgreSQL/MySQL、HA 和备份。
5. trust domain、node attestor、workload attestor、Key Manager、Registration Entry 和 federation 都必须被准确配置并冻结。
6. release 中标记为 experimental 的能力不能因版本号稳定而被当成稳定生产承诺。
7. SVID 生命周期不是“即时撤销魔法”；TTL、轮换、失效传播和依赖方缓存必须 PoC。

### 5.4 许可证、再分发和品牌边界

SPIRE `v1.15.2` 采用 `Apache-2.0`：

- 可使用、修改和再分发；
- 必须保留许可证、适用版权、NOTICE 和修改声明；
- 包含专利许可与终止条款；
- 不授予 SPIFFE/SPIRE 名称、商标或 Logo 的产品品牌权；
- 无担保；
- 随产品分发时仍需对第三方依赖执行 SBOM 和许可证扫描。

托管 SPIRE 服务与随产品分发二进制的合规义务不同。若打包镜像、Chart 或修改版，需要冻结实际分发制品并由法务复核 NOTICE、第三方依赖和商标陈述。

### 5.5 运维、升级与退出

- HA 需要多个 Server、共享 datastore、可靠 Key Manager 和明确 trust domain 拓扑。
- 官方升级顺序是先 Server、再 Agent；通常一次最多跨一个 minor 版本，并可滚动执行。
- 回滚顺序与升级相反，必须保留兼容的 datastore、Server/Agent 制品和配置。
- 官方安全政策支持当前和前一个 minor 系列；这不是企业 SLA。
- nested SPIRE 和 federation 增加故障域、信任传播和运维复杂度，只有真实需求触发时才应引入。

退出策略：

1. 应通过内部 workload identity Port 消费身份，而不是把所有业务代码绑定到 Workload API 细节。
2. 保留 trust domain、SPIFFE ID 命名、Registration Entry 和 selector 的可导出清单。
3. 退出时必须迁移信任根、客户端校验、身份映射和轮换流程，并撤销旧 SVID 信任。
4. 未找到可证明“从 SPIRE 自动无损迁移到任意工作负载身份系统”的通用官方方案；通用退出自动化为 `UNKNOWN`。

### 5.6 必须完成的 PoC

仅当跨集群、VM、裸机、统一 SPIFFE 身份或联邦需求真实出现时，至少验证：

1. 固定 Server、Agent、镜像/二进制、Chart/operator 和所有制品 Digest。
2. 定义 trust domain 与 SPIFFE ID 命名，并验证租户、环境和工作负载隔离。
3. 验证 node attestation、workload attestation 和 selector 欺骗攻击。
4. 验证 X.509-SVID / JWT-SVID 签发、轮换、过期、撤销窗口和依赖方缓存。
5. 验证本地 Workload API socket 权限和 delegated identity 最小授权。
6. 验证 Server HA、共享 datastore、Key Manager 故障、备份和恢复。
7. 验证 Kubernetes、VM 和裸机间的身份一致性及跨集群联邦边界。
8. 验证升级、版本偏差、Agent/Server 回滚和旧信任撤销。
9. 验证 OpenBao 或其他服务只接受预期 trust domain 和 SPIFFE ID。
10. 指定 PKI、datastore、Agent 和 incident response 运维责任人。

### 5.7 建议决定

```json
{
  "referenceId": "R26.SPIRE",
  "candidateVersion": "v1.15.2",
  "candidateCommit": "e78e2eeca03a8a420bfe1b23b6eaf3db0db78630",
  "decision": "DEFER",
  "preferredRole": "CONDITIONAL_O02_WORKLOAD_IDENTITY_POC_CANDIDATE",
  "productionAdoptionClaim": false,
  "reReviewTrigger": [
    "CROSS_CLUSTER_IDENTITY_REQUIRED",
    "VM_OR_BARE_METAL_WORKLOADS_REQUIRED",
    "UNIFORM_SPIFFE_IDENTITY_REQUIRED",
    "TRUST_DOMAIN_FEDERATION_REQUIRED"
  ],
  "blockedBy": [
    "CURRENT_SCOPE_TRIGGER_NOT_PROVED",
    "EXACT_DEPLOYMENT_ARTIFACT_DIGEST_UNSELECTED",
    "ATTESTATION_AND_SVID_LIFECYCLE_POC_NOT_RUN",
    "HA_DATASTORE_AND_KEY_MANAGER_POC_NOT_RUN",
    "OPERATIONS_OWNER_NOT_ASSIGNED"
  ]
}
```

当前较小范围的替代路径是 [Kubernetes ServiceAccount](https://kubernetes.io/docs/concepts/security/service-accounts/) 和 [projected ServiceAccount Token](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/) 配合受信服务端的 audience、issuer、TTL 和 TokenReview 校验。该路径仍需自己的官方 Reference Review 和 PoC；本研究没有把它自动写成 `O02_WORKLOAD_IDENTITY` 工具锁。

## 6. R26.EXTERNAL_SECRETS_OPERATOR

### 6.1 精确版本与供应链事实

官方 GitHub 的 `releases/latest` 可能指向 Helm Chart release，因此本研究显式区分应用 release 和 Chart release：

| 字段 | 官方核验值 |
|---|---|
| Application release | `v2.8.0` |
| 发布时间 | `2026-07-18T05:36:33Z` |
| Application tag commit | `2e0f135f739eff1543b0a86cbedf9331756432d5` |
| Helm Chart release | `helm-chart-2.8.0` |
| Helm Chart commit | `6f1eed573faac17c3272c576cfd419a5b40db25d` |
| 官方 GHCR multi-arch manifest | `sha256:24c0dd3699e0988520afd2218612758cd97d1f702757b5b4fcf89adaa33ef679` |
| `external-secrets.yaml` | `sha256:7d1533a7ace1f0ee9a21ac2215665e8f5856690ca7b224961df2011ff735d572` |
| Release provenance | `sha256:757bb4f44ef2fdb23f21955f48d895c853e12fb12ff231d4edc86ebd82c5af92` |
| Release SBOM | `sha256:78dd848d5b5f4fdb37cdae7857d09ceaced62f67b310768d6ef0705ba68852ba` |
| 许可证 | `Apache-2.0` |

这些是官方发布制品事实，不是当前 O02 部署锁。实际平台、Chart values、CRD 版本、目标镜像平台和 OpenBao 组合均未选择。

### 6.2 官方来源与阅读范围

| 官方来源 | 固定边界 | 实际阅读内容 |
|---|---|---|
| [ESO v2.8.0 release](https://github.com/external-secrets/external-secrets/releases/tag/v2.8.0) | `v2.8.0` | application release、提交、镜像和供应链制品 |
| [ExternalSecret API](https://external-secrets.io/v2.8.0/api/externalsecret/) | `v2.8.0` | refresh policy、target ownership、deletion 和同步语义 |
| [SecretStore API](https://external-secrets.io/v2.8.0/api/secretstore/) | `v2.8.0` | SecretStore、ClusterSecretStore 与 Provider |
| [Multi-tenancy](https://external-secrets.io/v2.8.0/guides/multi-tenancy/) | `v2.8.0` | namespace、共享 ClusterSecretStore 和密钥暴露风险 |
| [Security best practices](https://external-secrets.io/v2.8.0/guides/security-best-practices/) | `v2.8.0` | RBAC、NetworkPolicy、Provider 限制、签名、SBOM 和 Helm hardening |
| [Stability and support](https://external-secrets.io/v2.8.0/introduction/stability-support/) | `v2.8.0` | 当前 minor 支持、升级、Provider 状态和 Helm 边界 |
| [Deprecation policy](https://external-secrets.io/v2.8.0/introduction/deprecation-policy/) | `v2.8.0` | Beta 状态、breaking change、迁移和停机边界 |
| [OpenBao provider](https://external-secrets.io/v2.8.0/provider/openbao/) | `v2.8.0` | OpenBao 兼容路径、测试版本组合和 Provider 状态 |
| [ESO v2.8.0 SECURITY.md](https://github.com/external-secrets/external-secrets/blob/v2.8.0/SECURITY.md) | tag `v2.8.0` | 漏洞报告边界 |
| [ESO v2.8.0 LICENSE](https://github.com/external-secrets/external-secrets/blob/v2.8.0/LICENSE) | tag `v2.8.0` | Apache-2.0 再分发、通知和商标边界 |

### 6.3 能力、数据流与安全边界

ESO 的核心数据流是：

```text
OpenBao 或其他外部 Provider
  → ESO Controller 读取
ExternalSecret / SecretStore
  → Kubernetes Secret 写入
Kubernetes etcd
  → Pod 以 volume/env 等方式读取
```

因此：

1. ESO 不是秘密源；它依赖 OpenBao 或其他外部 Provider。
2. ESO 将秘密物化为 Kubernetes Secret，扩大了 RBAC、etcd、备份、节点、Pod 环境变量和日志的暴露面。
3. `SecretStore` 是 namespaced；`ClusterSecretStore` 可跨 namespace。共享 ClusterSecretStore 可能让应用开发者接触超出命名空间范围的秘密，必须用 Provider 端权限和 admission policy 阻断。
4. 应默认最小化或关闭 cluster-wide 资源，使用 namespace 级 SecretStore、最小 RBAC 和 deny-by-default NetworkPolicy。
5. `CreatedOnce`、`Periodic`、`OnChange`、target ownership 和 deletion policy 会影响轮换、覆盖、删除和恢复，必须按业务语义测试。
6. Kubernetes Secret 是否静态加密、备份如何保护、谁可读取 etcd，不属于 ESO 单独能证明的边界。
7. 官方 Provider 表将 OpenBao Provider 标为 `alpha`；官方 OpenBao 页面只声明测试过 ESO `v0.16.1` 与 OpenBao `v2.2.0`。它不能证明 ESO `v2.8.0` 与 OpenBao `v2.6.1` 已通过官方兼容验证。
8. 官方稳定性资料说明项目处于 Beta，并只支持最新 minor；不能把当前绿色 PoC 推断为长期兼容承诺。

### 6.4 许可证、再分发和品牌边界

ESO `v2.8.0` 采用 `Apache-2.0`：

- 可使用、修改和再分发；
- 需要保留许可证、适用版权/NOTICE 和修改声明；
- 包含专利许可；
- 不授予 External Secrets Operator 名称、商标或 Logo 的白标权；
- 无担保；
- Chart、镜像、CRD 和第三方依赖需独立固定版本、Digest、SBOM 和许可证结果。

产品打包时不能只审查 Controller 仓库许可证，还要审查 Chart 模板、镜像层、CRD、Provider SDK 及所有随产品分发的第三方制品。

### 6.5 运维、升级与退出

- 官方支持仅覆盖最新 minor；新 minor 发布后旧 minor 结束支持。
- 升级应一次跨一个 minor，并先在非生产环境验证 CRD、Controller、Provider 和同步语义。
- 项目 Beta 状态允许带迁移说明的不兼容变更，并可能要求停机。
- 官方 Helm Chart 按 “as-is” 提供，不等于生产 hardened Chart。
- Provider 不可用、权限变化、Secret 删除或模板错误时，ESO 的重试、Condition 和 Kubernetes Secret 残留必须纳入告警和事故响应。

退出策略：

1. 停止创建新的 ExternalSecret。
2. 导出并对账所有 SecretStore、ClusterSecretStore、ExternalSecret、ClusterExternalSecret 和目标 Secret。
3. 将工作负载切换到 OpenBao Agent/CSI/API 或另一经批准交付方式。
4. 删除 Controller/CRD 前确认最终目标 Secret 的所有权和删除策略。
5. 清理残留 Kubernetes Secret，并在外部 Provider 撤销或轮换旧秘密。
6. 未找到能自动保证上述迁移无损的通用官方退出工具；完整退出自动化为 `UNKNOWN`。

### 6.6 必须完成的 PoC

仅在确需同步到 Kubernetes Secret 时，至少验证：

1. 固定 v2.8.0 Controller、Chart、CRD、镜像平台 Digest、provenance 和 SBOM。
2. 显式验证 ESO v2.8.0 与所选 OpenBao 版本和认证方式的兼容性。
3. 证明 namespace 级 SecretStore、Provider 端最小权限和租户隔离。
4. 默认拒绝 ClusterSecretStore 或使用 admission policy 限制 namespace 和 key。
5. 使用 deny-by-default NetworkPolicy，仅允许目标 Provider、Kubernetes API 和必要遥测。
6. 验证 `CreatedOnce`、`Periodic`、`OnChange`、刷新、覆盖、删除、重建和所有权语义。
7. 验证 Provider 中断、Token 过期、权限撤销、网络分区和恢复后的同步行为。
8. 验证 Kubernetes Secret 在 etcd、备份、Pod、节点、环境变量和日志中的暴露边界。
9. 验证泄漏后的 Provider 端撤销、目标 Secret 替换和工作负载重载。
10. 演练 Controller/CRD 升级、回退、Provider 变更和完整退出清理。
11. 指定 Controller、Provider、Kubernetes Secret 和事故响应的运维责任人。

### 6.7 建议决定

```json
{
  "referenceId": "R26.EXTERNAL_SECRETS_OPERATOR",
  "candidateVersion": "v2.8.0",
  "candidateCommit": "2e0f135f739eff1543b0a86cbedf9331756432d5",
  "decision": "DEFER",
  "preferredRole": "OPTIONAL_KUBERNETES_SECRET_SYNC_LAYER",
  "rejectedRole": "PRIMARY_O02_SECRETS_SYSTEM",
  "productionAdoptionClaim": false,
  "reReviewTrigger": [
    "KUBERNETES_SECRET_MATERIALIZATION_REQUIRED",
    "DIRECT_OPENBAO_API_AGENT_OR_CSI_UNSUITABLE"
  ],
  "blockedBy": [
    "ROLE_AS_PRIMARY_SECRET_STORE_REJECTED",
    "OPENBAO_PROVIDER_ALPHA",
    "CURRENT_OPENBAO_COMBINATION_NOT_OFFICIALLY_TESTED",
    "EXACT_DEPLOYMENT_ARTIFACT_DIGEST_UNSELECTED",
    "TENANT_ISOLATION_AND_EXFILTRATION_POC_NOT_RUN",
    "ROTATION_DELETION_AND_RECOVERY_POC_NOT_RUN",
    "OPERATIONS_OWNER_NOT_ASSIGNED"
  ]
}
```

## 7. 替代路径比较

| 需求 | 候选路径 | 优点 | 代价 / 风险 | 当前研究状态 |
|---|---|---|---|---|
| 集中秘密源 | OpenBao | 动态秘密、租约、撤销、策略、审计、加密存储 | 高敏感运维、解封/恢复、HA、升级和退出复杂 | 首选 PoC 候选，Receipt 建议 `DEFER` |
| Kubernetes 秘密交付 | OpenBao Agent Injector | 不必由独立同步 Controller 持续写 Kubernetes Secret | sidecar/init 与文件生命周期、节点副本和注入策略需验证 | `NOT_EVALUATED_IN_FULL` |
| Kubernetes 秘密交付 | OpenBao CSI | 可按挂载路径交付，避免某些环境变量复制 | CSI、节点插件、挂载刷新和故障恢复复杂 | `NOT_EVALUATED_IN_FULL` |
| Kubernetes 秘密交付 | ESO | 声明式同步，支持多 Provider | 秘密写入 Kubernetes Secret；RBAC/etcd/多租户暴露面扩大 | 可选同步层，Receipt 建议 `DEFER` |
| Kubernetes 秘密交付 | 直接 OpenBao API | 副本和生命周期最可控 | 每个客户端需正确实现认证、缓存、续期和失败处理 | `NOT_EVALUATED_IN_FULL` |
| Kubernetes 工作负载身份 | projected ServiceAccount Token | 平台内置、范围小、可设 audience 与 TTL | 跨集群/VM/裸机一致性有限，依赖正确 TokenReview 与 issuer 校验 | 独立官方审查尚未完成 |
| 异构工作负载身份 | SPIRE | 统一 SVID、节点/工作负载 attestation、联邦 | Server/Agent/CA/datastore/Key Manager 运维复杂 | 条件 PoC 候选，Receipt 建议 `DEFER` |

本研究没有评估或拒绝具名云厂商 Secret Manager、Vault 或其他商业产品。未评估对象保持 `NOT_EVALUATED`，不能写成已经拒绝。

## 8. 工具锁闭合前的最小证据

### 8.1 `O02_SECRETS_SYSTEM`

至少需要：

1. 三项 applicable Reference 的关闭字段 Receipt，不能遗漏 ESO 或把其错误写成已采用。
2. OpenBao 的准确部署版本、commit、镜像/二进制 Digest、Chart Digest、SBOM 和签名验证。
3. OpenBao PoC 的租户隔离、短期身份、策略、动态秘密、审计故障、HA、备份恢复、升级回退和退出结果。
4. ESO 若 `DEFER`，必须有重新审查触发条件；若作为同步层 `ADOPT`，必须完成其独立 PoC。
5. ADR 说明为何选择 OpenBao，为什么 ESO 不是秘密源，以及交付路径如何选择。
6. 运行、密钥持有、备份恢复、升级和事故响应责任。

### 8.2 `O02_WORKLOAD_IDENTITY`

至少需要：

1. SPIRE Receipt 及明确的 `DEFER` 触发条件，或完整 PoC 后的 `ADOPT` 决定。
2. 若当前选择 Kubernetes projected ServiceAccount Token，则必须把该替代路径加入适用候选集合并完成官方 Reference Review；不能用本研究代替。
3. 固定 issuer、audience、TTL、TokenReview、身份映射、撤销窗口和跨租户拒绝测试。
4. 若采用 SPIRE，冻结 Server/Agent/Chart/operator/镜像 Digest、trust domain、attestor、Key Manager 和 datastore。
5. ADR 与运维责任。

### 8.3 当前治理结果

```json
{
  "O02_SECRETS_SYSTEM": "UNSELECTED_BLOCKS_EVIDENCE",
  "O02_WORKLOAD_IDENTITY": "UNSELECTED_BLOCKS_EVIDENCE",
  "referenceReviewReceiptsFrozen": false,
  "pocResultsFrozen": false,
  "d1ProfileApprovalEffect": false,
  "d1StartAuthorizationEffect": false,
  "productionAdoptionEffect": false
}
```

## 9. 未知项与停止条件

以下仍为 `UNKNOWN` 或未选择：

- O02 实际部署平台、架构和 Kubernetes 版本；
- OpenBao OCI 镜像与 Helm Chart 的准确 Digest；
- OpenBao seal / auto-unseal、KMS/HSM 和 Namespace 策略；
- 生产 datastore、HA、RTO/RPO 和恢复密钥持有人；
- 当前工作负载身份是否只限单个 Kubernetes 集群；
- projected ServiceAccount Token 的独立 Reference Review；
- 是否真实需要 Kubernetes Secret 物化；
- ESO v2.8.0 与 OpenBao v2.6.1 的兼容结果；
- 企业 SLA、值班和安全事件责任人；
- 通用退出迁移的验证结果；
- 法务对产品再分发和品牌使用的正式意见。

任一以下情况出现时必须停止并重新评审：

1. 候选 release、commit、镜像、Chart 或 SBOM 发生变化；
2. 运行平台、租户隔离模型或交付路径变化；
3. OpenBao、SPIRE 或 ESO 出现影响所选版本的新安全通报；
4. Provider 稳定性、许可证或支持政策变化；
5. PoC 不能证明默认拒绝、恢复、回退或退出；
6. 需要真实企业数据、凭据或生产系统才能继续；
7. 缺少真实独立复核人却要求最终 PASS。

## 10. 研究结论

当前最小、可复核的方向是：

1. 保持 OpenBao 为 `O02_SECRETS_SYSTEM` 的首选合成 PoC 候选，但正式 Receipt 暂建议 `DEFER`；
2. 先独立审查 Kubernetes projected ServiceAccount Token，若 O02 仍限 Kubernetes，则不因“更先进”而自动引入 SPIRE；
3. 只有出现跨集群、VM、裸机或统一 SPIFFE 身份需求时，才启动 SPIRE PoC；
4. ESO 只在确需 Kubernetes Secret 物化时评估，且不得作为主要秘密源；
5. 三份 Receipt、PoC、ADR、精确制品 Digest、运维责任和冻结 Bundle 闭合前，两个 O02 工具锁均保持未选择；
6. 本研究不批准 Profile，不授权 O02，不启动 O02，也不改变任何线上 D1 状态。
