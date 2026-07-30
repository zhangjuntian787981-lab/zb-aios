# ADR 0009: P1 身份、授权与数据隔离参考回填准备

- 状态：Candidate
- 日期：2026-07-30
- 范围：C04、C06、C07 的 `RETROSPECTIVE_BACKFILL`
- 数据边界：P1_SYNTHETIC_ONLY

## 决定

基于
`implementation/governance/reference-review/p2-profile-backfill-official-research.v1.md`
固定的官方资料和仓库证据，后续正式 Reference Review Receipt 应按以下
精确范围准备：

- C04 / Keycloak 26.7.0：拟 `ADOPT` P1 合成 OIDC、TOTP 和 SAML
  Broker 实现；SCIM 只作为 Preview 兼容性与负面能力验证。
- C06 / OpenFGA v1.18.1：拟 `ADOPT` P1 合成关系授权、不可变
  Authorization Model ID、Tuple Bundle 和固定 Check。
- C07 / PostgreSQL 17.10：拟 `ADOPT` P1 合成数据库强制租户隔离，
  包括 RLS、`FORCE ROW LEVEL SECURITY`、`USING`、`WITH CHECK` 和
  `NOBYPASSRLS` 运行角色。
- C07 / pgvector 0.8.5：拟 `ADOPT` P1 合成 `vector` 类型、租户向量表和
  RLS 隔离；当前没有采用 HNSW 或 IVFFlat 近似索引。

这些决定只记录已经存在并有冻结证据的 P1 实现边界。正式 Receipt 仍必须
绑定最终 Profile Core、Execution Baseline Core、候选集合、Policy、
适用性扫描、实现一致性证据和后继 Git 冻结证明。

## 明确推迟的生产范围

- Keycloak：生产 SCIM、外部 PostgreSQL、HA、正式 TLS/信任链、备份恢复、
  密钥托管、容量和真实企业 IdP 接入继续 `DEFER`。
- OpenFGA：生产 datastore、认证、TLS、HA、备份恢复、容量与控制面隔离
  继续 `DEFER`；experimental 内置访问控制不得充当生产安全边界。
- PostgreSQL：生产 HA、独立主机灾备、网络分区、备份保留、滚动升级、
  容量和监控继续 `DEFER`。
- pgvector：HNSW/IVFFlat 近似索引、生产召回率、延迟、容量和降级策略继续
  `DEFER`。

当前 Adapter、Port、稳定 Principal、固定 Authorization Model、标准 SQL
迁移和租户数据边界必须保持可替换。退出候选实现时，必须用同一组合成协议、
授权和隔离矩阵验证替代实现，不能把退出降级为删除依赖。

## 许可证与再分发边界

- Keycloak 和 OpenFGA：Apache License 2.0；再分发时保留许可证、适用
  Notice/版权声明和修改说明，不获得商标背书。
- PostgreSQL：PostgreSQL License；保留版权和许可文本。
- pgvector：PostgreSQL License；保留版权和许可文本。

许可证允许使用不等于安全、运维或生产采用已经完成。正式 Receipt 必须重新
绑定所审查版本的准确许可证字节或官方来源证据。

## 安全与数据流

Keycloak 接触身份、认证因素、协议断言和令牌，但不能代替 C06 的业务授权
真相。OpenFGA 只裁决关系授权，调用者不得覆盖 Store、Model、Tuple 或结果。
PostgreSQL 和 pgvector 持有租户数据，Tenant Context 必须由受信服务器设置，
普通运行连接必须为非 Owner、非 Superuser、`NOBYPASSRLS` 角色。

上述 P1 验证全部使用 Synthetic 数据。它们没有接入真实企业身份、OA、ERP、
BI 或生产凭据。

## 治理效力

This ADR does not claim production adoption.

This ADR does not create a formal Reference Review Receipt or Bundle.

This ADR does not approve a P2 Profile.

This ADR does not create D1, Gate, Profile, or start-authorization state.

本 ADR 只是后续正式回填的冻结输入，不改变 P0/P1、G0/G1、Manifest、
Supplemental Evidence Index 或 O02/O03 状态。P1-B11 未闭合时，不得据此
生成最终 Profile Approval。
