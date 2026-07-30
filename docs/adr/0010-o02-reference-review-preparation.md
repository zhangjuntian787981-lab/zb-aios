# ADR 0010: O02 密钥与工作负载身份参考审查准备

- 状态：Candidate
- 日期：2026-07-30
- 工作包：O02
- 审查模式：PROSPECTIVE

## 决定

基于
`implementation/governance/reference-review/o02-official-reference-research.v1.md`
固定的官方资料，当前不把任何候选写成已经采用：

- OpenBao v2.6.1：维持 `DEFER`，作为
  `O02_SECRETS_SYSTEM` 的首选合成 PoC 候选。
- SPIRE v1.15.2：维持 `DEFER`；只有跨集群、VM、裸机、统一
  SPIFFE 身份或信任域联邦成为真实需求时才启动 PoC。
- ESO v2.8.0：维持 `DEFER`，只允许作为可选 Kubernetes Secret
  同步层继续评估；明确拒绝把 ESO 当作主要秘密存储。

因此 `O02_SECRETS_SYSTEM` 与 `O02_WORKLOAD_IDENTITY` 均继续保持
`UNSELECTED_BLOCKS_EVIDENCE`。研究到的 release、commit 和制品摘要只用于
约束后续 PoC 输入，不能冒充实际部署锁。

## 选择前必须闭合的边界

OpenBao 在任何 `ADOPT` 决定前必须完成精确部署制品锁、租户隔离、短期身份、
动态秘密、审计故障、HA、密封/恢复、升级回退、退出迁移和运维责任 PoC。

SPIRE 不能保存业务秘密，也不能冒充 Enterprise User 或 HumanDecision。
若 O02 当前只运行在单个 Kubernetes 集群，应先独立审查 projected
ServiceAccount Token；不能为了“技术更先进”自动引入 SPIRE。

ESO 会把外部秘密物化为 Kubernetes Secret，扩大 RBAC、etcd、备份、节点和
Pod 的暴露面。其 OpenBao Provider 当前为 alpha，且官方资料不能证明 ESO
v2.8.0 与 OpenBao v2.6.1 已经完成兼容验证。

## 许可证与退出

- OpenBao v2.6.1：MPL-2.0。修改的 MPL 文件和二进制再分发需要落实相应
  Source Code Form、许可证和通知义务；不获得 OpenBao 商标权。
- SPIRE v1.15.2、ESO v2.8.0：Apache-2.0。再分发需要保留许可证、适用
  NOTICE/版权和修改说明；不获得项目商标权。

正式产品分发仍需冻结实际镜像、Chart、SBOM 和第三方许可证结果。三个项目均
没有提供可证明迁移到任意替代系统的通用无损退出方案，退出能力必须通过 PoC。

## 治理效力

This ADR does not create a formal Reference Review Receipt or Bundle.

This ADR does not select either O02 tool lock.

This ADR does not approve a P2 Profile.

This ADR does not authorize or start O02.

本 ADR 只是后续 Receipt、PoC、工具锁和启动授权的冻结输入，不修改 Manifest、
D1、Gate、Profile、Supplemental Evidence Index 或任何工作包状态。
