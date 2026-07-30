# ADR 0011: P0–P2 独立模型复核候选政策

- 状态：Candidate
- 日期：2026-07-30
- 范围：P0–P2 合成数据阶段的代码与治理制品复核
- 数据边界：SYNTHETIC_ONLY

## 背景

ADR 0008 为 C13 / P1-B11 记录了真实第二名人类复核要求。当前项目只有
一名人类负责人；继续把第二名人类作为 P0–P2 的唯一复核路径，会把合成数据
阶段永久保持为 `INCONCLUSIVE`。既有历史记录必须保留，模型复核也不能冒充
人类批准。

## 候选决定

在 Policy v2 经后续独立治理激活前，本 ADR 仅记录候选方向：

- P0、P1、P2 使用 `MODEL_ONLY_PREPRODUCTION`；
- 独立模型必须未参与实现、使用全新隔离上下文，并只读取准确 Git 提交、
  diff、规范、测试和验收证据；
- 独立模型没有文件写入、合并、D1 写入、部署或治理决定权限；
- 唯一允许的成功结论是
  `MODEL_REVIEW_CLEAR_FOR_PREPRODUCTION`；
- `humanIndependentReviewSatisfied` 始终为 `false`；
- 不创建虚假的 GitHub Human Approve；
- P1-B11 只能在合规 Receipt 形成后追加式重新评估。

本决定仅候选性 supersede ADR 0008 中“P0–P2 必须由第二名真实人类完成代码
复核”这一部分。ADR 0008 的 GitHub Ruleset、CODEOWNERS、required status
checks、无 bypass 和真实远端拒绝证据要求不因本 ADR 自动满足。

## P3 与高风险边界

以下范围不得使用模型复核替代真实第二名人类复核：

- P3、真实企业数据和生产发布；
- 身份、权限与租户隔离；
- D1、Gate、Profile 与启动授权；
- 代码执行沙箱与网络出口；
- 密钥、企业数据与企业连接器；
- 生产部署、回滚和数据写回。

进入这些边界时，缺少真实第二名人类必须保持
`INCONCLUSIVE_INDEPENDENT_HUMAN_REVIEWER_MISSING`。

## 证据与状态真相

- Git 只冻结 Policy、Schema、Validator、Review Bundle、模型输出、隔离证据
  和 Receipt 的准确字节；
- 本地控制平面只能声明
  `LOCAL_CONTROL_PLANE_OBSERVED_OS_ENFORCEMENT`：它证明冻结采集器在当前
  主机和指定隔离策略下观察到的拒绝与仓库前后状态，不提供外部不可抵赖性；
- 本地主机所有者理论上可以伪造整套本地证据，供应商内部模型版本也没有硬件
  或供应商签名证明；因此不得声称 `CRYPTOGRAPHICALLY_UNFORGEABLE` 或
  `PRODUCTION_GRADE`；
- 模型传输凭据只能由本地控制进程使用，不得作为模型工具、Review Bundle、
  Receipt 或日志内容暴露；
- 本地 probe 只能证明传入沙箱的净化环境中没有受检凭据变量；它不宣称扫描
  或读取宿主机凭据；
- Git commit 与 tag 写入会做操作系统拒绝探针；为避免外部副作用，不尝试
  push，因此证据只能记录 `PUSH_NOT_ATTEMPTED`，不能声称已证明远端 push
  被拒绝；
- 线上 D1 继续是工作包状态和治理事件的唯一真相；
- GitHub Required Check 只有在后续单独授权后才可发布；
- 旧的 `INCONCLUSIVE` 历史记录不删除、不覆盖，也不追溯改写为满足。

## 治理效力

This ADR is a candidate and has no governance effect.

This ADR does not activate Policy v2.

This ADR does not satisfy independent human review.

This ADR does not change P1-B11, D1, Gate, Profile, Manifest, or work-package
state.

This ADR does not authorize O02 or O03.
