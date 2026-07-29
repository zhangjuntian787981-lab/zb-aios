# ADR 0006: 工作包开工前使用 Git 冻结的 Reference Review 证明

- 状态：Candidate
- 日期：2026-07-29
- 范围：通用多企业 AI 员工平台的开源项目、标准和官方技术资料适用性审查

## 决策

当工作包存在适用的开源项目、标准或官方技术资料候选时，在对应治理边界通过之前，服务器必须验证一个与精确候选集合、Profile、源码提交和 Execution Baseline 绑定的 Reference Review Bundle。

Reference Review 使用四种合法决定：

- `ADOPT`：采用固定版本；必须完成许可证、再分发、安全、数据流、维护、退出、ADR 和必要 PoC 审查。
- `REJECT`：拒绝候选；必须记录拒绝理由和替代路径。
- `DEFER`：推迟决定；必须记录可验证的重新审查触发条件和最晚边界。
- `NOT_APPLICABLE`：候选与该工作包无关；必须记录工作包相关理由。

任何决定都不自动等于生产采用、工作包状态、启动授权、Profile Approval 或 Gate Decision。

## 权威边界

- `work-package-manifest.v1.json` 继续只定义 37 个工作包。
- 线上 D1 只追加治理账本继续是工作包状态、Gate、Profile Approval 和 Start Authorization 的唯一状态真相。
- Git 只冻结 Reference Catalog、Reference Policy、Receipt、Bundle、ADR 和验证证据。
- Reference Review 不创建任务表、进度表或第二套状态存储。
- 普通 Git commit、测试通过或聊天确认不能冒充 D1 治理事件。

Reference Policy 必须绑定 Manifest 的准确路径和规范 SHA-256，并绑定候选来源矩阵的准确路径、字节 SHA-256 和 Catalog Reference ID 全集。服务器构建绑定还必须独立固定 Manifest 项目标识、版本、37 项 ID 集合摘要、Manifest、Catalog、Policy 和候选来源矩阵摘要；只在同一链内同时替换这些对象不能改写信任根。Policy 中的每个工作包都必须存在于该 Manifest；Profile 回填集合必须由 `RETROSPECTIVE_BACKFILL + PROFILE_APPROVAL` Policy 条目确定性派生，调用者或 Policy 的第二份手写列表不能增加、遗漏或伪造工作包。

## 分层门

1. `PRE_START`：适用候选必须全部被识别并形成有效决定，才可满足开工准备。
2. `DEPENDENCY_ADOPTION`：只有完整 `ADOPT` Receipt 才可进入依赖锁；实际依赖锁或源码集成中出现 `REJECT`、`DEFER` 或 `NOT_APPLICABLE` 候选时必须拒绝。
3. `IMPLEMENTATION_CONFORMANCE`：标记 `VERIFIED` 前，实际实现摘要必须与 `ADOPT` 的固定制品摘要一致；被拒绝或推迟的候选不得出现在实现绑定中。
4. `RELEASE`：O03 继续独立验证 SBOM、Provenance、签名、漏洞、许可证和准入。本 ADR 不替代 O03。

与工作包无关且在冻结 Policy 中明确为空的候选集合不阻止工作。未被 Policy 覆盖的工作包不能被推断为“没有适用候选”，必须失败关闭并先扩展 Catalog 和 Policy。

## 摘要与陈旧规则

Receipt、Bundle、Catalog 与 Policy 使用关闭字段和确定性 SHA-256。Bundle 必须覆盖 Policy 给出的完整、有序候选集合，并引用每个 Receipt 的路径和摘要。Policy 的适用性证据必须同时覆盖冻结矩阵输入、依赖锁扫描、源码集成扫描和人工追加检查；只有手写候选清单不能证明“没有遗漏”。四类扫描各引用一个关闭字段、Git 冻结的输入描述符，描述符不得直接携带 `referenceId`、`READY` 或治理状态：

- `REFERENCE_MATRIX` 从冻结的工作包矩阵切片中读取 `matrixReferenceId + referenceName + officialSourceUri`，三者必须唯一匹配 Catalog；
- `DEPENDENCY_LOCK_SCAN` 从绑定 `evidenceFreezeTree` 的锁文件清单中读取包名、官方 URI、版本、制品摘要和工具锁域，再唯一匹配 Catalog；
- `SOURCE_INTEGRATION_SCAN` 从绑定同一 tree 的源码集成索引读取逐源码文件摘要；每个源码文件必须以唯一、规范的 `REFERENCE_INTEGRATION_MARKER_V1` 首行标记其标识、官方 URI 和集成类型。验证器对冻结字节执行严格 UTF-8 解码并从该标记重新派生三项字段，与索引逐字比较后再唯一匹配 Catalog；索引自述或仅在任意源码字节旁附带摘要不能证明集成关系；
- `MANUAL_SUPPLEMENT` 只允许以唯一官方 URI 记录 `APPLICABLE` 或 `NOT_APPLICABLE` 观察及逐项冻结证据，不能替代前三类扫描。

验证器必须从这些输入的准确冻结字节重新计算每类 `discoveredReferenceIds`，再将四类结果的并集与 Policy 比较；报告自述的候选 ID 不具有独立证明力。Policy 还固定源码扫描根和排除路径，构建时 Git 证明须从真实 freeze tree 独立枚举该范围，而不是复述 Attestation 自报的 subject 清单。Worker 通过服务器注入的固定路径枚举证明，先比较真实根路径集合与 Attestation 根内路径集合，再检查每个路径；缺少该独立枚举证明时默认拒绝。带有规范集成标记的路径集合必须与源码索引逐路径完全一致，未被索引或未进入 Attestation 的额外标记同样失败关闭。源码标记必须位于第一行、只出现一次、使用关闭字段和规范 JSON，且后面存在源码正文；无标记、重复或冲突标记、非法 UTF-8、非规范结构以及标记与索引不一致均失败关闭。其他输入不可解析、字段未关闭、来源未知或多义、tree 不一致、清单/源码摘要缺失时同样失败关闭。

Attestation 的 `evidenceSubjects` 必须与本次验证实际消费的 Manifest、Catalog、Policy、适用性输入、源码、锁文件、Receipt、Bundle、ADR、PoC 和实现证据路径形成精确闭包；存在未消费 subject 或已消费路径未冻结时拒绝。可信构建根验证同时绑定 `evidenceSubjects` 规范摘要、Manifest 摘要、源码根和排除路径，避免 Worker 把调用者自述的部分文件清单当作完整 Git 范围。

以下任一变化都会使旧证明失效：

- 候选集合或 Catalog 摘要变化；
- Reference Policy 摘要变化；
- Profile SHA-256 变化；
- source commit 或 Execution Baseline Digest 变化；
- `ADOPT` 的版本、commit、release、镜像或制品摘要变化；
- 实际依赖锁或源码集成事实与 `ADOPT` 的固定版本、制品摘要、官方来源或集成类型不一致；
- 实现一致性证据不是关闭字段的 `reference-implementation-conformance.v1`，或其准确冻结字节与上述实际事实不一致；
- Manifest 摘要、工作包集合或 Profile 回填集合变化。

`sourceCommit` 只表示被审查的实现基线，不能同时充当 Receipt 与 Bundle 自身的冻结提交。Reference Review 采用以下不可逆、无循环构造顺序：

1. 先计算不包含任何 Reference Review 摘要的上游 Profile Core SHA-256 和 Execution Baseline Core Digest。
2. Policy、适用性报告、Receipt 和 Bundle 只向后引用上述两个上游摘要，不允许上游对象反向引用它们。
3. 使用后续 `evidenceFreezeCommit` 和 `evidenceFreezeTree` 冻结 Catalog、Policy、Bundle、Receipt 及全部逐路径证据字节。可信构建证明必须确认该 commit 真实存在、对象类型为 commit、解析出的 tree 与声明值逐字一致，并证明 `sourceCommit` 是其严格上游；格式正确的任意 commit/tree 字符串不能代替该证明。
4. 冻结后为每个工作包分别生成一个关闭字段的 `reference-review-freeze-attestation.v1`。每个 Attestation 只允许一个 `bundleSubject`，并绑定上游 Profile、Execution Baseline、Catalog、Policy、该工作包 Bundle 及其精确冻结路径；Attestation 自身不进入 `evidenceFreezeCommit`，其 `attestationSha256` 计算时排除自身字段。Profile 多工作包回填必须使用服务器持有的逐工作包 Attestation 映射；缺项、交换、复用、未知工作包或回退到单个全局 Attestation 都失败关闭。
5. Worker 只验证固定 Attestation；它不得声称在运行时执行了 Git。

Attestation 固定声明 `upstreamProfileIncludesReferenceReviewDigests=false`、`upstreamExecutionBaselineIncludesReferenceReviewDigests=false` 和 `attestationIncludedInEvidenceFreeze=false`。任一声明变化都失败关闭。Catalog、Policy、Manifest、Bundle、Receipt、官方来源快照、审阅笔记、差距、现状、PoC、ADR 和实现一致性证据均须逐路径核验。依赖版本只能与 Receipt 的版本类字段比较，制品摘要只能与 `artifactDigest` 或 `imageDigest` 比较；不得用一个无类型字符串集合让版本冒充摘要。`IMPLEMENTATION_CONFORMANCE` 对开源项目还必须把实际依赖锁和实际源码集成事实同时绑定到关闭字段证据；实际出现 `REJECT`、`DEFER` 或 `NOT_APPLICABLE` 候选时拒绝。

当前 D1 Profile Approval 事件合同没有单独的 Reference Review Attestation 摘要字段。本候选实现只提供默认拒绝的验证 seam，不据此扩展 D1 合同或自动批准 Profile。正式激活前，必须由后续单独审批的非循环激活绑定把准确 Attestation pin 与批准命令的服务器端验证器固定起来；在此之前当前 Candidate 继续拒绝。

运行时 Worker 不执行 `/usr/bin/git`、不访问 GitHub API，也不持有长期 GitHub Token。Git commit、tree 存在性、严格祖先关系、Manifest、源码扫描范围、真实根路径枚举和冻结 subject 闭包由构建时可信 Git 证明；Worker 通过默认拒绝的 `verifyFreezeRoot` 与 `listFrozenPaths` seam 只验证固定 Attestation 与其上游绑定，不把 Attestation 反向塞入已经用于构造它的摘要。测试用 Synthetic seam 只能识别固定的 commit、tree、source、Manifest、subject 摘要和源码范围，不能进入生产 composition root。

## ProjectControl 接线

`createProjectControl` 只接收可注入、默认拒绝的 Reference Review readiness seam。它不反向依赖 HTTP 路由或 Git 实现。

- Profile Approval 在已有 Profile readiness 和 Execution Baseline 检查之前验证所需的回填 Bundle。
- O02、O03 Start Authorization 在结构依赖和活动 Profile 绑定成立后，分别验证自己的 Bundle。
- `RECORD_WORK_PACKAGE` 只有在越过 `NOT_STARTED` 或写入 `VERIFIED` 时才分别调用 `PRE_START` 或 `IMPLEMENTATION_CONFORMANCE`；不跨治理边界的普通命令不调用。
- O02、O03 的 `DEPENDENCY_ADOPTION` Bundle 必须把 Profile 中每个必需工具锁的 referenceId、版本和摘要精确绑定到一个 `ADOPT` Receipt；两个独立布尔验证器不能彼此冒充。
- Profile Approval 的 P0/P1 回填固定要求 `IMPLEMENTATION_CONFORMANCE`，不能由 Bundle 自行降级为 `PRE_START`。
- snapshot 和 GET 不调用 Reference Review 验证器。
- `/api/progress` 的公开写 action 集合不扩展；本 ADR 不新增 Reference Review、Profile Approval 或 Start Authorization HTTP 写入口。

当前 v2 Candidate、Recipe 和 Worker Attestation 没有冻结 Reference Review 摘要，当前 Policy 的适用性证据也明确为 `UNPROVED`。因此 Candidate 保持失败关闭；必须通过新的追加式 Profile/Execution Baseline/Attestation 才能获得治理效力。

## P0/P1 追加式回填

已完成工作包的 Receipt 必须使用 `RETROSPECTIVE_BACKFILL`，且 `governanceEffect=NONE`。现有 Keycloak、OpenFGA、PostgreSQL/pgvector 等材料只能作为输入，不能自动认定审查通过。

回填不得删除、覆盖或改变 P0/P1 工作包状态、G0/G1 或历史 Gate。若回填发现实质问题，只能提出复核和整改建议，并通过既有 D1 追加式治理流程处理。

## 后果

- 开工和依赖选型不再依赖执行者自觉或聊天记忆。
- “已阅读并比较”可通过来源、范围、决定、理由和 Git 冻结证据复核。
- 不能证明主观理解程度；本决策只证明规定的审查活动和证据闭包已经完成。
- 初始 Catalog 仅覆盖 P0/P1 回填候选及 O02/O03 候选，未覆盖工作包继续失败关闭，不能被解释为 `NOT_APPLICABLE`。

本 ADR 不修改 Manifest、D1、Gate、Profile、Receipt v1/v2、数据库、迁移、P0/P1 历史或 O02/O03 状态。
