# ADR 0014: K3 历史复核证据物化检查点候选

- 状态：Candidate
- 日期：2026-07-31
- 范围：P0–P2 合成数据阶段的 K3 单次独立复核材料
- 数据边界：SYNTHETIC_ONLY
- 追加说明：补充 ADR 0013，不修改其历史字节或既有失败证据

## 背景

ADR 0013 要求 K3 Review Material 保持完整、单次、失败关闭且不超过
1048576 UTF-8 bytes。`cd8b7623c34e346fd3460fed465f6c1998ee8443`
对应的正式材料为 957096 bytes。随后提交的历史取证目录同时保存了该材料、
完整正式请求、Token Estimate 请求、Review Bundle 和失败 Outcome。

当下一轮仍以
`ab95c7aff586279062c7698749fdbc0e38e955d1` 为 coverage base 时，这五个
派生证据路径会成为新的 Git source subjects。旧 Review Material 因而分别通过
自身、正式请求 user content 和 Token Estimate messages 多次进入新 Material，
使 SOURCE/PATCH 下界增长到约 3.9 MiB。该增长不是新的实现、规范或测试审查
范围，而是历史传输证据的递归物化。

历史 `single-call-outcome.v1.json` 还记录了不存在的 base commit
`ab95d8a18d80a74631e31d6a060dcf19019b098e`。准确 Review Bundle 和
Review Material 均绑定
`ab95c7aff586279062c7698749fdbc0e38e955d1`。历史 Outcome 必须保留原字节，
不能直接改写。

## 候选决定

新增 `independent-review-material.v4` 和关闭字段的 Historical Evidence Index
v1。Material v4 把历史派生证据表示为 manifest-only 的
`PRIOR_REVIEW_EVIDENCE_REFERENCE`，不再把它们作为带附件字节的 SOURCE
section。真实源码、规范、Schema、Validator、ADR 和测试仍必须以完整 SOURCE
或 PATCH 字节进入模型。

本决定不推进 coverage base。fixed base 继续精确为：

`ab95c7aff586279062c7698749fdbc0e38e955d1`

没有绑定完整材料的合规 CLEAR Receipt 时，任何提交都不能替代该base。

## 五个历史派生制品

Index只允许以下准确路径，全部源自 commit
`e40dd122ba323b825906e3362aea2cc37748ef7a`、tree
`ecc0c179792aa244037bd283a326da58d90f49e3`，Git mode必须为`100644`：

1. `formal-request.json`；
2. `review-bundle.v2.json`；
3. `review-material.v3.utf8`；
4. `single-call-outcome.v1.json`；
5. `token-estimate-request.json`。

准确路径、长度、原始字节SHA-256、内部语义摘要和派生关系冻结在
`historical-evidence-index.v1.json`。可信运行时必须从origin commit和当前
source commit分别读取这些字节，并证明两处完全相同。

Index中`reviewId`只是本地证据谱系标识，固定声明
`INDEX_LOCAL_LINEAGE_ONLY_NO_RECEIPT`。它不是历史Receipt，也不能证明历史
模型复核已经CLEAR。

## 派生关系

派生边统一表示“当前制品依赖的上游制品”：

- Review Bundle没有上游；
- Review Material完整嵌入Review Bundle section；
- Formal Request的user content逐字节等于Review Material；
- Token Estimate Request逐字节复用Formal Request的messages；
- Outcome绑定上述四个制品的准确路径、长度和SHA-256。

派生图必须无自环、无循环且与固定关系完全一致。路径前缀、`.json`扩展名、
调用者布尔值或任意索引内容均不能使路径获得Reference资格。

## Material v4覆盖合同

Material v4继续使用ADR 0013的长度前缀Envelope。`sections`仅描述实际附加并
提供给模型的原始UTF-8字节。`priorReviewEvidenceReferences`只存在于manifest，
不对应附件段。

以下三个集合必须分别重算摘要：

- section descriptors；
- historical reference descriptors；
- Bundle reviewed paths的完整覆盖映射。

覆盖映射由`path`、`coverageKind`和Bundle中的`sourceBlobSha256`组成。
每个reviewed path必须且只能由`SOURCE`、`PATCH`或
`PRIOR_REVIEW_EVIDENCE_REFERENCE`覆盖一次。raw section与reference不得重叠，
二者并集必须精确等于Bundle的`reviewedPaths`。

Review Bundle、Index、Index Schema、Prompt、Output Schema、Receipt Schema和
Provider Config均绑定准确Git字节。Index及其Schema本身属于当前审查范围，必须
以完整SOURCE/PATCH提供给模型，不能再被Reference排除。

## 哈希规则

所有值摘要使用按键UTF-8排序的Canonical JSON：

- `entrySha256`：删除entry自身的`entrySha256`字段后计算；
- `entrySetSha256`：按path排序的完整entries数组计算；
- `pathSetSha256`：按UTF-8排序的路径数组计算；
- `indexSha256`：删除Index自身的`indexSha256`字段后计算；
- `sectionSetSha256`：完整section descriptor数组计算；
- `priorReviewEvidenceReferenceSetSha256`：完整reference descriptor数组计算；
- `reviewedPathCoverageSha256`：按path排序的覆盖映射数组计算；
- `materialSha256`：删除Material自身的`materialSha256`字段后计算。

文件原始字节SHA-256与上述Canonical JSON摘要是不同绑定，不得互相替代。

## 历史Outcome纠正

Index以追加字段记录Outcome中的错误base及准确fixed base，并同时引用权威
Review Bundle与Review Material。该记录满足：

- `historicalArtifactMutated: false`；
- `confersClearStatus: false`；
- `governanceEffect: NONE`。

历史Outcome继续是`BLOCKED/INCONCLUSIVE`，Chat调用次数继续为0。纠正记录
不产生Receipt、不推进base，也不改变历史提交。

## 失败关闭

以下任一情况必须拒绝Material：

- Index或Schema字节、self-hash、entry-set或path-set失配；
- origin/current source字节不同；
- Git mode不是`100644`，或对象是symlink、submodule或可执行文件；
- 五路径之外的任何路径被表示为Reference；
- Bundle、Material、Request、Token Request或Outcome固定语义失配；
- 派生关系缺失、错误或循环；
- raw/reference重叠或reviewed path覆盖不完整；
- 历史结果被表示为CLEAR或coverage base已推进；
- 完整Material Envelope超过1048576 bytes。

超限时不得提高上限、裁剪必须审查的源码、以摘要替代模型必须阅读的内容、
分段复核、切换模型或回退其他端点。

## 治理效力

本候选只消除字节相同的历史派生传输载荷，不代表历史复核通过。它不产生D1
事件、Gate决定、P2 Profile Approval、O02/O03授权、工作包状态、部署或
GitHub治理变化。只有未来准确source commit的完整单次材料取得合规K3 CLEAR
Receipt后，才可按单独治理流程评估后续效力。
